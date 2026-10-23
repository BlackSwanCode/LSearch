#!/usr/bin/env python3
"""
LeakSearcher Ultra v5.0.0 — Fusion consolidée (5a + 5c + 5d).
Restaure les sources OSINT perdues en 5c/5d, corrige les bugs introduits,
conserve les apports (configs externes, TrafficLogger, Gist, polyfill Python<3.9).
Dépendance UI: pip install rich
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import random
import re
import signal
import sqlite3
import sys

# ==============================================================================
# COMPATIBILITÉ PYTHON 3.7 / 3.8
# ==============================================================================
if sys.version_info < (3, 9):
    import functools

    async def _to_thread_compat(func, *args, **kwargs):
        loop = asyncio.get_event_loop()
        if kwargs:
            func = functools.partial(func, **kwargs)
        return await loop.run_in_executor(None, lambda: func(*args))

    asyncio.to_thread = _to_thread_compat  # type: ignore[attr-defined]

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except Exception:  # pragma: no cover
    Console = None  # type: ignore
    Panel = Table = None  # type: ignore

APP = "LeakSearcher Ultra"
VERSION = "5.0.0-fusion"
UTC = timezone.utc
RUNNING = True
console = Console() if Console else None

DEFAULT_KEYWORDS = [
    "@votre-domaine.com", "api_key", "mot_de_passe", "sk_live_", "AKIA", "-----BEGIN",
]

BUILTIN_RULES: List[Dict[str, Any]] = [
    {"id": "email", "kind": "pii", "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "weight": 1, "mask_group": 0},
    {"id": "aws_access_key", "kind": "secret", "pattern": r"\b(AKIA|ASIA)[A-Z0-9]{16}\b", "weight": 8, "mask_group": 0},
    {"id": "aws_secret_key", "kind": "secret",
     "pattern": r"(?i)(aws_secret_access_key|aws_secret_key)[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?",
     "weight": 10, "mask_group": 2},
    {"id": "github_token", "kind": "secret", "pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "weight": 8, "mask_group": 0},
    {"id": "github_pat", "kind": "secret",
     "pattern": r"\bgithub_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}\b", "weight": 9, "mask_group": 0},
    {"id": "slack_token", "kind": "secret", "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "weight": 8, "mask_group": 0},
    {"id": "stripe_live", "kind": "secret", "pattern": r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", "weight": 9, "mask_group": 0},
    {"id": "stripe_test", "kind": "secret", "pattern": r"\b[sr]k_test_[A-Za-z0-9]{16,}\b", "weight": 4, "mask_group": 0},
    {"id": "google_api_key", "kind": "secret", "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b", "weight": 8, "mask_group": 0},
    {"id": "telegram_bot", "kind": "secret", "pattern": r"\b\d{8,10}:[A-Za-z0-9_-]{35,}\b", "weight": 7, "mask_group": 0},
    {"id": "discord_webhook", "kind": "secret",
     "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "weight": 6, "mask_group": 0},
    {"id": "private_key_header", "kind": "secret",
     "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----", "weight": 10, "mask_group": 0},
    {"id": "db_uri", "kind": "secret",
     "pattern": r"(?i)\b(?:mysql|postgres|postgresql|mongodb|redis|mssql):\/\/[^\s\"'<>]{10,}", "weight": 6, "mask_group": 0},
    {"id": "generic_assignment", "kind": "context",
     "pattern": r"(?i)\b(?:api[_-]?key|secret|token|password|mot[_ -]?de[_ -]?passe|client[_-]?secret|auth)\b\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?",
     "weight": 4, "mask_group": 1},
    {"id": "jwt", "kind": "token",
     "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "weight": 5, "mask_group": 0},
    {"id": "iban", "kind": "pii",
     "pattern": r"\bFR\d{2}(?:\s?\d{4}){5}\s?\d{3}\b", "weight": 7, "mask_group": 0},
    {"id": "internal_domain", "kind": "context",
     "pattern": r"(?i)\b[a-z0-9-]+\.(local|internal|corp|lan)\b", "weight": 6, "mask_group": 0},
]

SEVERITY = [(0, "INFO"), (3, "FAIBLE"), (7, "MOYENNE"), (12, "ÉLEVÉE"), (18, "CRITIQUE")]


# ==============================================================================
# CONFIG EXTERNE + TRAFFIC LOGGER
# ==============================================================================
def load_external_config(filepath: Optional[str], default_data: Any, key: str) -> Any:
    if filepath and Path(filepath).exists():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if key in data:
                _print(f"[+] Configuration chargée depuis {filepath}", "green")
                return data[key]
        except Exception as e:
            _print(f"[-] Erreur lecture {filepath} : {e}. Fallback par défaut.", "yellow")
    return default_data


class TrafficLogger:
    MAX_BODY_LENGTH = 4096

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def log(self, source: str, method: str, url: str, req_headers: dict,
            resp_status: int, resp_body: str) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filepath = self.log_dir / f"{timestamp}_{source}.json"
        body = (resp_body[: self.MAX_BODY_LENGTH] + "...[TRONQUÉ]"
                if len(resp_body) > self.MAX_BODY_LENGTH else resp_body)
        entry = {
            "timestamp": datetime.now().isoformat(), "source": source, "method": method,
            "url": url, "request_headers": req_headers,
            "response_status": resp_status, "response_body": body,
        }
        try:
            filepath.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass


traffic_logger: Optional[TrafficLogger] = None


# ==============================================================================
# STRUCTURES
# ==============================================================================
@dataclass
class Config:
    delay: float = 5.0
    max_iterations: int = 3
    keywords: List[str] = field(default_factory=lambda: list(DEFAULT_KEYWORDS))
    rules: List[Dict[str, Any]] = field(default_factory=lambda: list(BUILTIN_RULES))
    rules_file: Optional[Path] = None
    keywords_file: Optional[Path] = None
    use_ollama: bool = True
    ollama_url: str = "http://127.0.0.1:11434/api/generate"
    ollama_model: str = "llama3.2"
    ollama_timeout: float = 15.0
    verbose: bool = False
    quiet: bool = False
    redact: bool = True
    source: str = "github"
    github_token: Optional[str] = None
    publicwww_key: Optional[str] = None
    ghw_key: Optional[str] = None
    intelx_key: Optional[str] = None
    psbdmp_api_key: Optional[str] = None
    db_path: Path = Path("leaksearcher.sqlite3")
    report_dir: Path = Path("reports")
    audit_path: Path = Path("leaksearcher_audit.jsonl")
    webhook_url: Optional[str] = None
    dry_run: bool = False
    per_host_concurrency: int = 3
    max_retries: int = 2
    backoff_base: float = 1.0
    context_chars: int = 160
    min_score: int = 4


@dataclass
class Rule:
    id: str
    kind: str
    pattern: str
    weight: int = 1
    flags: int = re.IGNORECASE
    mask_group: int = 0
    regex: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, self.flags)


@dataclass
class Evidence:
    rule_id: str
    kind: str
    start: int
    end: int
    match_preview: str
    redacted_preview: str
    entropy: float
    weight: int


@dataclass
class Finding:
    source: str
    sha256: str
    score: int
    severity: str
    kinds: List[str]
    rule_ids: List[str]
    keywords: List[str]
    evidence: List[Evidence]
    excerpt: str
    triage: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["evidence"] = [asdict(e) for e in self.evidence]
        return d


class Fetcher(Protocol):
    name: str
    async def discover(self, keywords: List[str]) -> List[str]: ...
    async def fetch(self, item_id: str) -> str: ...


# ==============================================================================
# FETCHERS — GitHub
# ==============================================================================
class GitHubCodeFetcher:
    name = "github"
    SEARCH_URL = "https://api.github.com/search/code?q={}"

    def __init__(self, delay: float = 5.0, token: Optional[str] = None):
        self.delay = delay
        self.headers = {"User-Agent": "LeakSearcher/5.0",
                        "Accept": "application/vnd.github.v3+json"}
        if token:
            self.headers["Authorization"] = f"token {token}"

    async def discover(self, keywords: List[str]) -> List[str]:
        urls: List[str] = []
        for kw in keywords:
            url = self.SEARCH_URL.format(urllib.parse.quote(f"{kw} in:file"))
            req = urllib.request.Request(url, headers=self.headers)

            def _get() -> List[str]:
                with urllib.request.urlopen(req, timeout=15) as r:
                    body = r.read().decode("utf-8", "replace")
                    if traffic_logger:
                        traffic_logger.log(self.name, "GET", url, self.headers, r.status, body[:500])
                    data = json.loads(body)
                    return [it["html_url"] for it in data.get("items", [])[:5]]

            try:
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] GitHub: {len(found)} fichier(s) pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Erreur GitHub pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_url: str) -> str:
        raw_url = (item_url
                   .replace("github.com", "raw.githubusercontent.com")
                   .replace("/blob/", "/"))
        req = urllib.request.Request(raw_url, headers={"User-Agent": "LeakSearcher/5.0"})

        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                body = r.read().decode("utf-8", "replace")
                if traffic_logger:
                    traffic_logger.log(self.name, "GET", raw_url, {}, r.status, body[:500])
                return body

        return await asyncio.to_thread(_get)


class GitHubGistFetcher:
    name = "gist"
    LIST_URL = "https://api.github.com/gists?per_page=30"

    def __init__(self, delay: float = 5.0):
        self.delay = delay

    async def discover(self, keywords: List[str]) -> List[str]:
        req = urllib.request.Request(
            self.LIST_URL,
            headers={"User-Agent": "LeakSearcher/5.0",
                     "Accept": "application/vnd.github.v3+json"},
        )

        def _get() -> List[str]:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode("utf-8"))
            matched = []
            for gist in data:
                desc = (gist.get("description") or "").lower()
                if any(kw.lower() in desc for kw in keywords):
                    matched.append(gist["html_url"])
            return matched

        try:
            found = await asyncio.to_thread(_get)
            _print(f"[+] GitHub Gist: {len(found)} gist(s) pertinent(s)", "green")
            return list(set(found))
        except Exception as e:
            _print(f"[-] Erreur Gist: {e}", "yellow")
            return []

    async def fetch(self, item_url: str) -> str:
        raw_url = item_url.rstrip("/") + "/raw"
        req = urllib.request.Request(raw_url, headers={"User-Agent": "LeakSearcher/5.0"})

        def _get() -> str:
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    return r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError:
                return f"[Gist inaccessible ou supprimé: {item_url}]"

        return await asyncio.to_thread(_get)


# ==============================================================================
# FETCHERS — Pastebin / Psbdmp
# ==============================================================================
class PastebinArchiveFetcher:
    name = "pastebin"
    ARCHIVE_URL = "https://pastebin.com/archive"
    RAW_URL = "https://pastebin.com/raw/{}"
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html",
    }

    def __init__(self, delay: float = 5.0):
        self.delay = delay

    async def discover(self, keywords: List[str]) -> List[str]:
        req = urllib.request.Request(self.ARCHIVE_URL, headers=self.HEADERS)

        def _get() -> List[str]:
            with urllib.request.urlopen(req, timeout=15) as r:
                html = r.read().decode("utf-8", "replace")
            return list(set(re.findall(r'href="/([a-zA-Z0-9]{8})"', html)))[:15]

        try:
            found = await asyncio.to_thread(_get)
            _print(f"[+] Pastebin Archive: {len(found)} pastes récents", "green")
            return found
        except Exception as e:
            _print(f"[-] Erreur Pastebin: {e}", "red")
            return []

    async def fetch(self, item_id: str) -> str:
        req = urllib.request.Request(self.RAW_URL.format(item_id), headers=self.HEADERS)

        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")

        return await asyncio.to_thread(_get)


class PsbdmpFetcher:
    """Résilience multi-URL (apport 5b/5c conservé)."""
    name = "psbdmp"
    BASE_URLS = [
        "https://psbdmp.ws/api/search/v3/",
        "https://psbdmp.ws/api/v3/search/",
        "https://psbdmp.ws/api/search/",
        "https://www.psbdmp.ws/api/search/v3/",
    ]

    def __init__(self, delay: float = 5.0, api_key: Optional[str] = None):
        self.delay = delay
        self.api_key = api_key

    async def discover(self, keywords: List[str]) -> List[str]:
        ids: List[str] = []
        for kw in keywords:
            encoded = urllib.parse.quote(kw, safe="")
            success = False
            for base in self.BASE_URLS:
                if success:
                    break
                url = base.rstrip("/") + "/" + encoded
                headers = {"User-Agent": "LeakSearcher/5.0", "Accept": "application/json"}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"
                req = urllib.request.Request(url, headers=headers)

                def _get() -> List[str]:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        data = json.loads(r.read().decode("utf-8"))
                    if isinstance(data, list):
                        return [it.get("id") for it in data if it.get("id")]
                    if isinstance(data, dict) and "results" in data:
                        return [it.get("id") for it in data["results"] if it.get("id")]
                    return []

                try:
                    found = await asyncio.to_thread(_get)
                    if found:
                        ids.extend(found)
                        _print(f"[+] Psbdmp: {len(found)} dump(s) pour '{kw}' (via {base})", "green")
                        success = True
                except Exception:
                    continue
            if not success:
                _print(f"[-] Psbdmp: échec total pour '{kw}' après {len(self.BASE_URLS)} tentatives.", "red")
            await asyncio.sleep(self.delay)
        return list(set(ids))

    async def fetch(self, item_id: str) -> str:
        url = f"https://psbdmp.ws/api/v3/dump/{item_id}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "LeakSearcher/5.0", "Accept": "application/json"}
        )

        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode("utf-8"))
            return data.get("content", f"[Contenu non trouvé pour {item_id}]")

        return await asyncio.to_thread(_get)


# ==============================================================================
# FETCHERS — Grep.app
# ==============================================================================
class GrepAppFetcher:
    name = "grepapp"
    SEARCH_URL = "https://grep.app/api/search?q={}"

    def __init__(self, delay: float = 5.0):
        self.delay = delay

    async def discover(self, keywords: List[str]) -> List[str]:
        urls: List[str] = []
        for kw in keywords:
            url = self.SEARCH_URL.format(urllib.parse.quote(kw))
            req = urllib.request.Request(url, headers={"User-Agent": "LeakSearcher/5.0"})

            def _get() -> List[str]:
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read().decode("utf-8"))
                hits = data.get("results", {}).get("hits", [])
                return [f"https://github.com/{h['repo']}/blob/master/{h['path']}" for h in hits[:5]]

            try:
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] Grep.app: {len(found)} résultat(s) pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Erreur Grep.app pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_url: str) -> str:
        # FIX 5d conservé : index 5 = branche, pas 3
        parts = (item_url
                 .replace("github.com", "raw.githubusercontent.com")
                 .replace("/blob/", "/")
                 .split("/"))
        if len(parts) <= 5:
            return "[URL Grep.app malformée]"
        original_branch = parts[5]
        for branch in [original_branch, "main", "master", "HEAD"]:
            parts[5] = branch
            raw_url = "/".join(parts)
            req = urllib.request.Request(raw_url, headers={"User-Agent": "LeakSearcher/5.0"})
            try:
                def _get() -> str:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        return r.read().decode("utf-8", "replace")
                return await asyncio.to_thread(_get)
            except urllib.error.HTTPError:
                continue
        return f"[Échec récupération brute pour {item_url}]"


# ==============================================================================
# FETCHERS — PublicWWW / GrayHatWarfare / IntelX / NerdyData / MMNT  (restaurés depuis 5a)
# ==============================================================================
class PublicWWWFetcher:
    name = "publicwww"

    def __init__(self, delay: float = 5.0, api_key: Optional[str] = None):
        self.delay = delay
        self.api_key = api_key

    async def discover(self, keywords: List[str]) -> List[str]:
        if not self.api_key:
            _print("[-] PublicWWW nécessite --publicwww-key", "red")
            return []
        urls: List[str] = []
        for kw in keywords:
            q = urllib.parse.quote(f'"{kw}"')
            url = f"https://api.publicwww.com/v1/search?query={q}&key={self.api_key}&format=json"
            req = urllib.request.Request(url, headers={"User-Agent": "LeakSearcher/5.0"})

            def _get() -> List[str]:
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read().decode("utf-8"))
                return [it.get("url", "") for it in data
                        if isinstance(it, dict) and it.get("url")][:5]

            try:
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] PublicWWW: {len(found)} site(s) pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Erreur PublicWWW pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_url: str) -> str:
        req = urllib.request.Request(item_url, headers={"User-Agent": "LeakSearcher/5.0"})

        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")

        return await asyncio.to_thread(_get)


class GrayHatWarfareFetcher:
    name = "grayhatwarfare"
    SEARCH_URL = "https://buckets.grayhatwarfare.com/api/v2/files?keywords={}&start=0&limit=20"

    def __init__(self, delay: float = 5.0, api_key: Optional[str] = None):
        self.delay = delay
        self.api_key = api_key

    async def discover(self, keywords: List[str]) -> List[str]:
        if not self.api_key:
            _print("[-] GrayHatWarfare nécessite --ghw-key", "red")
            return []
        urls: List[str] = []
        for kw in keywords:
            url = self.SEARCH_URL.format(urllib.parse.quote(kw))
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "LeakSearcher/5.0",
                         "Authorization": f"Bearer {self.api_key}"},
            )

            def _get() -> List[str]:
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read().decode("utf-8"))
                return [f.get("url", "") for f in data.get("files", []) if f.get("url")][:5]

            try:
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] GrayHatWarfare: {len(found)} fichier(s) pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Erreur GrayHatWarfare pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_url: str) -> str:
        req = urllib.request.Request(item_url, headers={"User-Agent": "LeakSearcher/5.0"})

        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")

        return await asyncio.to_thread(_get)


class IntelXFetcher:
    name = "intelx"
    SEARCH_URL = "https://2.intelx.io/intelligent/search"
    RESULT_URL = "https://2.intelx.io/intelligent/search/result?id={}&limit=10"

    def __init__(self, delay: float = 5.0, api_key: Optional[str] = None):
        self.delay = delay
        self.api_key = api_key

    async def discover(self, keywords: List[str]) -> List[str]:
        if not self.api_key:
            _print("[-] Intelligence X nécessite --intelx-key", "red")
            return []
        urls: List[str] = []
        for kw in keywords:
            payload = {"term": kw, "maxresults": 10, "media": 0, "terminate": []}
            req = urllib.request.Request(
                self.SEARCH_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers={"User-Agent": "LeakSearcher/5.0",
                         "x-key": self.api_key,
                         "Content-Type": "application/json"},
            )

            def _get() -> List[str]:
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read().decode("utf-8"))
                search_id = data.get("id")
                if not search_id:
                    return []
                res_req = urllib.request.Request(
                    self.RESULT_URL.format(search_id),
                    headers={"x-key": self.api_key, "User-Agent": "LeakSearcher/5.0"},
                )
                with urllib.request.urlopen(res_req, timeout=15) as r2:
                    res_data = json.loads(r2.read().decode("utf-8"))
                return [rec.get("systemid") or rec.get("preview", "unknown")
                        for rec in res_data.get("records", [])[:5]]

            try:
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] Intelligence X: {len(found)} résultat(s) pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Erreur Intelligence X pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_id: str) -> str:
        return (f"[Intelligence X Record ID: {item_id}]\n"
                "L'endpoint 'read' complet consomme des crédits API. "
                "Consultez l'interface web IntelX pour le détail.")

class MmntFetcher:
    name = "mmnt"
    SEARCH_URL = "https://www.mmnt.ru/db/0/0?q={}"

    def __init__(self, delay: float = 5.0):
        self.delay = delay

    async def discover(self, keywords: List[str]) -> List[str]:
        urls: List[str] = []
        for kw in keywords:
            url = self.SEARCH_URL.format(urllib.parse.quote(kw))
            req = urllib.request.Request(url, headers={"User-Agent": "LeakSearcher/5.0"})

            def _get() -> List[str]:
                with urllib.request.urlopen(req, timeout=15) as r:
                    html = r.read().decode("utf-8", "replace")
                return list(set(re.findall(r'href="(ftp://[^"]+)"', html)))[:5]

            try:
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] MMNT: {len(found)} lien(s) FTP pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Erreur MMNT pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_url: str) -> str:
        req = urllib.request.Request(item_url, headers={"User-Agent": "LeakSearcher/5.0"})

        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")

        return await asyncio.to_thread(_get)


class NerdyDataFetcher:
    name = "nerdydata"
    SEARCH_URL = "https://www.nerdydata.com/search/#!/searchTerm={}"

    def __init__(self, delay: float = 5.0):
        self.delay = delay

    async def discover(self, keywords: List[str]) -> List[str]:
        urls: List[str] = []
        for kw in keywords:
            _print(f"[*] NerdyData: recherche '{kw}' (scraping best-effort)", "yellow")
            req = urllib.request.Request(
                self.SEARCH_URL.format(urllib.parse.quote(kw)),
                headers={"User-Agent": "LeakSearcher/5.0"},
            )

            def _get() -> List[str]:
                with urllib.request.urlopen(req, timeout=15) as r:
                    html = r.read().decode("utf-8", "replace")
                return list(set(re.findall(r'href="(https?://[^"]+)"', html)))[:5]

            try:
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] NerdyData: {len(found)} lien(s) pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Erreur NerdyData pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_url: str) -> str:
        req = urllib.request.Request(item_url, headers={"User-Agent": "LeakSearcher/5.0"})

        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")

        return await asyncio.to_thread(_get)


class MockFetcher:
    """Restaure la testabilité hors-ligne (perdu en 5c/5d)."""
    name = "mock"
    SAMPLES = [
        "journal système normal: aucune alerte, service ok",
        "backup log: user admin@votre-domaine.com pass:CorrectHorseBattery payload stable",
        "config: api_key=sk_live_4eC39HqLyjWDarjtT1zdp7dc et endpoint=https://example.invalid",
    ]

    def __init__(self) -> None:
        self._i = 0

    async def discover(self, keywords: List[str]) -> List[str]:
        return [f"mock_id_{self._i + x}" for x in range(2)]

    async def fetch(self, item_id: str) -> str:
        sample = self.SAMPLES[self._i % len(self.SAMPLES)]
        self._i += 1
        return f"# {item_id}\n{sample}\n"


# ==============================================================================
# OUTILS
# ==============================================================================
def utcnow() -> str:
    return datetime.now(UTC).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask_span(text: str, start: int, end: int) -> str:
    if end <= start:
        return text
    return text[:start] + "[REDACTED]" + text[end:]


def redact_text(text: str, spans: Sequence[Tuple[int, int]]) -> str:
    out = text
    for start, end in sorted(spans, key=lambda x: x[0], reverse=True):
        out = mask_span(out, max(0, start), min(len(out), end))
    return out


def _print(msg: str, style: str = "white") -> None:
    if console:
        console.print(f"[{style}]{msg}[/{style}]")
    else:
        print(msg)


def log(cfg: Config, msg: str, style: str = "dim") -> None:
    if cfg.verbose and not cfg.quiet:
        _print(f"{datetime.now().strftime('%H:%M:%S')} {msg}", style)


# ==============================================================================
# RULES
# ==============================================================================
def build_rules(cfg: Config) -> List[Rule]:
    raw: List[Dict[str, Any]] = list(cfg.rules)
    rules: List[Rule] = []
    for r in raw:
        flags = re.IGNORECASE if r.get("ignorecase", True) else 0
        if r.get("multiline"):
            flags |= re.MULTILINE
        rules.append(Rule(
            id=str(r.get("id", r.get("name", "unknown"))),
            kind=str(r.get("kind", "context")),
            pattern=str(r["pattern"]),
            weight=int(r.get("weight", 1)),
            flags=flags,
            mask_group=int(r.get("mask_group", 0)),
        ))
    return rules


def severity_for(score: int) -> str:
    label = "INFO"
    for threshold, name in SEVERITY:
        if score >= threshold:
            label = name
    return label


# ==============================================================================
# STORAGE
# ==============================================================================
class Storage:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS seen("
            "sha256 TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS findings("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, source TEXT, sha256 TEXT, "
            "score INTEGER, severity TEXT, kinds TEXT, rule_ids TEXT, keywords TEXT, payload TEXT)"
        )
        self.conn.commit()

    def seen(self, digest: str) -> bool:
        return self.conn.execute("SELECT 1 FROM seen WHERE sha256=?", (digest,)).fetchone() is not None

    def mark_seen(self, digest: str) -> None:
        now = utcnow()
        self.conn.execute(
            "INSERT INTO seen(sha256, first_seen, last_seen, hits) VALUES(?,?,?,1) "
            "ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen, hits=hits+1",
            (digest, now, now),
        )
        self.conn.commit()

    def save_finding(self, f: Finding) -> None:
        self.conn.execute(
            "INSERT INTO findings(created_at, source, sha256, score, severity, kinds, rule_ids, keywords, payload)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (f.created_at, f.source, f.sha256, f.score, f.severity,
             json.dumps(f.kinds, ensure_ascii=False),
             json.dumps(f.rule_ids, ensure_ascii=False),
             json.dumps(f.keywords, ensure_ascii=False),
             json.dumps(f.to_dict(), ensure_ascii=False)),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


# ==============================================================================
# RATE LIMITER
# ==============================================================================
class RateLimiter:
    def __init__(self, delay: float, concurrency: int):
        self.delay = max(0.0, delay)
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self._last: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, key: str = "default") -> None:
        async with self._lock:
            now = time.monotonic()
            delta = now - self._last.get(key, 0.0)
            if delta < self.delay:
                await asyncio.sleep(self.delay - delta + random.uniform(0, self.delay * 0.15))
            self._last[key] = time.monotonic()


# ==============================================================================
# ANALYZER
# ==============================================================================
class Analyzer:
    def __init__(self, cfg: Config, rules: List[Rule]):
        self.cfg = cfg
        self.rules = rules
        self.kw_regexes = [re.compile(re.escape(k), re.IGNORECASE) for k in cfg.keywords]

    def analyze(self, source: str, text: str) -> Optional[Finding]:
        digest = sha256_text(text)
        evidence: List[Evidence] = []
        spans: List[Tuple[int, int]] = []
        kinds: List[str] = []
        rule_ids: List[str] = []
        score = 0

        for rule in self.rules:
            for m in rule.regex.finditer(text):
                grp = rule.mask_group if rule.mask_group <= (m.re.groups or 0) else 0
                s, e = m.span(grp)
                raw = m.group(grp)
                spans.append((s, e))
                ent = shannon_entropy(raw)
                bonus = 2 if (rule.kind in {"secret", "token"} and ent >= 3.8 and len(raw) >= 16) else 0
                rule_ids.append(rule.id)
                kinds.append(rule.kind)
                score += rule.weight + bonus
                preview = raw[:80]
                if self.cfg.redact:
                    if len(preview) > 8:
                        redacted = preview[:4] + "****" + preview[-4:]
                    else:
                        redacted = "****"
                    match_preview = redacted
                else:
                    match_preview = preview
                evidence.append(Evidence(
                    rule_id=rule.id, kind=rule.kind, start=s, end=e,
                    match_preview=match_preview, redacted_preview=redacted if self.cfg.redact else "[REDACTED]",
                    entropy=round(ent, 3), weight=rule.weight + bonus,
                ))

        keywords = [kw for kw, rx in zip(self.cfg.keywords, self.kw_regexes) if rx.search(text)]
        if keywords:
            score += min(6, len(keywords))
        if score < self.cfg.min_score:
            return None

        # FIX 5d : redaction du texte complet AVANT extrait
        if self.cfg.redact:
            sorted_spans = sorted(spans, key=lambda x: x[0], reverse=True)
            redacted_text = redact_text(text, sorted_spans)
            redacted_spans = [(m.start(), m.end()) for m in re.finditer(r"\[REDACTED\]", redacted_text)]
            if redacted_spans:
                s0, e0 = redacted_spans[0]
                a = max(0, s0 - self.cfg.context_chars)
                b = min(len(redacted_text), e0 + self.cfg.context_chars)
                excerpt = ("…" if a > 0 else "") + redacted_text[a:b] + ("…" if b < len(redacted_text) else "")
            else:
                excerpt = redacted_text[: self.cfg.context_chars * 2]
        else:
            if spans:
                s0, e0 = spans[0]
                a = max(0, s0 - self.cfg.context_chars)
                b = min(len(text), e0 + self.cfg.context_chars)
                excerpt = ("…" if a > 0 else "") + text[a:b] + ("…" if b < len(text) else "")
            else:
                excerpt = text[: self.cfg.context_chars * 2]

        return Finding(
            source=source, sha256=digest, score=score, severity=severity_for(score),
            kinds=sorted(set(kinds)), rule_ids=sorted(set(rule_ids)), keywords=keywords,
            evidence=evidence[:25], excerpt=excerpt[:2000],
        )


# ==============================================================================
# TRIAGE IA
# ==============================================================================
class OllamaTriage:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.prompt = (
            "Tu es un trieur défensif. Réponds uniquement en JSON: "
            '{"severity":"INFO|FAIBLE|MOYENNE|ÉLEVÉE|CRITIQUE","type":"...",'
            '"recommendation":"...","false_positive_probability":0.0}. '
            "Ne demande jamais le secret. Contenu déjà masqué: "
        )

    async def triage(self, finding: Finding) -> Dict[str, Any]:
        if not self.cfg.use_ollama:
            return self._fallback(finding)
        payload = {
            "model": self.cfg.ollama_model,
            "prompt": self.prompt + json.dumps({
                "severity_hint": finding.severity,
                "kinds": finding.kinds,
                "rules": finding.rule_ids,
                "keywords": finding.keywords,
                "excerpt": finding.excerpt,
            }, ensure_ascii=False),
            "stream": False, "format": "json",
            "options": {"temperature": 0.0},
        }
        req = urllib.request.Request(
            self.cfg.ollama_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        def _post() -> str:
            with urllib.request.urlopen(req, timeout=self.cfg.ollama_timeout) as r:
                return str(json.loads(r.read().decode("utf-8", "replace")).get("response", "{}"))

        try:
            parsed = json.loads(await asyncio.to_thread(_post))
            if not isinstance(parsed, dict):
                raise ValueError("réponse non-JSON")
            parsed.setdefault("engine", "ollama")
            return parsed
        except Exception as exc:
            out = self._fallback(finding)
            out["ollama_error"] = str(exc)[:200]
            return out

    def _fallback(self, finding: Finding) -> Dict[str, Any]:
        low = " ".join(finding.keywords).lower()
        fp = 0.75 if any(k in low for k in ["example", "test", "expired", "désactivé"]) else 0.25
        return {
            "severity": finding.severity,
            "type": ", ".join(finding.kinds) or "contexte sensible",
            "recommendation": "Vérifier l'authenticité, révoquer/rotater si confirmé, ouvrir un incident.",
            "false_positive_probability": fp,
            "engine": "heuristic",
        }


# ==============================================================================
# NOTIFIER (restauré depuis 5a)
# ==============================================================================
class Notifier:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    async def send(self, finding: Finding) -> None:
        if not self.cfg.webhook_url:
            return
        payload = json.dumps(
            {"app": APP, "version": VERSION, "finding": finding.to_dict()},
            ensure_ascii=False,
        ).encode("utf-8")
        if self.cfg.dry_run:
            _print(f"[dry-run] webhook {self.cfg.webhook_url} bytes={len(payload)}", "yellow")
            return
        req = urllib.request.Request(
            self.cfg.webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
        )

        def _post() -> None:
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read(1024)

        try:
            await asyncio.to_thread(_post)
        except Exception as exc:
            _print(f"[-] Webhook échec (non bloquant): {exc}", "yellow")


# ==============================================================================
# RENDU
# ==============================================================================
def render_finding(f: Finding) -> None:
    if not console or not Panel or not Table:
        _print(json.dumps(f.to_dict(), ensure_ascii=False), "red")
        return
    console.print(Panel(
        f"[bold red]🚨 {f.severity}[/bold red] score={f.score}\n"
        f"source={f.source}\nsha256={f.sha256[:16]}…\n"
        f"règles: {', '.join(f.rule_ids) or '-'}\n"
        f"mots-clés: {', '.join(f.keywords) or '-'}",
        title="[bold red]LEAK POTENTIEL[/bold red]", border_style="red",
    ))
    table = Table(title="Triage IA Local", header_style="bold magenta")
    table.add_column("Champ", style="cyan")
    table.add_column("Valeur", style="white")
    for k in ["severity", "type", "recommendation", "false_positive_probability", "engine"]:
        table.add_row(k, str(f.triage.get(k, "-")))
    console.print(table)
    console.print(Panel(f.excerpt, title="Extrait masqué (PII protégées)", border_style="yellow"))


# ==============================================================================
# PIPELINE
# ==============================================================================
async def process_item(fetcher: Fetcher, item_id: str, cfg: Config,
                       storage: Storage, analyzer: Analyzer,
                       triager: OllamaTriage, notifier: Notifier,
                       limiter: RateLimiter) -> None:
    async with limiter.sem:
        await limiter.wait(fetcher.name)
        attempt = 0
        while True:
            try:
                text = await fetcher.fetch(item_id)
                break
            except (urllib.error.URLError, TimeoutError, asyncio.TimeoutError) as exc:
                attempt += 1
                if attempt > cfg.max_retries:
                    _print(f"[-] Échec définitif pour {item_id}: {exc}", "red")
                    return
                sleep = cfg.backoff_base * (2 ** attempt) + random.random()
                log(cfg, f"retry {attempt}/{cfg.max_retries} {item_id}: {exc}; sleep={sleep:.1f}s", "yellow")
                await asyncio.sleep(sleep)

        digest = sha256_text(text)
        if storage.seen(digest):
            log(cfg, f"doublon ignoré: {item_id}", "dim")
            storage.mark_seen(digest)
            return
        storage.mark_seen(digest)

        finding = analyzer.analyze(item_id, text)
        if not finding:
            log(cfg, f"score trop faible: {item_id}", "green")
            return

        finding.triage = await triager.triage(finding)
        storage.save_finding(finding)
        with cfg.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": utcnow(), "event": "finding",
                                 "finding": finding.to_dict()}, ensure_ascii=False) + "\n")
        if not cfg.quiet:
            render_finding(finding)
        await notifier.send(finding)


def write_reports(cfg: Config, storage: Storage) -> Tuple[Path, Path]:
    cfg.report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rows = storage.conn.execute(
        "SELECT payload FROM findings ORDER BY id DESC LIMIT 500"
    ).fetchall()
    findings = [json.loads(r[0]) for r in rows]

    json_path = cfg.report_dir / f"report_{stamp}.json"
    json_path.write_text(
        json.dumps({"app": APP, "version": VERSION, "generated_at": utcnow(),
                    "findings": findings}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path = cfg.report_dir / f"report_{stamp}.md"
    lines = [f"# Rapport {APP} {VERSION}", f"Généré: {utcnow()}",
             f"Findings: {len(findings)}", ""]
    for f in findings:
        lines += [
            f"## {f['severity']} — {f['source']}",
            f"- score: {f['score']}",
            f"- sha256: `{f['sha256']}`",
            f"- règles: {', '.join(f['rule_ids'])}",
            f"- recommandation: {f.get('triage', {}).get('recommendation', '-')}",
            "", "```", f["excerpt"], "```", "",
        ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


# ==============================================================================
# SÉLECTION DE FETCHERS
# ==============================================================================
def build_fetcher(cfg: Config) -> Fetcher:
    src = cfg.source
    if src == "github":
        return GitHubCodeFetcher(cfg.delay, cfg.github_token)
    if src == "gist":
        return GitHubGistFetcher(cfg.delay)
    if src == "pastebin":
        return PastebinArchiveFetcher(cfg.delay)
    if src == "psbdmp":
        return PsbdmpFetcher(cfg.delay, cfg.psbdmp_api_key)
    if src == "grepapp":
        return GrepAppFetcher(cfg.delay)
    if src == "publicwww":
        return PublicWWWFetcher(cfg.delay, cfg.publicwww_key)
    if src == "grayhatwarfare":
        return GrayHatWarfareFetcher(cfg.delay, cfg.ghw_key)
    if src == "intelx":
        return IntelXFetcher(cfg.delay, cfg.intelx_key)
    if src == "mmnt":
        return MmntFetcher(cfg.delay)
    if src == "nerdydata":
        return NerdyDataFetcher(cfg.delay)
    if src == "mock":
        return MockFetcher()
    raise SystemExit(f"Source inconnue: {src}")


def build_all_fetchers(cfg: Config) -> List[Fetcher]:
    """Lance toutes les sources compatibles. Ignore celles nécessitant une clé absente."""
    out: List[Fetcher] = []
    for name in ["github", "gist", "pastebin", "psbdmp", "grepapp", "mmnt", "nerdydata"]:
        sub = Config(**{**cfg.__dict__, "source": name})
        out.append(build_fetcher(sub))
    if cfg.publicwww_key:
        out.append(PublicWWWFetcher(cfg.delay, cfg.publicwww_key))
    if cfg.ghw_key:
        out.append(GrayHatWarfareFetcher(cfg.delay, cfg.ghw_key))
    if cfg.intelx_key:
        out.append(IntelXFetcher(cfg.delay, cfg.intelx_key))
    return out


async def monitor(cfg: Config, storage: Storage) -> None:
    rules = build_rules(cfg)
    cfg.report_dir.mkdir(parents=True, exist_ok=True)
    analyzer = Analyzer(cfg, rules)
    triager = OllamaTriage(cfg)
    notifier = Notifier(cfg)
    limiter = RateLimiter(cfg.delay, cfg.per_host_concurrency)

    if cfg.source == "all":
        fetchers = build_all_fetchers(cfg)
    else:
        fetchers = [build_fetcher(cfg)]

    if console and Panel:
        names = ", ".join(f.name for f in fetchers)
        console.print(Panel.fit(
            f"[bold green]{APP}[/bold green] [white]v{VERSION}[/white]\n"
            f"sources=[bold cyan]{names}[/bold cyan] | "
            f"IA={'ollama local' if cfg.use_ollama else 'heuristique'} | "
            f"redaction={'ON' if cfg.redact else 'OFF (⚠️)'} | délai={cfg.delay}s",
            title="[bold blue]Démarrage Proactif[/bold blue]", border_style="blue",
        ))

    i = 0
    while RUNNING and (cfg.max_iterations == 0 or i < cfg.max_iterations):
        _print(f"\n[bold cyan]--- Cycle de découverte {i + 1}/{cfg.max_iterations} ---[/bold cyan]")
        tasks: List[asyncio.Task] = []
        for fetcher in fetchers:
            try:
                new_ids = await fetcher.discover(cfg.keywords)
            except Exception as exc:
                _print(f"[-] Discovery {fetcher.name} a échoué: {exc}", "red")
                continue
            if not new_ids:
                continue
            _print(f"🎯 {fetcher.name}: {len(new_ids)} élément(s) à analyser.", "bold green")
            for item_id in new_ids:
                tasks.append(asyncio.create_task(
                    process_item(fetcher, item_id, cfg, storage, analyzer,
                                 triager, notifier, limiter)
                ))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        i += 1
        if RUNNING and (cfg.max_iterations == 0 or i < cfg.max_iterations):
            _print(f"[*] Mise en veille {cfg.delay * 2:.0f}s avant prochain cycle…", "dim")
            await asyncio.sleep(cfg.delay * 2)


# ==============================================================================
# SIGNAL / ARGS / MAIN
# ==============================================================================
def handle_signal(signum: int, frame: Any) -> None:
    global RUNNING
    RUNNING = False
    _print(f"\nSignal {signum} reçu: arrêt propre en cours…", "yellow")


def parse_args(argv: Optional[Sequence[str]] = None) -> Config:
    p = argparse.ArgumentParser(
        description=f"{APP} v{VERSION}: OSINT proactif, déduplication, "
                    f"détection masquée, triage IA local."
    )

    # --- Mots-clés (pas de conflit -q/-k) ---
    p.add_argument("-k", "--keyword", action="append", dest="keywords",
                   help="Mot-clé à surveiller (répétable)")
    p.add_argument("--keywords-file", default="keywords.json",
                   help="Fichier JSON des mots-clés (défaut: keywords.json)")

    # --- Règles ---
    p.add_argument("--rules-file", default="rules.json",
                   help="Fichier JSON des règles (défaut: rules.json)")

    # --- Sources ---
    p.add_argument(
        "--source",
        choices=["github", "gist", "pastebin", "psbdmp", "grepapp",
                 "publicwww", "grayhatwarfare", "intelx", "mmnt",
                 "nerdydata", "mock", "all"],
        default="github",
        help="Source (défaut: github ; 'all' = toutes celles sans clé absente)",
    )

    # --- Comportement ---
    p.add_argument("--delay", type=float, default=5.0,
                   help="Délai en secondes entre requêtes (défaut: 5.0)")
    p.add_argument("--max-iterations", type=int, default=3,
                   help="Nombre de cycles (0 = infini)")
    p.add_argument("--no-ollama", action="store_true",
                   help="Désactive le triage IA local")
    p.add_argument("--ollama-model", default="llama3.2")
    p.add_argument("--no-redact", action="store_true",
                   help="⚠️ Désactive le masquage des PII (déconseillé)")

    # --- Clés API ---
    p.add_argument("--github-token")
    p.add_argument("--publicwww-key")
    p.add_argument("--ghw-key")
    p.add_argument("--intelx-key")
    p.add_argument("--psbdmp-api-key")

    # --- Sortie ---
    p.add_argument("--db", type=Path, default=Path("leaksearcher.sqlite3"))
    p.add_argument("--report-dir", type=Path, default=Path("reports"))
    p.add_argument("--webhook-url", default=os.environ.get("LEAKSEARCHER_WEBHOOK"))
    p.add_argument("--dry-run", action="store_true")

    # --- Debug ---
    p.add_argument("--debug-traffic", metavar="DIR",
                   help="Répertoire des logs de trafic HTTP")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--quiet", action="store_true")  # pas de -q (conflit évité)

    a = p.parse_args(argv)
    cfg = Config()

    # Configs externes
    loaded_kw = load_external_config(a.keywords_file, list(DEFAULT_KEYWORDS), "keywords")
    if a.keywords:
        loaded_kw.extend(a.keywords)
    cfg.keywords = list({k.strip() for k in loaded_kw if isinstance(k, str) and k.strip()})

    loaded_rules = load_external_config(a.rules_file, list(BUILTIN_RULES), "rules")
    cfg.rules = loaded_rules

    cfg.delay = a.delay
    cfg.max_iterations = a.max_iterations
    cfg.use_ollama = not a.no_ollama
    cfg.ollama_model = a.ollama_model
    cfg.redact = not a.no_redact
    cfg.source = a.source
    cfg.github_token = a.github_token
    cfg.publicwww_key = a.publicwww_key
    cfg.ghw_key = a.ghw_key
    cfg.intelx_key = a.intelx_key
    cfg.psbdmp_api_key = a.psbdmp_api_key
    cfg.db_path = a.db
    cfg.report_dir = a.report_dir
    cfg.webhook_url = a.webhook_url
    cfg.dry_run = a.dry_run
    cfg.verbose = a.verbose
    cfg.quiet = a.quiet

    if a.no_redact:
        _print("⚠️ --no-redact actif : secrets bruts stockés. Usage déconseillé.", "bold red")

    global traffic_logger
    if a.debug_traffic:
        traffic_logger = TrafficLogger(a.debug_traffic)
        _print(f"[*] Debug trafic activé → {a.debug_traffic}", "yellow")

    return cfg


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    cfg = parse_args(argv)
    storage: Optional[Storage] = None
    try:
        storage = Storage(cfg.db_path)
        asyncio.run(monitor(cfg, storage))
        json_path, md_path = write_reports(cfg, storage)
        _print(f"\n✓ Terminé. Rapports:\n  - {md_path}\n  - {json_path}", "bold green")
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        _print(f"\nErreur fatale : {exc}", "bold red")
        return 1
    finally:
        if storage:
            storage.close()


if __name__ == "__main__":
    raise SystemExit(main())