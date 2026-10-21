#!/usr/bin/env python3
"""
LeakSearcher Ultra v3.2.0 — Surveillance de fuites avec triage IA local.
Sources natives : GitHub Code Search, Pastebin Archive, psbdmp (fallback).
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
VERSION = "3.2.0-native"
UTC = timezone.utc
RUNNING = True
console = Console() if Console else None

DEFAULT_KEYWORDS = [
    "@votre-domaine.com", "api_key", "mot_de_passe", "sk_live_", "AKIA", "-----BEGIN"
]

BUILTIN_RULES: List[Dict[str, Any]] = [
    {"id": "email", "kind": "pii", "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "weight": 1, "mask_group": 0},
    {"id": "aws_access_key", "kind": "secret", "pattern": r"\b(AKIA|ASIA)[A-Z0-9]{16}\b", "weight": 8, "mask_group": 0},
    {"id": "github_token", "kind": "secret", "pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "weight": 8, "mask_group": 0},
    {"id": "slack_token", "kind": "secret", "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "weight": 8, "mask_group": 0},
    {"id": "stripe_live", "kind": "secret", "pattern": r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", "weight": 9, "mask_group": 0},
    {"id": "telegram_bot", "kind": "secret", "pattern": r"\b\d{8,10}:[A-Za-z0-9_-]{35,}\b", "weight": 7, "mask_group": 0},
    {"id": "private_key_header", "kind": "secret", "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "weight": 10, "mask_group": 0},
    {"id": "db_uri", "kind": "secret", "pattern": r"(?i)\b(?:mysql|postgres|mongodb|redis):\/\/[^\s\"']{10,}", "weight": 6, "mask_group": 0},
    {"id": "generic_assignment", "kind": "context", "pattern": r"(?i)\b(?:api[_-]?key|secret|token|password|mot[_ -]?de[_ -]?passe|client[_-]?secret)\b\s*[:=]\s*[^\s]{6,}", "weight": 4, "mask_group": 0},
    {"id": "jwt", "kind": "token", "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "weight": 5, "mask_group": 0},
    {"id": "iban", "kind": "pii", "pattern": r"\bFR\d{2}(?:\s?\d{4}){5}\s?\d{3}\b", "weight": 7, "mask_group": 0},
]

SEVERITY = [
    (0, "INFO"), (3, "FAIBLE"), (7, "MOYENNE"), (12, "ÉLEVÉE"), (18, "CRITIQUE"),
]

@dataclass
class Config:
    delay: float = 10.0
    max_iterations: int = 3
    keywords: List[str] = field(default_factory=lambda: list(DEFAULT_KEYWORDS))
    rules_file: Optional[Path] = None
    use_ollama: bool = True
    ollama_url: str = "http://127.0.0.1:11434/api/generate"
    ollama_model: str = "llama3.2"
    ollama_timeout: float = 15.0
    verbose: bool = False
    quiet: bool = False
    redact: bool = True
    source: str = "github"  # 'github', 'pastebin', 'psbdmp', 'mock'
    github_token: Optional[str] = None
    db_path: Path = Path("leaksearcher.sqlite3")
    report_dir: Path = Path("reports")
    audit_path: Path = Path("leaksearcher_audit.jsonl")
    webhook_url: Optional[str] = None
    dry_run: bool = False
    per_host_concurrency: int = 2
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
    regex: re.Pattern[str] = field(init=False, repr=False)
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

class MockFetcher:
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

class GitHubCodeFetcher:
    """Recherche de fuites de secrets dans le code public GitHub."""
    name = "github"
    SEARCH_URL = "https://api.github.com/search/code?q={}"
    
    def __init__(self, delay: float = 10.0, token: Optional[str] = None):
        self.delay = delay
        self.headers = {
            "User-Agent": "LeakSearcher/3.2 (OSINT)",
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"

    async def discover(self, keywords: List[str]) -> List[str]:
        urls = []
        for kw in keywords:
            query = urllib.parse.quote(f"{kw} in:file")
            url = self.SEARCH_URL.format(query)
            req = urllib.request.Request(url, headers=self.headers)
            try:
                def _get():
                    with urllib.request.urlopen(req, timeout=15) as r:
                        data = json.loads(r.read().decode("utf-8"))
                        return [item["html_url"] for item in data.get("items", [])[:5]]
                found = await asyncio.to_thread(_get)
                urls.extend(found)
                _print(f"[+] GitHub: {len(found)} fichier(s) trouvé(s) pour '{kw}'", "green")
            except urllib.error.HTTPError as e:
                body = e.read(200).decode("utf-8", "replace")
                _print(f"[-] Erreur GitHub ({e.code}) pour '{kw}': {body}", "red")
            except Exception as e:
                _print(f"[-] Erreur GitHub pour '{kw}': {e}", "yellow")
            await asyncio.sleep(self.delay)
        return list(set(urls))

    async def fetch(self, item_url: str) -> str:
        raw_url = item_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        req = urllib.request.Request(raw_url, headers={"User-Agent": "LeakSearcher/3.2"})
        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")
        return await asyncio.to_thread(_get)

class PastebinArchiveFetcher:
    """Scrape l'archive publique de Pastebin pour les pastes récents."""
    name = "pastebin"
    ARCHIVE_URL = "https://pastebin.com/archive"
    RAW_URL = "https://pastebin.com/raw/{}"
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    def __init__(self, delay: float = 10.0):
        self.delay = delay

    async def discover(self, keywords: List[str]) -> List[str]:
        req = urllib.request.Request(self.ARCHIVE_URL, headers=self.HEADERS)
        try:
            def _get():
                with urllib.request.urlopen(req, timeout=15) as r:
                    html = r.read().decode("utf-8", "replace")
                    matches = re.findall(r'href="/([a-zA-Z0-9]{8})"', html)
                    return list(set(matches))[:15]
            found = await asyncio.to_thread(_get)
            _print(f"[+] Pastebin Archive: {len(found)} pastes récents trouvés (filtrage local)", "green")
            return found
        except Exception as e:
            _print(f"[-] Erreur Pastebin Archive: {e}", "red")
            return []

    async def fetch(self, item_id: str) -> str:
        url = self.RAW_URL.format(item_id)
        req = urllib.request.Request(url, headers=self.HEADERS)
        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")
        return await asyncio.to_thread(_get)

class PsbdmpFetcher:
    """Fallback sur psbdmp (si jamais il revient)."""
    name = "psbdmp"
    BASE_URLS = ["https://psbdmp.ws/api/v3", "https://psbdmp.cc/api/v3"]
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
    }

    def __init__(self, delay: float = 10.0):
        self.delay = delay
        self.active_base = self.BASE_URLS[0]

    async def discover(self, keywords: List[str]) -> List[str]:
        ids = []
        for kw in keywords:
            url = f"{self.active_base}/search/{urllib.parse.quote(kw)}"
            req = urllib.request.Request(url, headers=self.HEADERS)
            try:
                def _get():
                    with urllib.request.urlopen(req, timeout=15) as r:
                        raw = r.read().decode("utf-8")
                        try:
                            data = json.loads(raw)
                        except json.JSONDecodeError:
                            raise ValueError(f"Réponse non-JSON (WAF/Cloudflare ?): {raw[:100]}...")
                        return [d["id"] for d in data.get("dumps", [])[:5]]
                found = await asyncio.to_thread(_get)
                ids.extend(found)
                _print(f"[+] psbdmp ({self.active_base}): {len(found)} dump(s) pour '{kw}'", "green")
            except Exception as e:
                _print(f"[-] Échec psbdmp pour '{kw}': {e}", "yellow")
                if self.active_base == self.BASE_URLS[0]:
                    self.active_base = self.BASE_URLS[1]
            await asyncio.sleep(self.delay)
        return list(set(ids))

    async def fetch(self, item_id: str) -> str:
        url = f"{self.active_base}/dump/{item_id}"
        req = urllib.request.Request(url, headers=self.HEADERS)
        def _get() -> str:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "replace")
        return await asyncio.to_thread(_get)

def utcnow() -> str: return datetime.now(UTC).isoformat()
def sha256_text(text: str) -> str: return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    import math
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def mask_span(text: str, start: int, end: int) -> str:
    if end <= start: return text
    return text[:start] + "[REDACTED]" + text[end:]

def redact_text(text: str, spans: Sequence[Tuple[int, int]]) -> str:
    out = text
    for start, end in sorted(spans, key=lambda x: x[0], reverse=True):
        out = mask_span(out, max(0, start), min(len(out), end))
    return out

def context_excerpt(text: str, spans: Sequence[Tuple[int, int]], radius: int) -> str:
    if not spans: return text[: radius * 2]
    s, e = spans[0]
    a, b = max(0, s - radius), min(len(text), e + radius)
    prefix = "…" if a > 0 else ""
    suffix = "…" if b < len(text) else ""
    return prefix + text[a:b] + suffix

def build_rules(cfg: Config) -> List[Rule]:
    raw: List[Dict[str, Any]] = list(BUILTIN_RULES)
    if cfg.rules_file and cfg.rules_file.exists():
        extra = json.loads(cfg.rules_file.read_text(encoding="utf-8"))
        if not isinstance(extra, list): raise ValueError("rules_file doit contenir une liste JSON")
        raw.extend(extra)
    rules: List[Rule] = []
    for r in raw:
        flags = 0
        if r.get("ignorecase", True): flags |= re.IGNORECASE
        if r.get("multiline"): flags |= re.MULTILINE
        rules.append(Rule(id=str(r["id"]), kind=str(r.get("kind", "context")), 
                          pattern=str(r["pattern"]), weight=int(r.get("weight", 1)), 
                          flags=flags, mask_group=int(r.get("mask_group", 0))))
    return rules

def severity_for(score: int) -> str:
    label = "INFO"
    for threshold, name in SEVERITY:
        if score >= threshold: label = name
    return label

class Storage:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS seen(
            sha256 TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1)""")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, source TEXT, sha256 TEXT,
            score INTEGER, severity TEXT, kinds TEXT, rule_ids TEXT, keywords TEXT, payload TEXT)""")
        self.conn.commit()

    def seen(self, digest: str) -> bool:
        return self.conn.execute("SELECT 1 FROM seen WHERE sha256=?", (digest,)).fetchone() is not None

    def mark_seen(self, digest: str) -> None:
        now = utcnow()
        self.conn.execute("""INSERT INTO seen(sha256, first_seen, last_seen, hits) VALUES(?,?,?,1)
            ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen, hits=hits+1""", (digest, now, now))
        self.conn.commit()

    def save_finding(self, f: Finding) -> None:
        self.conn.execute("""INSERT INTO findings(created_at, source, sha256, score, severity, kinds, rule_ids, keywords, payload)
            VALUES(?,?,?,?,?,?,?,?,?)""", (f.created_at, f.source, f.sha256, f.score, f.severity,
            json.dumps(f.kinds, ensure_ascii=False), json.dumps(f.rule_ids, ensure_ascii=False),
            json.dumps(f.keywords, ensure_ascii=False), json.dumps(f.to_dict(), ensure_ascii=False)))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

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
                evidence.append(Evidence(rule.id, rule.kind, s, e, raw[:80], "[REDACTED]", round(ent, 3), rule.weight + bonus))
        
        keywords = [kw for kw, rx in zip(self.cfg.keywords, self.kw_regexes) if rx.search(text)]
        if keywords: score += min(6, len(keywords))
        if score < self.cfg.min_score: return None
            
        excerpt = context_excerpt(text, spans, self.cfg.context_chars)
        if self.cfg.redact:
            excerpt = redact_text(excerpt, [(max(0, s - self.cfg.context_chars), min(len(text), e + self.cfg.context_chars)) for s, e in spans])
            
        return Finding(source=source, sha256=digest, score=score, severity=severity_for(score),
            kinds=sorted(set(kinds)), rule_ids=sorted(set(rule_ids)), keywords=keywords,
            evidence=evidence[:25], excerpt=excerpt[:2000])

class OllamaTriage:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.prompt = (
            "Tu es un trieur défensif. Réponds uniquement en JSON: "
            "{\"severity\":\"INFO|FAIBLE|MOYENNE|ÉLEVÉE|CRITIQUE\",\"type\":\"...\",\"recommendation\":\"...\",\"false_positive_probability\":0.0}."
            " Ne demande jamais le secret. Contenu déjà masqué: "
        )

    async def triage(self, finding: Finding) -> Dict[str, Any]:
        if not self.cfg.use_ollama: return self._fallback(finding)
        payload = {
            "model": self.cfg.ollama_model,
            "prompt": self.prompt + json.dumps({
                "severity_hint": finding.severity, "kinds": finding.kinds,
                "rules": finding.rule_ids, "keywords": finding.keywords, "excerpt": finding.excerpt,
            }, ensure_ascii=False),
            "stream": False, "format": "json", "options": {"temperature": 0.0},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.cfg.ollama_url, data=data, headers={"Content-Type": "application/json"})
        def _post() -> str:
            with urllib.request.urlopen(req, timeout=self.cfg.ollama_timeout) as r:
                body = json.loads(r.read().decode("utf-8", "replace"))
                return str(body.get("response", "{}"))
        try:
            raw = await asyncio.to_thread(_post)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict): raise ValueError("réponse non-JSON")
            parsed.setdefault("engine", "ollama")
            return parsed
        except Exception as exc:
            out = self._fallback(finding)
            out["ollama_error"] = str(exc)[:200]
            return out

    def _fallback(self, finding: Finding) -> Dict[str, Any]:
        fp = 0.75 if any(k in " ".join(finding.keywords).lower() for k in ["example", "test", "expired", "désactivé"]) else 0.25
        rec = "Vérifier l'authenticité, révoquer/rotater si confirmé, ouvrir un incident."
        return {"severity": finding.severity, "type": ", ".join(finding.kinds) or "contexte sensible",
                "recommendation": rec, "false_positive_probability": fp, "engine": "heuristic"}

class Notifier:
    def __init__(self, cfg: Config):
        self.cfg = cfg
    async def send(self, finding: Finding) -> None:
        if not self.cfg.webhook_url: return
        payload = json.dumps({"app": APP, "finding": finding.to_dict()}, ensure_ascii=False).encode("utf-8")
        if self.cfg.dry_run:
            _print(f"[dry-run] webhook {self.cfg.webhook_url} bytes={len(payload)}", "yellow")
            return
        req = urllib.request.Request(self.cfg.webhook_url, data=payload, headers={"Content-Type": "application/json"})
        def _post() -> None:
            with urllib.request.urlopen(req, timeout=10) as r: r.read(1024)
        await asyncio.to_thread(_post)

def _print(msg: str, style: str = "white") -> None:
    if console: console.print(f"[{style}]{msg}[/{style}]")
    else: print(msg)

def log(cfg: Config, msg: str, style: str = "dim") -> None:
    if cfg.verbose and not cfg.quiet:
        _print(f"{datetime.now().strftime('%H:%M:%S')} {msg}", style)

def render_finding(f: Finding) -> None:
    if not console or not Panel or not Table:
        _print(json.dumps(f.to_dict(), ensure_ascii=False), "red")
        return
    console.print(Panel(
        f"[bold red]🚨 {f.severity}[/bold red] score={f.score}\n"
        f"source={f.source}\nsha256={f.sha256[:16]}…\n"
        f"règles: {', '.join(f.rule_ids) or '-'}\nmots-clés: {', '.join(f.keywords) or '-'}",
        title="[bold red]LEAK POTENTIEL[/bold red]", border_style="red"))
    table = Table(title="Triage IA Local", header_style="bold magenta")
    table.add_column("Champ", style="cyan"); table.add_column("Valeur", style="white")
    for k in ["severity", "type", "recommendation", "false_positive_probability", "engine"]:
        table.add_row(k, str(f.triage.get(k, "-")))
    console.print(table)
    console.print(Panel(f.excerpt, title="Extrait masqué (PII protégées)", border_style="yellow"))

async def process_item(fetcher: Fetcher, item_id: str, cfg: Config, rules: List[Rule], storage: Storage, analyzer: Analyzer, triager: OllamaTriage, notifier: Notifier, limiter: RateLimiter) -> None:
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
                log(cfg, f"retry {attempt}/{cfg.max_retries} pour {item_id}: {exc}; sleep={sleep:.1f}s", "yellow")
                await asyncio.sleep(sleep)
        
        digest = sha256_text(text)
        if storage.seen(digest):
            log(cfg, f"doublon ignoré (hash connu): {item_id}", "dim")
            storage.mark_seen(digest)
            return
            
        storage.mark_seen(digest)
        finding = analyzer.analyze(item_id, text)
        if not finding:
            log(cfg, f"rien à signaler (score trop faible): {item_id}", "green")
            return
            
        finding.triage = await triager.triage(finding)
        storage.save_finding(finding)
        
        with cfg.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": utcnow(), "event": "finding", "finding": finding.to_dict()}, ensure_ascii=False) + "\n")
            
        if not cfg.quiet:
            render_finding(finding)
        await notifier.send(finding)

def write_reports(cfg: Config, storage: Storage) -> Path:
    cfg.report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rows = storage.conn.execute("SELECT payload FROM findings ORDER BY id DESC LIMIT 500").fetchall()
    findings = [json.loads(r[0]) for r in rows]
    
    json_path = cfg.report_dir / f"report_{stamp}.json"
    md_path = cfg.report_dir / f"report_{stamp}.md"
    
    json_path.write_text(json.dumps({"app": APP, "version": VERSION, "generated_at": utcnow(), "findings": findings}, ensure_ascii=False, indent=2), encoding="utf-8")
    
    lines = [f"# Rapport {APP} {VERSION}", f"Généré: {utcnow()}", f"Findings: {len(findings)}", ""]
    for f in findings:
        lines += [f"## {f['severity']} — {f['source']}", f"- score: {f['score']}", f"- sha256: `{f['sha256']}`", 
                  f"- règles: {', '.join(f['rule_ids'])}", f"- recommandation: {f.get('triage', {}).get('recommendation', '-')}", "", "```", f['excerpt'], "```", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path

async def monitor(cfg: Config, storage: Storage) -> None:
    rules = build_rules(cfg)
    cfg.report_dir.mkdir(parents=True, exist_ok=True)
    analyzer = Analyzer(cfg, rules)
    triager = OllamaTriage(cfg)
    notifier = Notifier(cfg)
    limiter = RateLimiter(cfg.delay, cfg.per_host_concurrency)
    
    if cfg.source == "github":
        fetcher: Fetcher = GitHubCodeFetcher(cfg.delay, cfg.github_token)
    elif cfg.source == "pastebin":
        fetcher = PastebinArchiveFetcher(cfg.delay)
    elif cfg.source == "psbdmp":
        fetcher = PsbdmpFetcher(cfg.delay)
    elif cfg.source == "mock":
        fetcher = MockFetcher()
    else:
        raise SystemExit(f"Source inconnue: {cfg.source}")

    if console and Panel:
        console.print(Panel.fit(
            f"[bold green]{APP}[/bold green] [white]v{VERSION}[/white]\n"
            f"source={cfg.source} | IA={'ollama local' if cfg.use_ollama else 'heuristique'} | "
            f"redaction={'ON' if cfg.redact else 'OFF (⚠️)'} | délai={cfg.delay}s",
            title="[bold blue]Démarrage Proactif[/bold blue]", border_style="blue"))
            
    i = 0
    while RUNNING and (cfg.max_iterations == 0 or i < cfg.max_iterations):
        _print(f"\n[bold cyan]--- Cycle de découverte {i + 1}/{cfg.max_iterations} ---[/bold cyan]")
        
        new_ids = await fetcher.discover(cfg.keywords)
        if not new_ids:
            _print("Aucun nouveau dump trouvé pour ces mots-clés.", "dim")
        else:
            _print(f"🎯 {len(new_ids)} nouveau(x) dump(s) à analyser.", "bold green")
            
        tasks = []
        for item_id in new_ids:
            log(cfg, f"planification: {item_id}", "cyan")
            tasks.append(asyncio.create_task(
                process_item(fetcher, item_id, cfg, rules, storage, analyzer, triager, notifier, limiter)
            ))
            
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            
        i += 1
        if RUNNING and (cfg.max_iterations == 0 or i < cfg.max_iterations):
            _print(f"[*] Mise en veille pour {cfg.delay * 2}s avant le prochain cycle...", "dim")
            await asyncio.sleep(cfg.delay * 2)

def handle_signal(signum: int, frame: Any) -> None:
    global RUNNING
    RUNNING = False
    _print(f"\nSignal {signum} reçu: arrêt propre en cours...", "yellow")

def parse_args(argv: Optional[Sequence[str]] = None) -> Config:
    p = argparse.ArgumentParser(description=f"{APP}: OSINT proactif, déduplication, détection masquée, triage IA local.")
    p.add_argument("--delay", type=float, default=10.0, help="Délai en secondes entre les requêtes (défaut: 10.0)")
    p.add_argument("--max-iterations", type=int, default=3, help="Nombre de cycles de surveillance (0 = infini)")
    p.add_argument("--keyword", "-k", action="append", dest="keywords", help="Mot-clé à surveiller (répétable)")
    p.add_argument("--rules-file", type=Path, help="Fichier JSON de règles Regex supplémentaires")
    p.add_argument("--no-ollama", action="store_true", help="Désactive le triage IA local")
    p.add_argument("--ollama-model", default="llama3.2", help="Modèle Ollama à utiliser")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--no-redact", action="store_true", help="⚠️ Désactive le masquage des PII (déconseillé)")
    p.add_argument("--source", choices=["github", "pastebin", "psbdmp", "mock"], default="github", help="Source de données (défaut: github)")
    p.add_argument("--github-token", help="Token GitHub personnel pour éviter les rate limits (recommandé)")
    p.add_argument("--db", type=Path, default=Path("leaksearcher.sqlite3"))
    p.add_argument("--report-dir", type=Path, default=Path("reports"))
    p.add_argument("--webhook-url", default=os.environ.get("LEAKSEARCHER_WEBHOOK"))
    p.add_argument("--dry-run", action="store_true")
    
    a = p.parse_args(argv)
    cfg = Config()
    
    for attr in ["delay", "max_iterations", "ollama_model", "db", "report_dir", "webhook_url", "dry_run", "github_token"]:
        val = getattr(a, attr)
        if val is not None: setattr(cfg, attr, val)
        
    if a.keywords: cfg.keywords = a.keywords
    if a.rules_file: cfg.rules_file = a.rules_file
    if a.no_ollama: cfg.use_ollama = False
    cfg.verbose = cfg.verbose or a.verbose
    cfg.quiet = cfg.quiet or a.quiet
    if a.no_redact: 
        cfg.redact = False
        _print("⚠️ --no-redact actif : les secrets bruts seront stockés. Usage déconseillé.", "bold red")
    if a.source: cfg.source = a.source
    
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
        md = write_reports(cfg, storage)
        _print(f"\n✓ Terminé. Rapport généré : {md}", "bold green")
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        _print(f"\nErreur fatale : {exc}", "bold red")
        return 1
    finally:
        if storage: storage.close()

if __name__ == "__main__":
    raise SystemExit(main())
