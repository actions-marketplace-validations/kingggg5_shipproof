#!/usr/bin/env python3
"""Lexical rule search baseline (Q07).

Offline, dependency-free, deterministic. Three strictly separated indexes:

  executable - the 635 shipped detectors (ID, title, CWE, ecosystem,
               remediation). The only index allowed to answer "which shipped
               rule covers X".
  research   - reviewed promotion candidates (batch A dispositions). Results
               always carry their triage status and are never presented as
               shipped rules.
  examples   - human-reviewed code examples from Q03 curation.

Exact ID/CWE lookups are deterministic. Ranked queries use IDF-weighted token
overlap with a curated English/Thai synonym expansion. Ordering ties break by
rule ID, so repeated queries return identical rankings.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

SEARCH_VERSION = "rule-search/1.0"
MAX_QUERY_BYTES = 2048
MAX_QUERY_TOKENS = 64
MAX_TOP_K = 50
TOKEN = re.compile(r"[0-9a-z\u0e00-\u0e7f_]+")
RULE_ID_TOKEN = re.compile(r"^sp[0-9]{3,}$")
CWE_TOKEN = re.compile(r"^cwe-[0-9]+$")

# Curated general vocabulary, not per-question hacks: each group lists
# interchangeable English forms plus Thai equivalents of the same concept.
SEARCH_SYNONYMS: tuple[tuple[str, ...], ...] = (
    ("eval", "exec", "code-execution", "dynamic-code", "ประมวลผลโค้ด", "รันโค้ด"),
    ("sql", "sqli", "injection", "interpolation", "query", "ฉีดคำสั่ง", "เอสคิวแอล"),
    ("shell", "command", "subprocess", "os-system", "คำสั่งเชลล์", "รันคำสั่ง"),
    ("tls", "ssl", "certificate", "verify", "ใบรับรอง", "ตรวจสอบใบรับรอง"),
    ("jwt", "token", "signature", "verify-signature", "โทเค็น", "ลายเซ็น"),
    ("secret", "password", "credential", "apikey", "api-key", "รหัสผ่าน", "ความลับ"),
    ("random", "prng", "seed", "salt", "iv", "สุ่ม", "เกลือ"),
    ("aes", "ecb", "gcm", "cipher", "encrypt", "เข้ารหัส"),
    ("hash", "bcrypt", "pbkdf2", "md5", "sha1", "แฮช"),
    ("debug", "toolbar", "ดีบัก"),
    ("xss", "html", "innerhtml", "escape", "sanitize", "สคริปต์ข้ามไซต์"),
    ("ssrf", "fetch", "url", "request-url", "คำขอ", "ยูอาร์แอล"),
    ("traversal", "path", "zip", "slip", "directory", "พาธ", "ไฟล์"),
    ("cors", "origin", "null-origin", "跨域", "ต้นทาง"),
    ("csrf", "forgery", "ซีเอสอาร์เอฟ"),
    ("auth", "authentication", "authorization", "login", "ยืนยันตัวตน", "สิทธิ์"),
    ("cookie", "session", "samesite", "secure-flag", "คุกกี้", "เซสชัน"),
    ("oauth", "openid", "saml", "pkce", "nonce", "โอเอาต์"),
    ("crypto", "cryptographic", "เข้ารหัสลับ"),
    ("timing", "compare", "constant-time", "hmac", "เปรียบเทียบ", "เวลา"),
    ("header", "crlf", "setheader", "ส่วนหัว"),
    ("webhook", "stripe", "paypal", "signature", "เว็บฮุก", "ชำระเงิน"),
    ("payment", "charge", "refund", "invoice", "idempotency", "ชำระเงิน"),
    ("key", "private-key", "pem", "aws", "กุญแจ"),
    ("docker", "container", "image", "คอนเทนเนอร์"),
    ("kubernetes", "k8s", "terraform", "nginx", "โครงสร้างพื้นฐาน"),
    ("redis", "queue", "kafka", "database", "transaction", "ฐานข้อมูล", "คิว"),
    ("react", "effect", "usestate", "render", "รีแอกต์"),
    ("django", "flask", "fastapi", "raw-query", "จังโก้"),
    ("mcp", "tool", "skill", "agent", "เอเจนต์", "เครื่องมือ"),
    ("llm", "prompt", "rag", "embedding", "โมเดล", "พรอมต์"),
    ("tls-verify", "rejectunauthorized", "ca-bundle", "ปิดตรวจสอบ"),
    ("otp", "nonce", "csrf-token", "โทเค็นใช้ครั้งเดียว"),
    ("ldap", "xpath", "xml", "entity", "แอลแดป"),
    ("deserialization", "pickle", "yaml-load", "ดีซีเรียลไลซ์"),
    ("redirect", "open-redirect", "เปลี่ยนเส้นทาง"),
    ("clickjacking", "x-frame", "frame-ancestors", "คลิกแจ็กกิง"),
    ("ratelimit", "throttle", "quota", "timeout", "จำกัดอัตรา", "หมดเวลา"),
    ("password-storage", "hashing", "argon2", "scrypt", "เก็บรหัสผ่าน"),
)

_EXPANSION: dict[str, frozenset[str]] = {}
for _group in SEARCH_SYNONYMS:
    _members = frozenset(_group)
    for _term in _group:
        _EXPANSION[_term] = _EXPANSION.get(_term, frozenset()) | _members

# Thai has no word boundaries: segment Thai-script runs by longest match
# against the curated Thai dictionary. Fixed dictionary, deterministic.
_THAI_TERMS: tuple[str, ...] = tuple(
    sorted(
        {term for group in SEARCH_SYNONYMS for term in group if re.search(r"[ก-๛]", term)},
        key=len,
        reverse=True,
    )
)
_THAI_RUN = re.compile(r"[ก-๛a-z0-9_]+")


def _segment_thai(run: str) -> list[str]:
    if not re.search(r"[ก-๛]", run):
        return [run]
    pieces: list[str] = []
    rest = run
    while rest:
        ascii_run = re.match(r"[a-z0-9_]+", rest)
        if ascii_run:
            pieces.append(ascii_run.group(0))
            rest = rest[len(ascii_run.group(0)) :]
            continue
        hit = next((term for term in _THAI_TERMS if rest.startswith(term)), None)
        if hit is None:
            hit = rest[:1]
        pieces.append(hit)
        rest = rest[len(hit) :]
    return pieces


def _stem(token: str) -> str:
    """Deterministic light stemmer for ASCII tokens. Applied to queries and
    documents alike, so conflations are consistent on both sides."""
    if re.search(r"[ก-๛]", token) or len(token) <= 5:
        return token
    if token.endswith("ing"):
        return token[:-3]
    if token.endswith("ed"):
        return token[:-2]
    return token


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for run in TOKEN.findall(text.lower()):
        for piece in _segment_thai(run):
            stemmed = _stem(piece)
            if stemmed:
                tokens.append(stemmed)
    return tokens[:MAX_QUERY_TOKENS]


def expand(tokens: list[str]) -> tuple[set[str], set[str]]:
    """Return (direct tokens, expansion-only tokens). Direct matches weigh more."""
    direct = set(tokens)
    extra: set[str] = set()
    for token in tokens:
        for term in _EXPANSION.get(token, ()):
            extra.update(TOKEN.findall(term.lower()))
            stemmed = _stem(term.lower())
            if stemmed:
                extra.add(stemmed)
    return direct, extra - direct


@dataclass
class SearchIndex:
    kind: str
    version: str = SEARCH_VERSION
    documents: list[dict[str, Any]] = field(default_factory=list)
    document_frequency: dict[str, int] = field(default_factory=dict)

    def add(self, document: dict[str, Any], text: str) -> None:
        tokens = set(tokenize(text))
        document["_tokens"] = tokens
        self.documents.append(document)
        for token in tokens:
            self.document_frequency[token] = self.document_frequency.get(token, 0) + 1

    def idf(self, token: str) -> float:
        return math.log((1 + len(self.documents)) / (1 + self.document_frequency.get(token, 0)))


def build_executable_index(rules: list[Any], remediation_of: Any) -> SearchIndex:
    """Index shipped detectors. remediation_of(rule_id) -> remediation text."""
    index = SearchIndex(kind="executable")
    for rule in rules:
        rule_id = rule.rule_id if not isinstance(rule, dict) else rule["rule_id"]
        title = rule.title if not isinstance(rule, dict) else rule.get("title", "")
        cwe = rule.cwe if not isinstance(rule, dict) else rule.get("cwe", "")
        suffixes = rule.suffixes if not isinstance(rule, dict) else rule.get("suffixes", set())
        remediation = remediation_of(rule_id)
        ecosystem = _ecosystem_for(title, {str(suffix) for suffix in suffixes})
        index.add(
            {
                "kind": "executable",
                "rule_id": rule_id,
                "title": title,
                "cwe": cwe,
                "ecosystem": ecosystem,
                "remediation": remediation,
                "provenance": f"shipproof-executable/{rule_id}",
            },
            f"{rule_id} {title} {cwe} {ecosystem} {remediation}",
        )
    return index


def _ecosystem_for(title: str, suffixes: set[str]) -> str:
    lowered = title.lower()
    for ecosystem, known in (
        ("python", {".py", ".pyi"}),
        ("typescript", {".ts", ".tsx"}),
        ("javascript", {".js", ".jsx", ".mjs", ".cjs"}),
        ("go", {".go"}),
        ("php", {".php"}),
        ("csharp", {".cs"}),
        ("cpp", {".c", ".cpp", ".h", ".hpp"}),
        ("java", {".java"}),
        ("rust", {".rs"}),
        ("sql", {".sql"}),
        ("infrastructure", {".yaml", ".yml", ".json", ".tf", ".service"}),
    ):
        if suffixes and (suffixes <= known or suffixes & known == suffixes):
            return ecosystem
    for needle, ecosystem in (
        ("c#", "csharp"),
        ("rust", "rust"),
        ("go ", "go"),
        ("php", "php"),
        ("kubernetes", "infrastructure"),
        ("terraform", "infrastructure"),
        ("docker", "infrastructure"),
    ):
        if needle in lowered:
            return ecosystem
    return "common"


def build_research_index(candidates: list[dict[str, Any]]) -> SearchIndex:
    index = SearchIndex(kind="research")
    for candidate in candidates:
        index.add(
            {
                "kind": "research",
                "candidate_id": candidate.get("candidate_id", ""),
                "ecosystem": candidate.get("ecosystem", ""),
                "cwe": candidate.get("source_id", ""),
                "status": candidate.get("batch_status", ""),
                "provenance": "shipproof-research/promotion-batch-a",
                "warning": "research candidate: not a shipped rule",
            },
            f"{candidate.get('candidate_id', '')} {candidate.get('ecosystem', '')} "
            f"{candidate.get('source_id', '')} {candidate.get('batch_status', '')} "
            f"{candidate.get('decision', '')}",
        )
    return index


def build_example_index(examples: list[dict[str, Any]]) -> SearchIndex:
    index = SearchIndex(kind="examples")
    for example in examples:
        index.add(
            {
                "kind": "examples",
                "rule_id": example.get("rule_id", ""),
                "polarity": example.get("polarity", ""),
                "provenance": "shipproof-reviewed-examples/q03",
                "excerpt": str(example.get("source", ""))[:160],
            },
            f"{example.get('rule_id', '')} {example.get('polarity', '')} reviewed example "
            f"{example.get('source', '')[:400]}",
        )
    return index


def search(index: SearchIndex, query: str, *, top_k: int = 5) -> dict[str, Any]:
    """Ranked lookup with byte/token/top-k limits and deterministic ordering."""
    if not isinstance(query, str):
        raise ValueError("query must be a string")
    if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise ValueError(f"query exceeds {MAX_QUERY_BYTES} bytes")
    if not (1 <= int(top_k) <= MAX_TOP_K):
        raise ValueError(f"top_k must hold 1-{MAX_TOP_K}")
    tokens = tokenize(query)
    if not tokens:
        return {
            "query": query,
            "kind": index.kind,
            "results": [],
            "reason": "empty query after tokenization",
        }
    direct, extra = expand(tokens)
    scored: list[tuple[float, str, dict[str, Any]]] = []
    for position, document in enumerate(index.documents):
        terms = document["_tokens"]
        direct_overlap = direct & terms
        extra_overlap = (extra & terms) - direct
        if RULE_ID_TOKEN.fullmatch(tokens[0]) and len(tokens) == 1:
            identifier = tokens[0].upper()
            key = document.get("rule_id") or document.get("candidate_id")
            if key == identifier:
                scored.append((1e9, str(key), document))
                continue
        cwe_hits = {token.upper() for token in tokens if CWE_TOKEN.fullmatch(token)}
        cwe_boost = 25.0 if cwe_hits and str(document.get("cwe", "")).upper() in cwe_hits else 0.0
        if not direct_overlap and not extra_overlap and not cwe_boost:
            continue
        score = cwe_boost + sum(2.0 * index.idf(token) for token in direct_overlap)
        score += sum(index.idf(token) for token in extra_overlap)
        key = str(document.get("rule_id") or document.get("candidate_id") or position)
        scored.append((score, key, document))
    scored.sort(key=lambda item: (-item[0], item[1]))
    results = []
    for score, _key, document in scored[: int(top_k)]:
        record = {key: value for key, value in document.items() if not key.startswith("_")}
        record["score"] = round(score, 4)
        record["search_version"] = SEARCH_VERSION
        results.append(record)
    return {"query": query, "kind": index.kind, "results": results}
