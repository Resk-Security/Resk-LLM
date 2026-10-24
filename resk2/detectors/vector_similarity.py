"""Vector similarity detector - cosine similarity with pluggable backends."""

from __future__ import annotations

import ipaddress
import math
import re
import json
import socket
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml

from resk2.core.detector import DetectionResult, Severity, ThreatCategory, BaseDetector

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "patterns.yaml"


class VectorBackend(ABC):
    """Abstract backend for vector similarity queries."""

    @abstractmethod
    def query(self, text: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Returns list of {id, score, metadata} sorted by descending similarity."""
        ...


class LocalTFIDFBackend(VectorBackend):
    """Local TF-IDF + cosine similarity. No external deps.

    Uses raw term frequency vectors with IDF precomputed from the pattern set.
    Cosine similarity: dot(a,b) / (norm(a) * norm(b))
    """

    def __init__(self, attack_patterns: list[str]):
        self._patterns = attack_patterns
        self._doc_count = len(attack_patterns) + 1  # +1 for smoothing
        self._idf: dict[str, float] = {}
        self._tokenized: list[list[str]] = []
        self._build_index()

    def _tokenize(self, text: str) -> list[str]:
        tokens = re.findall(r"[a-z]{2,}", text.lower())
        return [t for t in tokens if len(t) >= 2]

    def _build_index(self) -> None:
        tokens_list = [self._tokenize(p) for p in self._patterns]
        # Document frequency
        df: dict[str, int] = defaultdict(int)
        for tokens in tokens_list:
            for t in set(tokens):
                df[t] += 1
        self._idf = {t: math.log(self._doc_count / max(1, c)) for t, c in df.items()}
        self._tokenized = tokens_list

    def _tfidf_vector(self, tokens: list[str]) -> dict[str, float]:
        tf: dict[str, float] = defaultdict(float)
        for t in tokens:
            tf[t] += 1
        # Normalize
        total = sum(tf.values()) or 1
        return {t: (c / total) * self._idf.get(t, 0) for t, c in tf.items()}

    def _cosine(self, vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
        all_keys = set(vec_a) | set(vec_b)
        if not all_keys:
            return 0.0
        dot = sum(vec_a.get(k, 0) * vec_b.get(k, 0) for k in all_keys)
        norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
        norm_b = math.sqrt(sum(v * v for v in vec_b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def query(self, text: str, top_k: int = 3) -> list[dict[str, Any]]:
        tokens = self._tokenize(text)
        query_vec = self._tfidf_vector(tokens)
        scores = []
        for i, doc_tokens in enumerate(self._tokenized):
            doc_vec = self._tfidf_vector(doc_tokens)
            score = self._cosine(query_vec, doc_vec)
            scores.append(
                {
                    "id": f"local_{i}",
                    "score": score,
                    "metadata": {"pattern": self._patterns[i][:100]},
                }
            )
        scores.sort(key=lambda x: x["score"], reverse=True)  # type: ignore[arg-type,return-value]
        return scores[:top_k]


class _NoRedirect(HTTPRedirectHandler):
    """Refuse HTTP redirects so a validated public URL cannot pivot to an internal one."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _validate_endpoint(
    endpoint: str,
    allow_private: bool = False,
    allowed_hosts: Iterable[str] | None = None,
) -> None:
    """Validate a remote vector-DB endpoint against SSRF.

    Raises:
        ValueError: non-HTTP(S) scheme, missing host, disallowed host, or a
            hostname resolving to a private/loopback/link-local/reserved IP.
    """
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported endpoint scheme: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("Endpoint must include a hostname")
    if allowed_hosts is not None and host not in set(allowed_hosts):
        raise ValueError(f"Endpoint host not in allowlist: {host}")
    if allow_private:
        return
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve endpoint host {host}: {exc}") from exc
    for info in infos:
        raw_ip = str(info[4][0]).split("%", 1)[0]
        ip = ipaddress.ip_address(str(raw_ip))
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError(f"Refusing to connect to non-public address {ip}")


class RemoteBackend(VectorBackend):
    """Generic HTTP backend for remote vector DBs (Pinecone, Qdrant, etc.).

    Sends a text embedding request to an external API, receives similarity scores.
    Expects the remote to return a JSON array of [{id, score, metadata}].
    """

    def __init__(
        self,
        endpoint: str,
        headers: dict | None = None,
        top_k_param: str = "top_k",
        allow_private: bool = False,
        allowed_hosts: Iterable[str] | None = None,
    ):
        _validate_endpoint(endpoint, allow_private=allow_private, allowed_hosts=allowed_hosts)
        self._endpoint = endpoint
        self._headers = headers or {}
        self._top_k_param = top_k_param
        self._opener = build_opener(_NoRedirect)

    def query(self, text: str, top_k: int = 3) -> list[dict[str, Any]]:
        payload = json.dumps({"text": text, self._top_k_param: top_k})
        req = Request(
            self._endpoint,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json", **self._headers},
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            raise ValueError(f"Remote vector query failed: {exc}") from exc


class VectorSimilarityDetector(BaseDetector):
    """Detects prompts similar to known attack patterns via cosine similarity.

    Supports multiple backends:
    - local: TF-IDF built-in (default, no deps)
    - remote: HTTP POST to external vector DB
    - pg_vector: (via remote backend pointing to PG endpoint)

    Config in patterns.yaml under 'vector_similarity':
      enabled: true
      backend: local  # local | remote
      threshold: 0.75
      top_k: 3
      attack_patterns:  # for local backend
        - "ignore all previous instructions"
      endpoint: https://...  # for remote backend
      headers: {}  # for remote backend
    """

    name = "vector_similarity"
    category = ThreatCategory.DIRECT_INJECTION

    def __init__(self, config_path: str | Path | None = None):
        self._backend: VectorBackend | None = None
        self._threshold: float = 0.75
        self._top_k: int = 3

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            section = data.get("vector_similarity", {}) if data else {}
            self.enabled = section.get("enabled", True)
            self._threshold = section.get("threshold", 0.75)
            self._top_k = section.get("top_k", 3)
            backend = section.get("backend", "local")
            if backend == "local":
                raw_patterns = section.get("attack_patterns", [])
                # Support both simple strings and dicts with 'pattern' key
                patterns = []
                for p in raw_patterns:
                    if isinstance(p, dict):
                        patterns.append(p.get("pattern", ""))
                    else:
                        patterns.append(str(p))
                patterns = [p for p in patterns if p]  # filter empties
                if patterns:
                    self._backend = LocalTFIDFBackend(patterns)
            elif backend == "remote":
                self._backend = RemoteBackend(
                    section.get("endpoint", ""),
                    section.get("headers"),
                    allow_private=bool(section.get("allow_private", False)),
                    allowed_hosts=section.get("allowed_hosts"),
                )
        else:
            self.enabled = True

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")
        if not self._backend:
            return DetectionResult.safe(self.name, "No vector backend configured")

        results = self._backend.query(text, self._top_k)
        if not results:
            return DetectionResult.safe(self.name, "No similar patterns found")

        # Find best match
        best = results[0]
        score = best.get("score", 0.0)

        if score < self._threshold:
            return DetectionResult.safe(
                self.name,
                f"No matches above threshold {self._threshold} (best: {score:.3f})",
            )

        # Scoring based on similarity
        if score >= 0.95:
            severity = Severity.CRITICAL
            confidence = score
        elif score >= 0.85:
            severity = Severity.HIGH
            confidence = score
        elif score >= 0.75:
            severity = Severity.MEDIUM
            confidence = score
        else:
            severity = Severity.LOW
            confidence = score

        metadata = [r.get("metadata", {}) for r in results if r.get("score", 0) > 0]
        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=f"Similar to known attack (cosine={score:.3f}, threshold={self._threshold})",
            details={
                "best_score": score,
                "threshold": self._threshold,
                "top_matches": metadata,
                "all_scores": {r["id"]: round(r["score"], 4) for r in results},
            },
        )
