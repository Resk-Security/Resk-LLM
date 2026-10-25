# Changelog

## [2.2.1] - 2026-10-25

### Fixed
- `goal_hijack` is now part of the default `block_categories`: the detector
  reported the threat but never blocked it unless the caller opted in.
- Importing `resk2.integrations` no longer requires Starlette; the OpenAI
  wrapper can be used with only the `[openai]` extra.

### Changed
- `resklogits` moved to the optional `[logits]` extra (included in `[all]`).
  The base install depends only on `pyyaml` on every Python version, so
  PyTorch/Transformers are no longer pulled in implicitly on 3.11+.
- License metadata aligned with `LICENSE.txt`: Apache-2.0 (was declared MIT).

## [2.2.0] - 2026-10-24

### Added
- LLM Guard compatibility layer: `resk2.compat.llm_guard` exposes
  `PromptInjection`, `Jailbreak`, `Sensitive`, `BanTopics`, `Toxicity` and the
  `scan_prompt` / `scan_output` helpers with the same three-tuple contract.
- Tests for the compatibility layer.

### Security
- SSRF guard on `RemoteBackend`: http/https only, host allowlist, refusal of
  private, loopback, link-local and reserved addresses, redirects disabled.
- `resklogits` is only installed on Python 3.11+ (3.10 is EOL and cannot
  install the patched filelock).
- Dependency floors: `fastapi>=0.135.0`, `starlette>=1.3.1`.

### Changed
- Minimum supported Python remains 3.10 for the core package; the optional
  generation-time integration requires 3.11+.

## [2.1.0] - 2026-04-10

Previous release. See the Git history for the v2 rewrite.
