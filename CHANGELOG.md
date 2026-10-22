# Changelog

## 0.1.0 (2026-10-21)

First release. Security wave, tranche 1.

- `hookcheck scan [path] [--json]`: scans package.json install scripts, Claude Code settings hooks, VS Code folderOpen tasks, husky, lefthook, pre-commit, Cursor and Codex configs, MCP autostart configs, GitHub workflow run steps, and githooks.
- Per hook classification SAFE, RISKY, or UNKNOWN with rule ids and evidence for every finding.
- Verdict CLEAN, REVIEW, or COMPROMISED-PATTERN. COMPROMISED-PATTERN fires when a risky hook fetches remote code or touches credential stores, the Shai-Hulud persistence shape.
- Local file escalation: a hook that runs a local file such as node setup.mjs inherits the classification of that file when the file matches risky rules.
- MCP server with `scan_hooks` and `explain_hook` tools.
- Malformed JSON produces explicit warnings instead of silent skips.
