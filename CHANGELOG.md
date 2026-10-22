# Changelog

## 0.1.1 (2026-10-21)

Hardening pass. Every fix below was found by an adversarial battery test that failed against 0.1.0 first; the battery lives in test/hardening.test.ts (44 tests, 78 total).

- Fixed crashes on malformed VS Code tasks: a null task entry, or a tasks key that is not an array, aborted the whole scan with a TypeError. Bad entries are now skipped, a non-array tasks key produces a warning, and every other surface still scans.
- Fixed a false positive: a standard pre-commit config with a remote hook repo verdicted COMPROMISED-PATTERN because the bare repo URL matched the remote URL rule. Remote pre-commit repos are now inventoried as UNKNOWN with a note to review the pinned rev.
- Fixed a miss: a UTF-8 BOM in a JSON config made JSON.parse fail and the file was skipped, hiding every hook inside it. BOMs are stripped before parsing.
- Fixed misses in one hop following: a hook that runs `./setup.sh` directly, `node --require ./setup.mjs`, or chains through another package.json script (`postinstall: npm run evil`) now inherits the target classification, the same as `node setup.mjs` did before.
- Fixed a miss: hook files (husky, githooks, agent config files) were classified from only the first 500 characters, so a payload behind padding was invisible. Classification now reads up to 200,000 characters, and referenced local files are read to the same depth.
- Fixed severity: base64 decode piped into a shell (`echo ... | base64 -d | sh`) is now its own rule, DECODE-PIPE-SH, and verdicts COMPROMISED-PATTERN instead of REVIEW. `eval $VAR` without parens now matches the OBFUSCATION rule.
- Fixed rule loss on shell line continuations: `curl ... \` split across lines keeps the CURL-PIPE-SH rule.
- Fixed VS Code folderOpen labeling: runOn is now also read from options.runOptions and from a top level runOn on the task, not only from runOptions.
- Fixed CLI exit codes: scanning a nonexistent path or a file instead of a directory is now a clean error with exit code 2, in both scan and explain. The core scan of a file path returns REVIEW with a not-a-directory warning.
- Shape warnings added: hooks key that is not an object, scripts key that is not an object, and a package.json root that is not an object each produce an explicit warning instead of a silent pass.

## 0.1.0 (2026-10-21)

First release. Security wave, tranche 1.

- `hookcheck scan [path] [--json]`: scans package.json install scripts, Claude Code settings hooks, VS Code folderOpen tasks, husky, lefthook, pre-commit, Cursor and Codex configs, MCP autostart configs, GitHub workflow run steps, and githooks.
- Per hook classification SAFE, RISKY, or UNKNOWN with rule ids and evidence for every finding.
- Verdict CLEAN, REVIEW, or COMPROMISED-PATTERN. COMPROMISED-PATTERN fires when a risky hook fetches remote code or touches credential stores, the Shai-Hulud persistence shape.
- Local file escalation: a hook that runs a local file such as node setup.mjs inherits the classification of that file when the file matches risky rules.
- MCP server with `scan_hooks` and `explain_hook` tools.
- Malformed JSON produces explicit warnings instead of silent skips.
