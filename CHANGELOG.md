# Changelog

## 0.1.3 (2026-10-22)

Pipe truncation fix, found during the v0.1.2 re-validation pass. The CLI called process.exit immediately after console.log; stdout to a pipe is asynchronous in Node, so a large JSON report piped to another process truncated at exactly 65,536 characters while the same report redirected to a file was complete (measured on a sparse cli/cli checkout: 145,508 characters to a file, 65,536 through a pipe, JSON unparseable, on the v0.1.2 binary). The scan and explain paths now set process.exitCode and let the runtime flush stdout in full before exiting; exit codes are unchanged. Regression test in test/round1.test.ts: a 350 step workflow report over 64 KiB piped through the real CLI parses in full with the correct exit code. 106 tests total. No classification or verdict changes from 0.1.2.

## 0.1.2 (2026-10-22)

Round 1 real-repo validation fixes (validation/problems.md P-002 to P-007, plus the P-015 and P-016 documentation limits). Every fix has a regression test built from the Round 1 evidence in test/round1.test.ts (26 tests, 105 total). Measured with the published 0.1.0 binary on real repos, real package trees (esbuild, puppeteer), and real agent config repos before the fix.

- P-002 BLOCKER: GitHub workflow block scalar run steps (run: | and run: >, including |- and >- and |+ chomping variants) were not inventoried at all; a repo whose only run step was a block scalar reported total 0, CLEAN. Block bodies are now collected by indentation, dedented, and classified exactly like one line commands, and every workflow finding carries the line number of its run: key.
- P-003 and P-004 calibration: COMPROMISED-PATTERN now requires strong evidence in a single finding: fetched or decoded content executed directly as code (curl or base64 decode piped to an interpreter, eval of fetched content), or credential access combined with network behavior. Weak signals alone (a remote URL, a download by itself, credential access with no send) verdict REVIEW. The canonical legitimate installers esbuild and puppeteer, and the real estates langfuse and cli/cli, no longer verdict COMPROMISED-PATTERN on pattern soup.
- P-004: CRED-ACCESS is matched on content and credential paths, never on substrings of script filenames: a gh-aw step running configure_git_credentials.sh no longer fires it. Comments are stripped before classification (a docs URL in a comment is not a fetch), and a fetch whose every URL is loopback is downgraded (localhost health checks are not network exfil shapes).
- P-005: ENV-ACCESS fires only on credential shaped env names (token, secret, password, api key, and friends, in any access syntax) or bulk access (whole object serialization such as JSON.stringify(process.env), printenv, bare env dumps, whole os.environ use), reported as ENV-ACCESS and ENV-BULK. Ordinary single named reads (NODE_ENV, HOME, RUNNER_DEBUG, ESBUILD_BINARY_PATH, npm_config_user_agent) are not flagged.
- P-006: SHELL-EXEC removed. Being a shell script, or spawning a child process, is the normal state of a hook and no longer escalates a finding to RISKY on its own; a hook is classified by its target script's contents, one hop. A svelte-kit style pre-push running pnpm install, lint, and check is no longer RISKY.
- P-007: Claude settings discovery covers the GNU stow layout (claude/settings.json, no dot, as in real dotfiles repos) and settings nested one level under a config dir (config/.claude/settings.json). A settings path that exists as a directory now produces an explicit warning instead of a silent skip.
- P-015 and P-016 documented in the README limits: .gemini/settings.json is not scanned yet, template configs are inert and not scanned, and UNKNOWN dominance on large real estates is stated with its measured share.

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
