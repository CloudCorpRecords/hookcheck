# hookcheck

**Find the hooks that run before you do. One scan, every auto-exec surface, one verdict.**

Modern supply chain attacks do not need you to run anything. They persist through hooks that run automatically: an npm `postinstall` script, a Claude Code `SessionStart` hook in `.claude/settings.json`, a VS Code task set to run on folder open. The Shai-Hulud npm worm used exactly this pattern, planting a preinstall dropper and then persisting through agent and editor hooks so it survived cleanup and stole credentials on the next open.

hookcheck scans a local repo for every auto-exec hook, classifies each one, and prints a single verdict: CLEAN, REVIEW, or COMPROMISED-PATTERN, with the file, command, rules, and evidence for every finding. Deterministic only. No LLM, no network in the core scan.

## Why this exists

Reports in October 2026 described AI agents orchestrating attacks and a self-propagating npm worm that backdoored hundreds of packages. Its persistence layer was not exotic malware. It was ordinary config files that every developer and every coding agent already trusts: package.json install scripts, `.claude/settings.json` hooks, and `.vscode/tasks.json` folderOpen tasks. Defenders needed a fast local check that an agent itself can call before opening, installing, or trusting a repo. That is hookcheck.

## What it checks

| surface | what it looks for |
| --- | --- |
| `package.json` | preinstall, install, postinstall, prepare scripts |
| `.claude/settings.json` and `settings.local.json` | SessionStart, PreToolUse, and other hook commands |
| `.vscode/tasks.json` | tasks with runOn folderOpen, plus task inventory |
| `.husky/` | every hook file and its full command content |
| `lefthook.yml` | run commands |
| `.pre-commit-config.yaml` | entry commands and remote repo URLs |
| `.cursor/` and `.codex/` | config commands and files |
| MCP configs | `.mcp.json`, `mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` servers that autostart |
| `.github/workflows/` | run steps, as inventory |
| `.githooks/` | hook files |

Classification per hook:

- **SAFE**: matches known safe dev patterns such as test, lint, build, typecheck, husky, or lint-staged, and matches no risky rule.
- **RISKY**: matches at least one risky rule: network fetch, curl piped to a shell, base64 decode piped to a shell, credential store paths such as ~/.ssh or ~/.aws, environment secret access, base64 decoding or eval style obfuscation, shell spawning, inline code execution, or a remote URL.
- **UNKNOWN**: matches neither safe nor risky patterns. A local script name alone is UNKNOWN until a human reads it. When a hook runs a local file such as `node setup.mjs`, hookcheck reads that file and escalates the finding if the file itself matches risky rules. The same one hop following applies to direct script execution (`./setup.sh`), `node --require ./setup.mjs`, and package.json script chains (`postinstall: npm run other-script`).

Verdict rules:

- **CLEAN**: every finding is SAFE, or no hooks were found. Exit code 0.
- **REVIEW**: at least one UNKNOWN finding, or a RISKY finding without a remote fetch, credential, or decode-and-execute rule. Exit code 1.
- **COMPROMISED-PATTERN**: at least one RISKY finding that fetches remote code, touches credential stores, or decodes a payload into a shell. This is the Shai-Hulud persistence shape. Treat the repo as untrusted until proven otherwise. Exit code 1.

Every finding reports file, hook id, command text, classification, rule ids, and evidence. Malformed JSON is reported as a warning, never silently ignored. Scanning a path that does not exist, or that is a file instead of a directory, is a clean error with exit code 2.

## Limits

Honest boundaries, pinned by tests in test/hardening.test.ts:

- One hop only. hookcheck follows a hook into the local file or package.json script it directly invokes, and classifies that target. It does not follow a second hop, and it does not trace data flow inside a script. A payload assembled at runtime from pieces that never appear as a recognizable pattern in any single file will not be named; the hook that runs it will usually still land in UNKNOWN or REVIEW, which is the signal to read it by hand.
- Pattern based, not execution based. hookcheck never runs the hooks it finds. A RISKY verdict means the command text matches a known bad shape, not that the payload was observed doing harm. A CLEAN verdict means no known shape matched, not that the repo is proven safe.
- Remote pre-commit repos and remote MCP servers are inventoried, not verified. hookcheck cannot see inside a remote pre-commit repo, so those entries are UNKNOWN with a note to review the pinned rev. A remote MCP server URL is RISKY by construction, because the server autostarts and is remote.
- Duplicate JSON keys resolve last-wins, exactly as JSON.parse, Node, and npm resolve them, so the scanner sees the same value that would actually run.
- Non-string package.json script values are skipped: npm only executes string script values, so an array or number in scripts cannot auto-run.
- Classification reads up to 200,000 characters of a hook file or a referenced local file. Beyond that depth a payload can hide; the cap exists so a hostile file cannot make the scan unbounded.
- GitHub workflow run steps in block scalars (`run: |`) are inventoried only when they appear as single line run values; multi-line block scalar bodies are not parsed yet.

## Usage

### CLI

```bash
npx @reneturcios/hookcheck scan
npx @reneturcios/hookcheck scan ./some-repo
npx @reneturcios/hookcheck scan ./some-repo --json
npx @reneturcios/hookcheck explain ./some-repo package.json:postinstall
```

Example output:

```
hookcheck ./some-repo: COMPROMISED-PATTERN
  2 hook(s): 0 SAFE, 2 RISKY, 0 UNKNOWN
  [RISKY] package.json:postinstall (package.json)
      command: node setup.mjs
      rules: NET-FETCH, ENV-ACCESS
      evidence: referenced local file setup.mjs is RISKY: NET-FETCH: performs a network fetch
COMPROMISED-PATTERN: at least one risky hook fetches remote code or touches credential stores.
```

### MCP server

Add to your MCP client config:

```json
{
  "mcpServers": {
    "hookcheck": {
      "command": "npx",
      "args": ["-y", "@reneturcios/hookcheck", "mcp"]
    }
  }
}
```

Tools:

- `scan_hooks(path)`: full scan with verdict, findings, counts, and warnings.
- `explain_hook(path, hookId or file)`: one hook explained in plain language with its evidence.

### Docker

```bash
docker run -i ghcr.io/cloudcorprecords/hookcheck mcp
docker run --rm -v "$PWD:/repo" ghcr.io/cloudcorprecords/hookcheck scan /repo
```

## The toolkit

hookcheck is part of a family of small, single-purpose developer tools by the same author, all built the same way: one bin that serves a CLI and an MCP server, deterministic checks with evidence, no invented answers.

- [greenlight](https://github.com/CloudCorpRecords/greenlight): pre-flight checks for open-source contributions: is this issue actually landable?
- [shipcheck](https://github.com/CloudCorpRecords/shipcheck): verify a release actually shipped on every surface, or NO-GO.

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
