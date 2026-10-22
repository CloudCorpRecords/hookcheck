# hookcheck

**Find the hooks that run before you do. One scan, every auto-exec surface, one verdict.**

Modern supply chain attacks do not need you to run anything. They persist through hooks that run automatically: an npm `postinstall` script, a Claude Code `SessionStart` hook in `.claude/settings.json`, a VS Code task set to run on folder open. The Shai-Hulud npm worm used exactly this pattern, planting a preinstall dropper and then persisting through agent and editor hooks so it survived cleanup and stole credentials on the next open.

hookcheck scans a local repo for every auto-exec hook, classifies each one, and prints a single verdict: CLEAN, REVIEW, or COMPROMISED-PATTERN, with the file, command, rules, and evidence for every finding. Deterministic only. No LLM, no network in the core scan.

## Why this exists

Reports in October 2026 described AI agents orchestrating attacks and a self-propagating npm worm that backdoored hundreds of packages. Its persistence layer was not exotic malware. It was ordinary config files that every developer and every coding agent already trusts: package.json install scripts, `.claude/settings.json` hooks, and `.vscode/tasks.json` folderOpen tasks. Defenders needed a fast local check that an agent itself can call before opening, installing, or trusting a repo. That is hookcheck.

## What it checks

| surface | what it looks for |
| --- | --- |
| `package.json` | preinstall, install, postinstall, prepare scripts. The root package.json and nested workspace package.json files (for example `packages/*/package.json`, `apps/*/package.json`, any directory up to 8 levels below the root, node_modules excluded) are inventoried the same way |
| `.claude/settings.json` and `settings.local.json` | SessionStart, PreToolUse, and other hook commands. Also discovered: the GNU stow layout (`claude/settings.json`, no dot) and settings nested one level under a config dir (for example `config/.claude/settings.json`). A settings path that exists as a directory is reported as a warning, not silently skipped |
| Claude Code plugin hooks | `hooks/hooks.json` in a plugin root: at the repo root, or nested under plugin directories (for example `plugins/<name>/hooks/hooks.json`), with the plugin root at most 8 levels below the scan root. The file carries the same events map as the hooks key of `.claude/settings.json` (SessionStart, PreToolUse, PostToolUse, Stop, UserPromptSubmit, and the rest of the Claude Code event set) and its commands are classified exactly the same way. The sibling `hooks/hooks-cursor.json` variant carries the same command object shape under Cursor event names and is inventoried the same way |
| `.vscode/tasks.json` | tasks with runOn folderOpen, plus task inventory |
| `.husky/` | every hook file and its full command content |
| `lefthook.yml` | run commands |
| `.pre-commit-config.yaml` | entry commands and remote repo URLs |
| `.cursor/` and `.codex/` | config commands and files |
| MCP configs | `.mcp.json`, `mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, `.windsurf/mcp.json`, `.codex/mcp.json` servers that autostart, each inventoried exactly once |
| `.github/workflows/` | run steps, as inventory, including block scalar bodies (`run: |` and `run: >`, with chomping variants). Every workflow finding carries the line number of its `run:` key |
| `.githooks/` | hook files |

Every surface above is discovered by one bounded recursive walk, not only at the scan root: a surface that appears inside a subdirectory (for example `packages/foo/.claude/settings.json`, `sub/.vscode/tasks.json`, or `sub/.github/workflows/ci.yml`) is inventoried from a parent scan with its real relative path in the finding, within the discovery bound documented under Limits. A surface file is inventoried exactly once however many discovery paths reach it.

Classification per hook:

- **SAFE**: matches known safe dev patterns such as test, lint, build, typecheck, husky, or lint-staged, and matches no risky rule.
- **RISKY**: matches at least one risky rule: network fetch, curl piped to an interpreter, base64 decode piped to an interpreter, credential store paths or credential files (matched on content and paths, never on a script filename that merely contains the word credentials), credential shaped environment names (token, secret, password, api key) or bulk environment access, base64 decoding or eval style obfuscation, inline code execution, or a remote URL. Ordinary single named environment reads (NODE_ENV, HOME, RUNNER_DEBUG) are not flagged. Neither are operations that are not reads: `env -u NAME` unsets a variable, `os.environ.setdefault(...)` writes one key with a default, and a `[ -n "$NAME" ]` test checks existence. A hook whose target is a shell script is classified by that script's contents, not by the fact that it is a shell script. Comments are stripped before classification, so a docs URL inside a comment is not a fetch, and a fetch whose every URL is loopback (a localhost health check) is not treated as network behavior. In script files (JavaScript, Python), the contents of string and regex literals are data, not behavior: a defensive guard whose pattern list quotes `eval(` or `curl | sh` performs neither, and hookcheck does not classify it as an attacker. Literals handed to exec style calls (`execSync("...")`, `os.system("...")`) are code by construction and are still matched. Two rules are about value flow, not co-occurrence: ENV-EXFIL fires only when a credential value demonstrably flows into an outbound send (a request payload, a query string, a pipe into a network tool, or printed output next to a send), and CRED-EXFIL when credential store contents are piped or posted straight into a network send. Environment inheritance is not a send: when the only environment movement is inheritance or bulk access passed as a subprocess environment (env=os.environ, a {**os.environ, ...} spread, dict(os.environ), os.environ.copy(), and their JavaScript forms), ENV-EXFIL additionally requires a non-loopback destination in the flow, so a test harness that starts its own server on 127.0.0.1 and hands it the inherited environment does not verdict as exfiltration; the same forms serialized into a payload, or paired with a remote destination, still fire. The ENV-BULK evidence names the form it saw: inheritance and copy forms are described as bulk access in inheritance or copy form, not as a serialization or dump. A token used as authentication (an Authorization header, the userinfo of a push URL to the repo's own host, a `--token` flag) is authentication, not exfiltration, and never fires either rule. Authentication positions are recognized by shape, not only by the Authorization spelling: any curl `-H` header argument whatever its name, any dict or object entry whose key is an authentication header name (Authorization, `x-api-key`, `*-api-key`, `*-auth-token`, and friends) in a one hop script file, and any header shaped entry inside a headers construction (a dict assigned to a headers variable, a `headers=` argument, a headers property of a request options object) all count as authentication positions. Further authentication positions are recognized by the same shape principle: a curl `-u` or `--user` basic auth pair, the value configured for a git `http.extraheader` key (an Authorization header value however it was built), an `::add-mask::` registration (printing a value there is the masking idiom itself), and destination positions in the URL of a send itself: a credential that is an entire URL path segment, the whole URL, or the URL origin (capability URLs are credentials by design: a build hook URL, a preview token in the path, a token query parameter), the value of an authentication named query parameter (`token`, `api_key`, `access_token`, `auth`, `secret`, `signature`, `key`), a bare reference in the curl URL operand position, and the destination first argument of a fetch style call. The body test decides: a credential presented in one of those positions with no credential or bulk data in the body is authentication, while the same credential in a body, in a data named query parameter, in a partial URL path segment, or in printed output still counts as exfiltration, and a capability URL shape plus credential data in the body still fires. Taint does not pass through a locally defined helper function's return value unless the helper itself returns tainted data (its body is analyzed as part of the same text), a printed length or count of a value (`len(x)`, `x.length`, `${#NAME}`) is metadata rather than a disclosure of the value, and a name occurrence that is an object key, a property name, an assignment target, or a parameter declaration is a binding, not a reference to the variable of that name. A shell variable assigned in the same text from a value containing no credential atom (a token named response variable bound to a literal file path, used as a curl `--output` sink), or bound via a command substitution whose only credential atoms sit in destination positions (an HTTP status code variable), is not itself a credential value. Fetch detection requires command position: curl or wget counts as a network fetch only when it is the invoked command (the head of a statement or pipeline segment, after sudo or env wrappers, or the head of a command string handed to an interpreter), never when the word merely names a package in an install line (`pacman -S curl`, `apt-get install curl`). In script files the remote URL rule follows the same data view as the other behavior rules: a URL that appears only inside a string literal or a comment (an error message, a documentation link, an API base constant) is data, while a URL handed to a network call (fetch, requests, http.get, urlopen, axios, sendBeacon) is a fetch target and still fires. Inline code execution (DOWNLOAD-EXEC) fires only when the evaluated content itself carries a download or remote reference; constant inline code such as a `node -e` version comparison downloads nothing and is not flagged.
- **UNKNOWN**: matches neither safe nor risky patterns. A local script name alone is UNKNOWN until a human reads it. When a hook runs a local file such as `node setup.mjs`, hookcheck reads that file and escalates the finding if the file itself matches risky rules. The same one hop following applies to direct script execution (`./setup.sh`), `node --require ./setup.mjs`, and package.json script chains (`postinstall: npm run other-script`). If the referenced file itself spawns a further local script, the chain runs past the one hop limit: the finding is floored at UNKNOWN, never SAFE, and the evidence names the second hop file, so the verdict lands at REVIEW for a hand read.

Verdict rules:

- **CLEAN**: every finding is SAFE, or no hooks were found. Exit code 0. When nothing was found, the report carries a note saying nothing was found to audit, in the JSON as well as the human output, so an empty estate never reads as an all-clear.
- **REVIEW**: at least one UNKNOWN finding, or a RISKY finding whose evidence is weak on its own (a remote URL alone, a download by itself, credential access with no network behavior). Exit code 1.
- **COMPROMISED-PATTERN**: at least one RISKY finding with strong evidence: fetched or decoded content executed directly as code (curl piped to an interpreter, base64 decode piped to an interpreter, eval of fetched content), a verified exfil flow (a credential value flowing into an outbound send, or credential store contents piped into a network tool), or credential store access combined with network behavior in the same finding. This is the Shai-Hulud persistence shape. Treat the repo as untrusted until proven otherwise. Exit code 1. Canonical legitimate installers that download their own binary (esbuild, puppeteer) verdict REVIEW under this calibration, not COMPROMISED-PATTERN; the download is reported as a RISKY finding with its evidence, and the top verdict no longer over-claims it. The same applies to a repo's own release automation: a step that reads its token and pushes to its own repo, posts its own workflow dispatch, or updates its own homebrew tap uses the token as authentication and verdicts REVIEW, because the credential value never flows into a payload to a third party. One more calibration in the same family: a CI workflow step whose only severe evidence is a curl pipe to a named vendor's official installer over HTTPS (an installer shaped path such as /install or /uv/install.sh, or a known installer host such as astral.sh or sh.rustup.rs), with no credential, persistence, or second severe signal in the finding, verdicts REVIEW with the finding kept RISKY. The same pipe on an auto-exec hook surface (an install script, a Claude settings or plugin hook, a folderOpen task), a pipe to a non-installer source, or a pipe accompanied by any other signal still reaches COMPROMISED-PATTERN. The installer shape generalizes deterministically rather than by exact list: a path segment or filename token of install, installer, or setup on token boundaries (so cargo-hawk-installer.sh and setup_lts.x qualify, and uninstall.sh does not), an installer subdomain as the first host label (get, install, installer, setup, sh, so get.maestro.mobile.dev and install.python-poetry.org qualify), a documented installer host (astral.sh, sh.rustup.rs, pyenv.run), or a pipe of the repo's own script at the immutable commit under test (github.com or raw.githubusercontent.com, the repo itself named by ${{ github.repository }} and the ref ${{ github.sha }}): same-repo content at an immutable ref adds no trust surface beyond the code already running and does not count as a remote download for the severe pipe rules. The footprint of the install itself counts as part of the pipe shape in the accompaniment test: the pipe's own NET-FETCH and REMOTE-URL, and WRITE-OUTSIDE (an installer writes into $HOME by definition), while a genuinely independent severe signal on the same finding (credential access, an exfil flow, persistence) still defeats the calibration. The calibration also composes per finding at the verdict layer: a calibrated pipe never drives the top verdict and cannot be re-armed by an unrelated severe finding elsewhere in the repo; that finding stands or falls on its own merits. Two content rules complete the picture. Content inside a search pattern is pattern text, not behavior, for both halves of a strong-evidence combination: when a command runs a search tool (grep, egrep, fgrep, rg, ag, ack), the pattern argument and the file operands are a search over data, so a credential-path string named there is a reference, not credential access, and a URL inside the pattern is never contacted; a lint that greps .npmrc and package-lock.json for a package feed pattern so it can block that feed is a defensive control, not a credential access plus network finding. The same reference doctrine covers output text: a printed message that names a credential file (the lint's own error line, "Could not scan .npmrc and package-lock.json") is a reference, not an access, so echo and printf argument text is data for the credential rule too; a command substitution inside the message ($(cat ~/.npmrc) or the backtick form) is code that runs when the message prints and stays fully visible. Actually reading a credential file and sending its contents, or grepping for a URL and then fetching it, still fires at full strength. And a pipe into an interpreter fires the severe pipe rules only when the interpreter executes its standard input: a bare interpreter, a lone dash, or mode flags only. When the program is supplied another way (an interpreter module such as python3 -m json.tool, an inline -e or -c program, or a script operand), the piped stream is data being parsed, not code being executed, so a health check that pipes a local JSON response into a formatter is not a download-and-execute shape; a program that itself executes its standard input (an inline program calling exec or eval on stdin) still fires.

Every finding reports file, hook id, command text, classification, rule ids, and evidence. Malformed JSON is reported as a warning, never silently ignored. Scanning a path that does not exist, or that is a file instead of a directory, is a clean error with exit code 2. Reports are written through a flush-aware emit: if the reader of a piped report closes the pipe early, the process exits 141 (the shell-visible equivalent of death by SIGPIPE) rather than reporting the verdict code for a report that was never delivered.

## Limits

Honest boundaries, pinned by tests in test/hardening.test.ts:

- One hop only. hookcheck follows a hook into the local file or package.json script it directly invokes, and classifies that target. It does not follow a second hop, and it does not trace data flow inside a script. A payload assembled at runtime from pieces that never appear as a recognizable pattern in any single file will not be named; the hook that runs it will usually still land in UNKNOWN or REVIEW, which is the signal to read it by hand. When the first hop file spawns a further local script, that landing is enforced rather than usual: the finding is floored at UNKNOWN and the evidence names the second hop.
- Pattern based, not execution based. hookcheck never runs the hooks it finds. A RISKY verdict means the command text matches a known bad shape, not that the payload was observed doing harm. A CLEAN verdict means no known shape matched, not that the repo is proven safe.
- Exfil detection is a static value flow check inside one finding: a credential value must visibly reach a send construct in the same command or referenced file (including through one variable assignment chain). A value laundered through several files, assembled at runtime, or sent by a tool whose arguments never name it will not be named as exfil; the finding still lands in RISKY or UNKNOWN on its other evidence. Conversely, a credential value placed in a request body, in a data named query parameter, or in a partial URL path segment counts as exfil shape even to a first party host, because credentials belong in authentication positions, not payloads; a credential presented as an entire URL path segment, as the whole URL, or as the value of an authentication named query parameter is a capability URL presentation and counts as authentication when the body carries no credential or bulk data.
- Quote awareness has edges. In script files, string and regex literal contents are treated as data for the behavior rules; a payload hidden inside a string that is assembled and executed indirectly (not through a recognized exec call) can be missed. In shell text, quoted strings are command text and stay visible, except echo and printf arguments, which are output data.
- Remote pre-commit repos and remote MCP servers are inventoried, not verified. hookcheck cannot see inside a remote pre-commit repo, so those entries are UNKNOWN with a note to review the pinned rev. A remote MCP server URL is RISKY by construction, because the server autostarts and is remote.
- Duplicate JSON keys resolve last-wins, exactly as JSON.parse, Node, and npm resolve them, so the scanner sees the same value that would actually run.
- Non-string package.json script values are skipped: npm only executes string script values, so an array or number in scripts cannot auto-run.
- Classification reads up to 200,000 characters of a hook file or a referenced local file. Beyond that depth a payload can hide; the cap exists so a hostile file cannot make the scan unbounded.
- GitHub workflow run steps in block scalars (`run: |`, `run: >`, and chomping variants) are parsed and classified like one line commands. Plain multi-line scalars without a block header are not joined, and reusable workflow internals are not resolved. YAML anchors, aliases, and merge keys on run steps are resolved when the anchor is defined in the same file; anchors applied to other step fields, and anchors defined in other files, are not resolved. Workflow files with CRLF line endings are parsed exactly like their LF equivalents.
- Nested discovery is one bounded walk covering every inventoried surface: package.json files, `.claude/settings.json` and `settings.local.json` (including the stow layout `claude/settings.json`), plugin `hooks/hooks.json` and `hooks/hooks-cursor.json` files, `.vscode/tasks.json`, `.github/workflows/*.yml` and `*.yaml`, `.husky/` and `.githooks/` hook files, lefthook configs (`lefthook.yml`, `lefthook.yaml`, `.lefthook.yml`), `.pre-commit-config.yaml`, `.cursor/` and `.codex/` config files, and MCP configs (`.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.windsurf/mcp.json`, `.codex/mcp.json`, and `.vscode/mcp.json`). A surface is in scope when its project directory sits at most 8 levels below the scan root (the plugin hooks directory itself sits one level below its plugin root), visited in sorted order. Each surface family inventories at most 200 nested files; the scan root files always count. node_modules, .git, dot directories, and symlinked directories are never entered, so surfaces deeper than the depth bound, or anywhere under node_modules, are not scanned. Non-regular files (FIFOs, sockets, device files) are never opened: every file the scanner reads is checked by stat type first and a non-regular file is skipped with a warning naming it, because opening a FIFO blocks until a writer appears and would hang the scan. The bound is never silent: when the walk hits the depth bound with more tree remaining, the report carries a warning naming the depth bound and counts the directories just below the bound that contain hook surface files or config directories; when a family hits the file cap, a warning names the cap and the count found. A scan cut short by either bound, by the cap, or by unreadable files is partial, says so in its warnings, and never verdicts a bare CLEAN when surfaces are known to have been missed. Only the object command form of the plugin schema is inventoried; a hook entry written as a bare string instead of a command object is outside the documented schema and is not inventoried.
- A file or directory the scanner sets out to inventory but cannot read (for example a workflow file at mode 000) is never skipped silently: the report carries a warning naming it, and the verdict is floored at REVIEW while any part of the estate is unread, so a partial scan never presents as a complete all-clear.
- Custom git hook directories set through core.hooksPath are not scanned: hookcheck inventories the standard `.githooks/` directory and `.husky/`, but it does not parse git config or a committed `.gitconfig` to discover a custom core.hooksPath directory. Hooks kept only in a custom hooksPath directory are outside the inventory; audit them by scanning a tree where they sit in a standard location.
- Agent config coverage boundaries: `.gemini/settings.json` is not scanned yet. Template configs (for example `templates/settings.json.template`) are not scanned: they are inert until copied into place, at which point the copied file is scanned under its real name.
- UNKNOWN is the dominant classification on large real repos (measured at roughly 80 percent of findings on langfuse and cli/cli in Round 1 validation). The classifications are inventory, not suspicion: a REVIEW verdict on a large estate means the auto-exec surface is mapped and needs human triage, and the per finding evidence says exactly what each hook runs. More workflow step patterns will be classified over time; until then hookcheck does not guess.

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
      rules: NET-FETCH, REMOTE-URL, ENV-BULK, ENV-EXFIL
      evidence: referenced local file setup.mjs is RISKY: NET-FETCH: performs a network fetch
COMPROMISED-PATTERN: at least one risky hook shows strong evidence: fetched or decoded content executed as code, credential values flowing into an outbound send, or credential store access combined with network behavior.
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
