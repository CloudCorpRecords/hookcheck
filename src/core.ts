/**
 * hookcheck core: deterministic local scan for auto-exec hooks.
 *
 * No network, no LLM. Every classification comes from explicit pattern
 * rules so the same repo always produces the same report.
 */
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import type { Classification, HookFinding, HookSource, ScanReport, Verdict } from "./types.js";

export const VERSION = "0.1.6";

interface RuleDef {
  id: string;
  pattern: RegExp;
  evidence: string;
  /** True when this rule indicates outbound network behavior. */
  remote?: boolean;
  /** True when this rule indicates credential store or credential shaped access. */
  credential?: boolean;
  /**
   * True when this rule is strong evidence on its own: fetched or decoded
   * content executed directly as code. Round 1 calibration (P-003, P-004):
   * COMPROMISED-PATTERN requires strong evidence, either a severe rule, or
   * credential access combined with network behavior in the same finding.
   * A pile of weak signals (a URL alone, a localhost curl, an ordinary env
   * read) is RISKY at most and verdicts REVIEW.
   */
  severe?: boolean;
}

export const RISKY_RULES: RuleDef[] = [
  { id: "DECODE-PIPE-SH", pattern: /\bbase64\s+(-d|--decode|-D)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|node|python3?|perl|ruby)\b/, evidence: "decodes a base64 payload and pipes it straight into an interpreter", severe: true, remote: true },
  { id: "CURL-PIPE-SH", pattern: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|node|python3?|perl|ruby)\b/, evidence: "pipes a network download straight into an interpreter", severe: true, remote: true },
  { id: "REMOTE-EVAL", pattern: /\beval\b[^;]{0,80}\b(curl|wget)\b|\beval\b[^;]{0,80}\$\(\s*(curl|wget)|\bFunction\s*\([^)]{0,80}(curl|wget|fetch)/, evidence: "evaluates content fetched from the network as code", severe: true, remote: true },
  { id: "NET-FETCH", pattern: /\b(curl|wget)\b|\bfetch\s*\(|https?\s*\.get\s*\(|requests\.(get|post)\b|Invoke-WebRequest\b|Invoke-RestMethod\b/, evidence: "performs a network fetch", remote: true },
  { id: "REMOTE-URL", pattern: /https?:\/\/[^\s"'`]+/, evidence: "references a remote URL", remote: true },
  { id: "OBFUSCATION", pattern: /base64\s+(-d|--decode)|atob\s*\(|Buffer\.from\s*\([^)]*base64|\\x[0-9a-fA-F]{2}|\beval\b\s*\(|\beval\b\s+["'$(]|Function\s*\(/, evidence: "uses decoding or dynamic evaluation often used to hide payloads" },
  { id: "WRITE-OUTSIDE", pattern: /(>>?|tee)\s+~\/|(>>?|tee)\s+\$HOME\/|chmod\s+\+x/, evidence: "writes outside the repo or changes executable bits" },
  { id: "DOWNLOAD-EXEC", pattern: /\bnode\s+-e\b|\bpython3?\s+-c\b|\bdeno\s+eval\b|\bbun\s+-e\b/, evidence: "executes inline code supplied on the command line" },
];

/**
 * Rule metadata for procedurally detected rules (credential access and env
 * access are computed, not regex matched, so they are not in RISKY_RULES).
 * SHELL-EXEC is deliberately absent since v0.1.2 (P-006): spawning a child
 * process or being a shell script is the normal state of a hook and is not
 * a risky signal on its own; the target script contents are classified
 * instead, one hop.
 */
const EXTRA_RULE_META: Record<string, { remote?: boolean; credential?: boolean; severe?: boolean }> = {
  "CRED-ACCESS": { credential: true },
  "ENV-ACCESS": { credential: true },
  "ENV-BULK": { credential: true },
  // ENV-EXFIL is severe since v0.1.4 (P-018): it no longer fires on
  // co-occurrence of a credential shaped name and a URL, only when the
  // credential value demonstrably flows into an outbound send, so on its
  // own it is strong evidence. Token as authentication (an Authorization
  // header, the userinfo of a push URL, a --token flag) never counts.
  "ENV-EXFIL": { credential: true, remote: true, severe: true },
  // CRED-EXFIL: credential store contents piped straight into a network
  // tool. Severe for the same reason: the value flow is in the text.
  "CRED-EXFIL": { credential: true, remote: true, severe: true },
};

function ruleMeta(id: string): { remote?: boolean; credential?: boolean; severe?: boolean } {
  const r = RISKY_RULES.find((x) => x.id === id);
  if (r) return r;
  return EXTRA_RULE_META[id] ?? {};
}

/**
 * Strip comments before classification: block comments anywhere, and full
 * line comments (// or #) in shell, JS, and Python style files. A docs URL
 * inside a comment is not a fetch (P-003, puppeteer), and shell comments do
 * not execute. String literals containing comment markers on a code line
 * are untouched.
 */
export function stripComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .filter((l) => {
      const t = l.trim();
      return !t.startsWith("//") && !t.startsWith("#");
    })
    .join("\n");
}

/**
 * Quote awareness (Round 2, P-019). Pattern rules describe behavior:
 * fetching, evaluating, piping downloads into interpreters. A defensive
 * tool that QUOTES those patterns (a guard whose pattern list contains
 * the text eval( or curl | sh) performs none of them, and matching the
 * quoted text produced the corpus's only severe finding in Round 2, on a
 * security guard. So for script files (JS and Python), the behavior
 * rules match against a code view: the contents of string and regex
 * literals are blanked, except literals handed to exec style calls,
 * whose contents are code by construction and are spliced back in.
 * Credential path detection matches against a credential view that also
 * keeps literals handed to file access calls (a credential path is
 * normally a string argument to a read). Procedural detectors (env
 * names, exfil value flow) run on the full text but ignore matches that
 * start inside a data literal.
 *
 * Shell text is different: a quoted string in a hook command is usually
 * the command itself (CMD='curl ... | sh'; $CMD), so shell strings stay
 * visible. The one exception is echo and printf arguments, which are
 * output data: a workflow step that echoes a JSON test payload into a
 * guard is printing data, not executing it. Echo arguments are blanked
 * in the code view unless the pipeline ends in a bare interpreter,
 * where the printed text really is fed to an interpreter as code.
 */
export type Lang = "shell" | "js" | "python";

function langForFile(name: string): Lang {
  if (/\.py$/i.test(name)) return "python";
  if (/\.(?:mjs|cjs|js|ts|tsx|jsx)$/i.test(name)) return "js";
  return "shell";
}

interface TextRange { start: number; end: number }

interface LiteralSpan extends TextRange {
  contentStart: number;
  contentEnd: number;
  /** Interpolation expressions inside a template or f-string: code, never blanked. */
  holes: TextRange[];
}

function inRanges(idx: number, ranges: TextRange[]): boolean {
  return ranges.some((r) => idx >= r.start && idx < r.end);
}

/**
 * True when `name` is referenced at a code position inside `seg` (whose
 * global start offset is `segStart`): at least one occurrence that does
 * not begin inside a data literal. A variable merely NAMED in prose (help
 * text, a banner string, a docstring) is mentioned, not used; the mention
 * must not propagate taint or count as disclosure. Found in the v0.1.4
 * re-validation on jpoley/flowspec: a kwarg default tainted the variable
 * name `help` through its prose value ("GitHub token for API requests"),
 * and a banner printing the word --help then read as credential
 * disclosure next to the prose word "fetch" in a docstring.
 */
function refOutsideData(seg: string, name: string, segStart: number, dataRanges: TextRange[]): boolean {
  const re = new RegExp(`\\b${name.replace(/\$/g, "\\$")}\\b`, "g");
  for (const m of seg.matchAll(re)) {
    if (!inRanges(segStart + (m.index ?? 0), dataRanges)) return true;
  }
  return false;
}

function blankRanges(text: string, ranges: TextRange[]): string {
  if (ranges.length === 0) return text;
  const chars = text.split("");
  for (const r of ranges) {
    for (let i = r.start; i < r.end && i < chars.length; i++) {
      if (chars[i] !== "\n") chars[i] = " ";
    }
  }
  return chars.join("");
}

/** Content ranges of a literal with its interpolation holes left visible. */
function contentRanges(lit: LiteralSpan): TextRange[] {
  const out: TextRange[] = [];
  let cur = lit.contentStart;
  for (const h of lit.holes) {
    if (h.start > cur) out.push({ start: cur, end: h.start });
    cur = Math.max(cur, h.end);
  }
  if (lit.contentEnd > cur) out.push({ start: cur, end: lit.contentEnd });
  return out;
}

function scanJsLiterals(text: string): LiteralSpan[] {
  const spans: LiteralSpan[] = [];
  const n = text.length;
  let i = 0;
  let prevSig = "";
  let prevWord = "";
  const regexAfterChar = new Set("=({[,;:!&|?+-*%~^<>".split(""));
  const regexAfterWord = new Set(["return", "typeof", "case", "in", "of", "new", "delete", "void", "instanceof", "yield", "await", "throw", "else", "do"]);
  while (i < n) {
    const ch = text[i];
    if (ch === "/" && text[i + 1] === "/") { const e = text.indexOf("\n", i); i = e === -1 ? n : e; continue; }
    if (ch === "/" && text[i + 1] === "*") { const e = text.indexOf("*/", i + 2); i = e === -1 ? n : e + 2; continue; }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (text[j] === "\\") { j += 2; continue; }
        if (text[j] === ch || text[j] === "\n") break;
        j++;
      }
      spans.push({ start: i, end: Math.min(j + 1, n), contentStart: i + 1, contentEnd: j, holes: [] });
      i = Math.min(j + 1, n); prevSig = ch; prevWord = "";
      continue;
    }
    if (ch === "`") {
      let j = i + 1;
      const holes: TextRange[] = [];
      while (j < n) {
        if (text[j] === "\\") { j += 2; continue; }
        if (text[j] === "`") break;
        if (text[j] === "$" && text[j + 1] === "{") {
          const holeStart = j;
          let depth = 1; j += 2;
          while (j < n && depth > 0) {
            if (text[j] === "{") depth++;
            else if (text[j] === "}") depth--;
            j++;
          }
          holes.push({ start: holeStart, end: j });
          continue;
        }
        j++;
      }
      spans.push({ start: i, end: Math.min(j + 1, n), contentStart: i + 1, contentEnd: j, holes });
      i = Math.min(j + 1, n); prevSig = "`"; prevWord = "";
      continue;
    }
    if (ch === "/" && (prevSig === "" || regexAfterChar.has(prevSig) || regexAfterWord.has(prevWord))) {
      let j = i + 1;
      let inClass = false;
      while (j < n) {
        if (text[j] === "\\") { j += 2; continue; }
        if (text[j] === "[") inClass = true;
        else if (text[j] === "]") inClass = false;
        else if (text[j] === "/" && !inClass) break;
        else if (text[j] === "\n") break;
        j++;
      }
      let end = Math.min(j + 1, n);
      while (end < n && /[a-z]/i.test(text[end])) end++;
      spans.push({ start: i, end, contentStart: i + 1, contentEnd: j, holes: [] });
      i = end; prevSig = "/"; prevWord = "";
      continue;
    }
    if (/[A-Za-z0-9_$]/.test(ch)) { prevWord += ch; prevSig = ch; i++; continue; }
    if (/\s/.test(ch)) { i++; continue; }
    prevSig = ch; prevWord = ""; i++;
  }
  return spans;
}

function scanPyLiterals(text: string): LiteralSpan[] {
  const spans: LiteralSpan[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const ch = text[i];
    if (ch === "#") { const e = text.indexOf("\n", i); i = e === -1 ? n : e; continue; }
    if (ch === "'" || ch === '"') {
      // String prefix letters (r, b, f, u) sit immediately before the quote.
      let p = i - 1;
      let prefix = "";
      while (p >= 0 && /[rRbBfFuU]/.test(text[p])) { prefix = text[p] + prefix; p--; }
      const isF = /f/i.test(prefix);
      const triple = text.startsWith(ch + ch + ch, i);
      const qLen = triple ? 3 : 1;
      let j = i + qLen;
      const holes: TextRange[] = [];
      while (j < n) {
        if (text[j] === "\\") { j += 2; continue; }
        if (triple ? text.startsWith(ch + ch + ch, j) : text[j] === ch || text[j] === "\n") break;
        if (isF && text[j] === "{") {
          if (text[j + 1] === "{") { j += 2; continue; }
          const holeStart = j;
          let depth = 1; j++;
          while (j < n && depth > 0) {
            if (text[j] === "{") depth++;
            else if (text[j] === "}") depth--;
            j++;
          }
          holes.push({ start: holeStart, end: j });
          continue;
        }
        if (isF && text[j] === "}" && text[j + 1] === "}") { j += 2; continue; }
        j++;
      }
      spans.push({ start: i, end: Math.min(j + qLen, n), contentStart: i + qLen, contentEnd: j, holes });
      i = Math.min(j + qLen, n);
      continue;
    }
    i++;
  }
  return spans;
}

const EXEC_CALLS = ["eval", "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "system", "popen", "Popen", "Function", "runInThisContext", "runInNewContext", "runInContext", "setTimeout", "setInterval", "compile"];
const PATH_CALLS = ["readFileSync", "readFile", "createReadStream", "createWriteStream", "open", "join", "resolve", "Path", "expanduser", "homedir"];

/**
 * First argument spans of calls to the named functions. The matching
 * close paren is found with a scan that jumps over literal spans, so
 * parens inside strings do not unbalance it.
 */
function callFirstArgSpans(text: string, names: string[], literals: LiteralSpan[]): TextRange[] {
  const spans: TextRange[] = [];
  const litAt = new Map<number, LiteralSpan>();
  for (const l of literals) litAt.set(l.start, l);
  const re = new RegExp(`\\b(?:${names.join("|")})\\s*\\(`, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const open = m.index + m[0].length - 1;
    let depth = 1;
    let j = open + 1;
    let firstArgEnd = -1;
    while (j < text.length && depth > 0) {
      const lit = litAt.get(j);
      if (lit) { j = lit.end; continue; }
      const c = text[j];
      if (c === "(") depth++;
      else if (c === ")") { depth--; if (depth === 0) break; }
      else if (c === "," && depth === 1 && firstArgEnd === -1) firstArgEnd = j;
      j++;
    }
    spans.push({ start: open + 1, end: firstArgEnd === -1 ? j : firstArgEnd });
  }
  return spans;
}

/**
 * Split shell text into segments on the given separators, tracking
 * single and double quotes so separators inside quoted strings do not
 * split. Returns segment ranges in the original text.
 */
function splitShell(text: string, separators: string[]): TextRange[] {
  const out: TextRange[] = [];
  let start = 0;
  let i = 0;
  let quote = "";
  while (i < text.length) {
    const c = text[i];
    if (quote) {
      if (c === "\\" && quote === '"') { i += 2; continue; }
      if (c === quote) quote = "";
      i++;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; i++; continue; }
    const sep = separators.find((s) => text.startsWith(s, i));
    if (sep) {
      out.push({ start, end: i });
      i += sep.length;
      start = i;
      continue;
    }
    i++;
  }
  out.push({ start, end: text.length });
  return out;
}

function firstShellWord(segment: string): string {
  let s = segment.trim();
  // Skip leading env assignments and sudo.
  for (;;) {
    const assign = s.match(/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/);
    if (assign) { s = s.slice(assign[0].length); continue; }
    if (/^sudo\s+/.test(s)) { s = s.replace(/^sudo\s+/, ""); continue; }
    break;
  }
  const w = s.match(/^[A-Za-z_][A-Za-z0-9_.-]*/);
  return w ? w[0] : "";
}

/**
 * Content ranges of echo and printf string arguments in shell text:
 * output data, blanked in the code view, unless the pipeline ends in a
 * bare interpreter (or a bare sh or bash), where the printed text is fed
 * to the interpreter as its program.
 */
function shellEchoDataRanges(text: string): TextRange[] {
  const ranges: TextRange[] = [];
  for (const stmt of splitShell(text, ["\n", ";", "&&", "||"])) {
    const stmtText = text.slice(stmt.start, stmt.end);
    if (!stmtText.trim()) continue;
    const segments = splitShell(stmtText, ["|"]);
    const lastText = stmtText.slice(segments[segments.length - 1].start, segments[segments.length - 1].end);
    const lastWord = firstShellWord(lastText);
    let execSink = ["sh", "bash", "zsh", "dash", "eval", "source"].includes(lastWord);
    if (!execSink && ["python", "python3", "node", "perl", "ruby"].includes(lastWord)) {
      const rest = lastText.trim().replace(/^[A-Za-z_][A-Za-z0-9_.-]*/, "").trim();
      // Bare interpreter (optionally a lone "-") reads its program from stdin.
      execSink = rest === "" || rest === "-";
    }
    if (execSink) continue;
    for (const seg of segments) {
      const segText = stmtText.slice(seg.start, seg.end);
      const word = firstShellWord(segText);
      if (word !== "echo" && word !== "printf") continue;
      // Every quoted literal in an echo segment is printed data.
      let j = 0;
      while (j < segText.length) {
        const c = segText[j];
        if (c === "'" || c === '"') {
          let k = j + 1;
          while (k < segText.length) {
            if (segText[k] === "\\" && c === '"') { k += 2; continue; }
            if (segText[k] === c) break;
            k++;
          }
          ranges.push({ start: stmt.start + seg.start + j + 1, end: stmt.start + seg.start + k });
          j = k + 1;
          continue;
        }
        j++;
      }
    }
  }
  return ranges;
}

interface Views {
  codeText: string;
  credText: string;
  dataRanges: TextRange[];
}

function buildViews(text: string, lang: Lang): Views {
  if (lang === "shell") {
    const dataRanges = shellEchoDataRanges(text);
    return { codeText: blankRanges(text, dataRanges), credText: text, dataRanges };
  }
  const literals = lang === "python" ? scanPyLiterals(text) : scanJsLiterals(text);
  const execSpans = callFirstArgSpans(text, EXEC_CALLS, literals);
  const pathSpans = callFirstArgSpans(text, PATH_CALLS, literals);
  const role = (lit: LiteralSpan): "code" | "path" | "data" => {
    if (execSpans.some((s) => lit.contentStart >= s.start && lit.contentEnd <= s.end)) return "code";
    if (pathSpans.some((s) => lit.contentStart >= s.start && lit.contentEnd <= s.end)) return "path";
    return "data";
  };
  const codeBlank: TextRange[] = [];
  const credBlank: TextRange[] = [];
  const dataRanges: TextRange[] = [];
  for (const lit of literals) {
    const r = role(lit);
    const contents = contentRanges(lit);
    if (r === "data") { codeBlank.push(...contents); credBlank.push(...contents); dataRanges.push(...contents); }
    else if (r === "path") { codeBlank.push(...contents); }
    // "code" literals keep their contents in both views: the text is a
    // program handed to an interpreter, and behavior rules should see it.
  }
  return { codeText: blankRanges(text, codeBlank), credText: blankRanges(text, credBlank), dataRanges };
}

const CRED_FILE_PATTERNS: RegExp[] = [
  /~\/\.ssh(\/|\s|$|["'])/, /\$HOME\/\.ssh(\/|\s|$|["'])/, /(^|[\s"'(=])\.ssh\//,
  /\.aws\/credentials\b/, /\.aws\/config\b/,
  /~\/\.gnupg(\/|\s|$|["'])/, /\$HOME\/\.gnupg(\/|\s|$|["'])/, /\/\.gnupg\//,
  /(^|[\s"'(=\/])(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?\b/,
  /\.npmrc\b/, /\.netrc\b/,
  /credentials\.(json|ya?ml|toml|ini|xml|env)\b/,
  /(^|[\s"'(=\/])credentials(?=$|[\s;|&)"'])/,
  /\/\.config\/gh\//,
  /find-generic-password|find-internet-password/,
  /(homedir\(\)|Path\.home\(\)|expanduser\()\s*[,+]\s*["'][^"']*\.(ssh|aws|gnupg)/,
];

/**
 * Credential store access, matched on content and paths (P-004). Script
 * filenames are scrubbed first: a hook that runs a script named like
 * configure_git_credentials.sh is classified by that script's contents
 * (one hop), never by the word credentials inside its filename.
 */
function detectCredAccess(cmd: string): boolean {
  const scrubbed = cmd.replace(/[A-Za-z0-9_.\/-]+\.(?:sh|bash|zsh|mjs|cjs|js|ts|py|ps1)\b/g, " ");
  return CRED_FILE_PATTERNS.some((p) => p.test(scrubbed));
}

const CRED_ENV_NAME = /(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|AUTH_?KEY|SESSION_?KEY)/i;

/**
 * Env access calibration (P-005). Ordinary single named reads
 * (process.env.NODE_ENV, os.environ.get("HOME")) are not flagged at all.
 * Only credential shaped names (token, secret, password, api key, and
 * friends, in any access syntax) and bulk access (whole object
 * serialization, printenv, bare env dumps, whole os.environ use) count.
 *
 * Round 2 (P-020): the rules must match reads, not any mention.
 * os.environ.setdefault writes one named key with a default and
 * os.environ.pop removes one; neither is bulk access, and the bare
 * os.environ scan below excludes the accessor, subscript, and mutation
 * forms explicitly. Passing the environment to a subprocess
 * (env=os.environ) is inheritance, not a read. In shell text,
 * `env -u NAME` unsets a variable for the subprocess, the opposite of a
 * read, and a bare [ -n "$NAME" ] or [ -z "$NAME" ] test checks
 * existence without reading the value into anything; matches inside
 * those spans, and matches that start inside a quoted data literal
 * (an echo string, a pattern list), are skipped.
 */
function detectEnvAccess(cmd: string, dataRanges: TextRange[]): { cred: boolean; bulk: boolean } {
  let cred = false;
  let bulk = false;
  const skipSpans: TextRange[] = [
    ...Array.from(cmd.matchAll(/\benv(?:\s+-u\s+[A-Za-z_][A-Za-z0-9_]*)+/g), (m) => ({ start: m.index, end: m.index + m[0].length })),
    ...Array.from(cmd.matchAll(/\[\[?\s+-[nz]\s+"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?\s*\]\]?/g), (m) => ({ start: m.index, end: m.index + m[0].length })),
  ];
  const skipped = (idx: number): boolean => inRanges(idx, dataRanges) || inRanges(idx, skipSpans);
  const nameRes = [
    /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
    /process\.env\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g,
    /os\.environ\.get\(["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
    /os\.environ\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g,
    /getenv\(["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
    /Deno\.env\.get\(["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
    /import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
    /\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)\}?/g,
  ];
  for (const re of nameRes) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(cmd)) !== null) {
      if (m[0].startsWith("${#")) continue; // ${#NAME} is a length, not a value
      if (skipped(m.index)) continue;
      if (CRED_ENV_NAME.test(m[1])) cred = true;
    }
  }
  if (/(JSON\.stringify|Object\.(keys|values|entries|assign)|util\.inspect)\s*\([^)]*(process\.env|os\.environ)/.test(cmd)) bulk = true;
  if (/\bprintenv\b/.test(cmd) && !inRanges(cmd.search(/\bprintenv\b/), dataRanges)) bulk = true;
  if (/(^|[;&|]\s*)env\s*($|[|>;])/m.test(cmd)) bulk = true;
  if (/\b(str|dict|list)\s*\(\s*os\.environ\s*\)/.test(cmd)) bulk = true;
  // Whole os.environ use (P-020): scan every occurrence and judge the
  // operation that follows it, instead of one negative lookahead.
  const envRe = /\bos\.environ\b/g;
  let em: RegExpExecArray | null;
  while ((em = envRe.exec(cmd)) !== null) {
    if (skipped(em.index)) continue;
    const after = cmd.slice(em.index + em[0].length, em.index + em[0].length + 30);
    if (/^\s*\.get\s*\(/.test(after)) continue; // named read, judged above
    if (/^\s*\[/.test(after)) continue; // named subscript read
    if (/^\s*\.(?:setdefault|pop|update)\s*\(/.test(after)) continue; // write or removal, not a read
    if (/^\s*\.copy\s*\(/.test(after)) { bulk = true; continue; } // whole copy is a bulk read
    const before = cmd.slice(Math.max(0, em.index - 24), em.index);
    if (/env\s*=\s*$/.test(before)) continue; // subprocess env inheritance
    bulk = true;
  }
  return { cred, bulk };
}

interface Atom extends TextRange { kind: "cred" | "bulk"; inData: boolean }

/**
 * Credential value atoms: text positions where a credential shaped env
 * value, or the whole environment, is read. Atoms that start inside a
 * quoted data literal are marked inData: a pattern list that MENTIONS
 * process.env.SECRET is not reading it. Print disclosure is the one
 * analysis that still uses inData atoms, because echoing a value prints
 * it whether or not it was quoted.
 */
function findAtoms(text: string, dataRanges: TextRange[]): Atom[] {
  const atoms: Atom[] = [];
  const named: Array<{ re: RegExp; always?: boolean }> = [
    { re: /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g },
    { re: /process\.env\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g },
    { re: /os\.environ\.get\(["']([A-Za-z_][A-Za-z0-9_]*)["']/g },
    { re: /os\.environ\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g },
    { re: /getenv\(["']([A-Za-z_][A-Za-z0-9_]*)["']/g },
    { re: /Deno\.env\.get\(["']([A-Za-z_][A-Za-z0-9_]*)["']/g },
    { re: /import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)/g },
    { re: /\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)\}?/g },
    { re: /\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g, always: true },
    { re: /\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g },
  ];
  for (const { re, always } of named) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].startsWith("${#")) continue;
      if (!always && !CRED_ENV_NAME.test(m[1])) continue;
      atoms.push({ start: m.index, end: m.index + m[0].length, kind: "cred", inData: inRanges(m.index, dataRanges) });
    }
  }
  const bulkRes: RegExp[] = [
    /(?:JSON\.stringify|util\.inspect|Object\.(?:keys|values|entries|assign))\s*\([^)]*(?:process\.env|os\.environ)/g,
    /\bprintenv\b/g,
    /\b(?:str|dict|list)\s*\(\s*os\.environ\s*\)/g,
    /\bos\.environ\.copy\s*\(\s*\)/g,
    /\bprocess\.env(?!\s*(?:\.|\[))/g,
    /(^|[;&|]\s*)env\s*($|[|>;])/gm,
  ];
  for (const re of bulkRes) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const rel = m[0].search(/process\.env|os\.environ|\benv\b|printenv/);
      const at = m.index + (rel === -1 ? 0 : rel);
      atoms.push({ start: at, end: at + 3, kind: "bulk", inData: inRanges(at, dataRanges) });
    }
  }
  const envRe = /\bos\.environ\b/g;
  let em: RegExpExecArray | null;
  while ((em = envRe.exec(text)) !== null) {
    const after = text.slice(em.index + em[0].length, em.index + em[0].length + 30);
    if (/^\s*(?:\.get|\[|\.setdefault|\.pop|\.update)/.test(after)) continue;
    const before = text.slice(Math.max(0, em.index - 24), em.index);
    if (/env\s*=\s*$/.test(before)) continue;
    atoms.push({ start: em.index, end: em.index + em[0].length, kind: "bulk", inData: inRanges(em.index, dataRanges) });
  }
  return atoms;
}

/**
 * Spans where a credential is used as authentication for the destination
 * it belongs to: the userinfo of a URL (x-access-token pushes and clones
 * to the repo's own host), the value of an Authorization header, and the
 * value of a CLI auth flag (--token, --auth, --api-key). A token in one
 * of these positions authenticates the send; it is not the payload, and
 * Round 2 showed it driving false exfil verdicts on langfuse, PostHog,
 * and cas release automation (P-018).
 */
function authRanges(text: string): TextRange[] {
  const ranges: TextRange[] = [];
  for (const m of text.matchAll(/https?:\/\/[^\s"'`]+/g)) {
    const url = m[0];
    const schemeEnd = url.indexOf("://") + 3;
    const authority = url.slice(schemeEnd).split("/")[0];
    const at = authority.lastIndexOf("@");
    if (at > 0) ranges.push({ start: m.index + schemeEnd, end: m.index + schemeEnd + at });
  }
  const valueAfter = (from: number): TextRange => {
    let end = from;
    while (end < text.length && end - from < 200 && !/[\s"'`,;]/.test(text[end])) end++;
    return { start: from, end };
  };
  for (const m of text.matchAll(/authorization\s*["']?\s*[:=]\s*["']?\s*(?:bearer|basic|token)\s+/gi)) {
    ranges.push(valueAfter(m.index + m[0].length));
  }
  for (const m of text.matchAll(/--(?:token|auth|api[-_]?key|password|secret)(?:\s*=\s*|\s+)["']?/gi)) {
    ranges.push(valueAfter(m.index + m[0].length));
  }
  return ranges;
}

/** Variables assigned (transitively) from a credential value expression. */
function taintedVars(text: string, atoms: Atom[], dataRanges: TextRange[]): Set<string> {
  const tainted = new Set<string>();
  const assignRe = /(?:^|[;\n,])\s*(?:export\s+|const\s+|let\s+|var\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=(?![=<>])\s*/g;
  const assigns: Array<{ name: string; rhsStart: number; rhsEnd: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = assignRe.exec(text)) !== null) {
    const rhsStart = m.index + m[0].length;
    let rhsEnd = rhsStart;
    while (rhsEnd < text.length && text[rhsEnd] !== ";" && text[rhsEnd] !== "\n") rhsEnd++;
    assigns.push({ name: m[1], rhsStart, rhsEnd });
  }
  const live = atoms.filter((a) => !a.inData);
  for (let pass = 0; pass < 4; pass++) {
    for (const a of assigns) {
      if (tainted.has(a.name)) continue;
      if (live.some((x) => x.start >= a.rhsStart && x.start < a.rhsEnd)) { tainted.add(a.name); continue; }
      const rhs = text.slice(a.rhsStart, a.rhsEnd);
      for (const v of tainted) {
        if (refOutsideData(rhs, v, a.rhsStart, dataRanges)) { tainted.add(a.name); break; }
      }
    }
  }
  return tainted;
}

/** Balanced paren span starting at the "(" index, quote aware. */
function callSpan(text: string, openIdx: number): TextRange {
  let depth = 0;
  let quote = "";
  for (let j = openIdx; j < text.length; j++) {
    const c = text[j];
    if (quote) {
      if (c === "\\") { j++; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { quote = c; continue; }
    if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return { start: openIdx, end: j + 1 }; }
  }
  return { start: openIdx, end: text.length };
}

function spanHasTaint(text: string, span: TextRange, atoms: Atom[], tainted: Set<string>, dataRanges: TextRange[]): boolean {
  if (atoms.some((a) => !a.inData && a.start >= span.start && a.start < span.end)) return true;
  if (tainted.size === 0) return false;
  const seg = text.slice(span.start, span.end);
  for (const v of tainted) {
    if (refOutsideData(seg, v, span.start, dataRanges)) return true;
  }
  return false;
}

/**
 * Exfil value flow (Round 2, P-018). ENV-EXFIL used to fire on mere
 * co-occurrence: a credential shaped name and any URL inside one finding.
 * Since block scalars made a finding a whole 30 to 100 line step, and one
 * hop following classifies whole referenced files, co-occurrence is the
 * default state of any authenticated release step. Round 2 hand-read all
 * 15 verdict drivers across langfuse, PostHog/posthog-js, attune-ai,
 * cas, and flowspec: genuinely exfil shaped, zero. Every one was the
 * repo's own automation using its token as authentication.
 *
 * ENV-EXFIL now requires the credential VALUE to flow into a send:
 *   - an atom or a tainted variable inside a fetch, axios, requests,
 *     http.get, urlopen, XHR send, or sendBeacon call span;
 *   - an atom or tainted variable anywhere in a curl or wget statement
 *     (payload, query string, or a non Authorization header), after
 *     authentication positions have been removed;
 *   - a pipeline whose earlier segments produce a credential value or a
 *     bulk dump and whose later segment is netcat, or curl or wget
 *     reading its body from stdin;
 *   - a credential value printed or logged while a send construct is
 *     present in the same text (CI logs are a real leak channel).
 */
function analyzeExfil(text: string, views: Views, lang: Lang): boolean {
  const dataRanges = views.dataRanges;
  const auth = authRanges(text);
  const atoms = findAtoms(text, dataRanges).filter((a) => !inRanges(a.start, auth));
  const tainted = taintedVars(text, atoms, dataRanges);
  const has = (span: TextRange): boolean => spanHasTaint(text, span, atoms, tainted, dataRanges);

  const callRes: RegExp[] = [
    /\bfetch\s*\(/g,
    /\baxios(?:\s*\.\s*(?:post|put|patch|get|request|delete))?\s*\(/g,
    /\brequests\s*\.\s*(?:get|post|put|patch|request)\s*\(/g,
    /\bhttps?\s*\.\s*(?:request|get)\s*\(/g,
    /\burlopen\s*\(/g,
    /\.\s*send\s*\(/g,
    /\bsendBeacon\s*\(/g,
  ];
  for (const re of callRes) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (has(callSpan(text, m.index + m[0].length - 1))) return true;
    }
  }

  const statements = splitShell(text, ["\n", ";", "&&", "||"]);
  for (const stmt of statements) {
    if (!/\b(?:curl|wget)\b/.test(text.slice(stmt.start, stmt.end))) continue;
    if (has(stmt)) return true;
  }

  for (const stmt of statements) {
    const stmtText = text.slice(stmt.start, stmt.end);
    const segments = splitShell(stmtText, ["|"]);
    if (segments.length < 2) continue;
    for (let k = 1; k < segments.length; k++) {
      const segText = stmtText.slice(segments[k].start, segments[k].end);
      const word = firstShellWord(segText);
      const isNc = word === "nc" || word === "netcat";
      const isStdinSend = (word === "curl" || word === "wget") && /(?:-d\s+@-|--data(?:-raw|-binary)?\s+@-|-T\s+-)/.test(segText);
      if (!isNc && !isStdinSend) continue;
      for (let e = 0; e < k; e++) {
        const early: TextRange = { start: stmt.start + segments[e].start, end: stmt.start + segments[e].end };
        if (has(early)) return true;
      }
    }
  }

  // Print disclosure alongside a send construct in the same text. The
  // send gate runs on the code view with data blanked: a send WORD in
  // prose (a docstring saying "we fetch release metadata") is not a send
  // construct. In script files a printed atom or variable only counts at
  // a code position (an f-string or template interpolation hole is code;
  // prose inside a plain string is not). In shell text, echo and printf
  // arguments ARE the printed values, so references inside them count.
  const gateText = blankRanges(views.codeText, dataRanges);
  const hasSendConstruct = /\b(?:fetch|axios|requests\s*\.|urlopen|https?\s*\.\s*(?:request|get)|curl|wget|nc|netcat)\b/.test(gateText);
  if (hasSendConstruct) {
    for (const m of text.matchAll(/(?:^|[;\n|&]\s*)(?:echo|printf)\s+([^\n;|]*)/g)) {
      const span: TextRange = { start: m.index, end: m.index + m[0].length };
      if (atoms.some((a) => a.start >= span.start && a.start < span.end)) return true;
      const argText = m[1] ?? "";
      const argStart = m.index + m[0].length - argText.length;
      for (const v of tainted) {
        if (lang === "shell" || refOutsideData(argText, v, argStart, dataRanges)) return true;
      }
    }
    for (const m of text.matchAll(/\b(?:console\.(?:log|info|debug)|print)\s*\(([^)]*)\)/g)) {
      const span: TextRange = { start: m.index, end: m.index + m[0].length };
      if (atoms.some((a) => a.start >= span.start && a.start < span.end && (lang === "shell" || !a.inData))) return true;
      const argText = m[1] ?? "";
      const argStart = m.index + m[0].indexOf(argText);
      for (const v of tainted) {
        if (lang === "shell" || refOutsideData(argText, v, argStart, dataRanges)) return true;
      }
    }
  }
  return false;
}

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "0.0.0.0" || h === "::1" || h === "[::1]";
}

const SAFE_PATTERNS: RegExp[] = [
  /^(npm|npx|yarn|pnpm|bun)\s+(run\s+)?(test|lint|build|dev|start|typecheck|check|format|prepare:.*|prepublishOnly.*)$/i,
  /^(npx\s+)?(tsc|eslint|prettier|vitest|jest|mocha|husky|lint-staged|lefthook|pre-commit)(\s|$)/i,
  /^node\s+(--test|scripts\/|tools\/|build)/i,
  /^(echo|true|exit 0)\b/i,
  /^git\s+(config|rev-parse|status)/i,
  /^patch-package$/i,
  /^simple-git-hooks$/i,
];

export function classifyCommand(command: string, lang: Lang = "shell"): { classification: Classification; rules: string[]; evidence: string } {
  // Strip comments first (a docs URL in a comment is not a fetch), then
  // normalize shell line continuations and stray carriage returns, so a
  // payload split as `curl ... \` + newline + `| sh` classifies the same as
  // the one line form. GitHub ${{ }} expressions are whitespace collapsed
  // so URLs containing them parse as one token. Newlines are kept: the
  // exfil value flow analysis works statement by statement.
  const cmd = stripComments(command)
    .replace(/\\\r?\n/g, " ")
    .replace(/\r/g, " ")
    .replace(/\$\{\{([\s\S]*?)\}\}/g, (_m, inner: string) => "${{" + inner.replace(/\s+/g, "") + "}}")
    .trim();
  // Behavior rules match the code view (P-019): quoted pattern text in a
  // script file is data, not behavior. REMOTE-URL is the exception: a URL
  // is a reference wherever it appears, so it matches the full text.
  const views = buildViews(cmd, lang);
  const joined = cmd.replace(/\n/g, " ");
  const codeJoined = views.codeText.replace(/\n/g, " ");
  const fired: Array<{ id: string; evidence: string }> = [];
  for (const rule of RISKY_RULES) {
    const hay = rule.id === "REMOTE-URL" ? joined : codeJoined;
    if (rule.pattern.test(hay)) fired.push({ id: rule.id, evidence: rule.evidence });
  }
  // Loopback downgrade (P-004): a fetch whose every URL is loopback is a
  // local health check shape, not a network exfil shape. Downgrade only
  // when no severe rule fired.
  const hosts = Array.from(cmd.matchAll(/https?:\/\/([^\s"'`\/:?#]+)/g)).map((m) => m[1]);
  if (hosts.length > 0 && hosts.every(isLoopbackHost) && !fired.some((f) => ruleMeta(f.id).severe)) {
    for (let i = fired.length - 1; i >= 0; i--) {
      if (fired[i].id === "NET-FETCH" || fired[i].id === "REMOTE-URL") fired.splice(i, 1);
    }
  }
  // Credential store access, content and path based (P-004), matched on
  // the credential view so paths quoted as data in a script file (a
  // guard's blocklist) do not count, while paths handed to file access
  // calls do.
  const credAccess = detectCredAccess(views.credText);
  if (credAccess) {
    fired.push({ id: "CRED-ACCESS", evidence: "touches a credential store path or credential file" });
  }
  // Env access, credential shaped names or bulk only (P-005, P-020).
  const env = detectEnvAccess(cmd, views.dataRanges);
  if (env.cred) {
    fired.push({ id: "ENV-ACCESS", evidence: "reads an environment variable whose name is credential shaped (token, secret, password, api key)" });
  }
  if (env.bulk) {
    fired.push({ id: "ENV-BULK", evidence: "accesses the whole environment at once (serialization, printenv, or env dump)" });
  }
  // Exfil is a value flow, not a co-occurrence (P-018): the credential
  // value must reach a send. Token as authentication does not count.
  if (analyzeExfil(cmd, views, lang)) {
    fired.push({ id: "ENV-EXFIL", evidence: "a credential shaped or bulk environment value flows into an outbound send (payload, query string, printed output next to a send, or a pipe into a network tool); a token used as authentication does not count" });
  }
  if (credAccess && (
    /\|\s*(?:nc|netcat)\b/.test(joined) ||
    /\|\s*(?:curl|wget)\b[^|\n]*?(?:-d\s+@-|--data(?:-raw|-binary)?\s+@-)/.test(joined) ||
    /(?:-d|--data(?:-raw|-binary)?)\s+@[^\s"']*(?:\.ssh|\.aws|\.gnupg|id_rsa|credentials)/.test(joined)
  )) {
    fired.push({ id: "CRED-EXFIL", evidence: "credential store contents are piped or posted straight into an outbound network send" });
  }
  if (fired.length > 0) {
    return {
      classification: "RISKY",
      rules: fired.map((r) => r.id),
      evidence: fired.map((r) => `${r.id}: ${r.evidence}`).join("; "),
    };
  }
  for (const safe of SAFE_PATTERNS) {
    if (safe.test(cmd)) {
      return { classification: "SAFE", rules: [], evidence: "matches a known safe dev pattern (test, lint, build, dev tooling)" };
    }
  }
  // A bare local script or binary with no risky indicators is UNKNOWN, not SAFE:
  // we cannot prove what a local file does without reading it, and when the
  // referenced local file itself contains risky patterns we escalate below.
  return { classification: "UNKNOWN", rules: [], evidence: "no known safe pattern and no risky pattern matched; manual review needed" };
}

const SCRIPT_TOKEN_RE = /[A-Za-z0-9_.\/-]+\.(?:mjs|cjs|js|ts|sh|py)\b/g;

/**
 * Second hop detection (P-031). The one hop limit means a payload two
 * files deep is never read, and that limit is documented. What was not
 * acceptable was the chain head classifying SAFE on the strength of its
 * own command text (`node scripts/a.js` matches a safe dev pattern)
 * while its target's whole job is spawning a further local script the
 * scanner cannot see: SAFE is an affirmative statement, and the README
 * floor for chains beyond the follower is UNKNOWN or REVIEW. This
 * detector returns the local script tokens that `content` EXECUTES:
 * script tokens inside exec style call spans (execSync, spawn, Popen,
 * os.system, and friends), and interpreter invocations (`node x.js`,
 * `bash x.sh`) appearing as command text. Spawning a plain binary
 * (spawn('esbuild', ...)) executes no local script and does not count,
 * and a mere require or mention of a file is not a spawn.
 */
function secondHopScripts(scanRootAbs: string, baseAbs: string, content: string, selfAbs: string): string[] {
  const text = stripComments(content);
  const found = new Set<string>();
  const collectFrom = (segText: string): void => {
    for (const tok of segText.match(SCRIPT_TOKEN_RE) ?? []) found.add(tok);
  };
  // Exec style call spans: everything up to the matching close paren.
  const callRe = /\b(?:execSync|execFileSync|execSync|execFile|spawnSync|spawn|exec|system|popen|Popen|runInThisContext|runInNewContext)\s*\(/g;
  let cm: RegExpExecArray | null;
  while ((cm = callRe.exec(text)) !== null) {
    const span = callSpan(text, cm.index + cm[0].length - 1);
    collectFrom(text.slice(span.start, span.end));
  }
  // Interpreter invocations written as command text anywhere (shell
  // lines, command strings outside the calls above).
  const interpRe = /(?:^|[\s'"`(;|&])(?:node|bash|sh|zsh|python3?|perl|ruby)\s+(?:\.\/)?([A-Za-z0-9_.\/-]+\.(?:mjs|cjs|js|ts|sh|py))\b/gm;
  let im: RegExpExecArray | null;
  while ((im = interpRe.exec(text)) !== null) found.add(im[1]);
  const out: string[] = [];
  for (const tok of found) {
    const rel = tok.replace(/^\.\//, "");
    if (rel.includes("://")) continue;
    for (const base of [baseAbs, scanRootAbs]) {
      const abs = resolve(base, rel);
      if (abs === selfAbs) continue;
      if (abs !== scanRootAbs && !abs.startsWith(scanRootAbs + sep)) continue;
      let st; try { st = statSync(abs); } catch { continue; }
      if (st.isFile()) { out.push(rel); break; }
    }
  }
  return out;
}

/**
 * If a command references local script files, inspect those files for risky
 * patterns too (one hop). References are found by token, not only after an
 * interpreter name, so `node setup.mjs`, `./setup.sh`, `node --require
 * ./setup.mjs`, and `bash setup.sh` all resolve. References that escape the
 * scanned root are never followed. Local references resolve against
 * baseAbs first (the directory of the file that carries the hook, which
 * matters for nested package.json files) and then against the scan root.
 *
 * P-031 floor: when a referenced file is not itself RISKY but spawns a
 * further local script, the chain continues past the one hop limit, so a
 * SAFE classification is floored to UNKNOWN with the second hop named in
 * the evidence. The payload at hop two stays unclassified (the limit),
 * but the head can no longer be affirmatively cleared.
 */
function escalateWithLocalFile(root: string, finding: HookFinding, baseAbs: string = root): HookFinding {
  const tokens = Array.from(new Set(finding.command.match(SCRIPT_TOKEN_RE) ?? [])).slice(0, 5);
  if (tokens.length === 0) return finding;
  const rootAbs = resolve(root);
  const baseResolved = resolve(baseAbs);
  let out = finding;
  for (const token of tokens) {
    const rel = token.replace(/^\.\//, "");
    if (rel.includes("://")) continue;
    let abs = resolve(baseResolved, rel);
    if ((abs !== rootAbs && !abs.startsWith(rootAbs + sep)) || !existsSync(abs)) {
      abs = resolve(rootAbs, rel);
    }
    if (abs !== rootAbs && !abs.startsWith(rootAbs + sep)) continue;
    if (!existsSync(abs)) continue;
    let st; try { st = statSync(abs); } catch { continue; }
    if (!st.isFile()) continue;
    let content = "";
    try { content = readFileSync(abs, "utf8").slice(0, 200000); } catch { continue; }
    const inner = classifyCommand(content, langForFile(token));
    if (inner.classification === "RISKY") {
      const rules = Array.from(new Set([...out.rules, ...inner.rules]));
      out = {
        ...out,
        classification: "RISKY",
        rules,
        evidence: `${out.evidence === "" ? "" : out.evidence + "; "}referenced local file ${rel} is RISKY: ${inner.evidence}`,
      };
      continue;
    }
    const hops = secondHopScripts(rootAbs, dirname(abs), content, abs);
    if (hops.length > 0) {
      const note = `referenced local file ${rel} spawns further local script(s) ${hops.join(", ")} beyond the one hop limit; the chain head cannot be verified past hop one`;
      out = {
        ...out,
        classification: out.classification === "SAFE" ? "UNKNOWN" : out.classification,
        evidence: `${out.evidence === "" ? "" : out.evidence + "; "}${note}; classification floored at UNKNOWN`,
      };
    }
  }
  return out;
}

/** Classify a command string, including one hop into local files it runs. */
function classifyWithLocalFile(root: string, source: HookSource, command: string, baseAbs: string = root): { classification: Classification; rules: string[]; evidence: string } {
  const c = classifyCommand(command);
  const temp: HookFinding = { id: "", file: "", source, hook: "", command, classification: c.classification, rules: c.rules, evidence: c.evidence };
  const escalated = escalateWithLocalFile(root, temp, baseAbs);
  return { classification: escalated.classification, rules: escalated.rules, evidence: escalated.evidence };
}

/**
 * A watched install script may chain to another package.json script
 * (`postinstall: npm run evil`). Follow that chain one hop: if the target
 * script is RISKY (directly or through a local file it runs), the install
 * hook inherits the classification.
 */
function escalateWithScriptChain(root: string, scripts: Record<string, unknown>, currentName: string, finding: HookFinding, baseAbs: string = root): HookFinding {
  const chainRe = /\b(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g;
  let out = finding;
  let m: RegExpExecArray | null;
  while ((m = chainRe.exec(finding.command)) !== null) {
    const name = m[1];
    if (name === currentName) continue;
    const chained = scripts[name];
    if (typeof chained !== "string" || !chained.trim()) continue;
    const inner = classifyWithLocalFile(root, "package.json", chained, baseAbs);
    if (inner.classification === "RISKY") {
      const rules = Array.from(new Set([...out.rules, ...inner.rules]));
      out = {
        ...out,
        classification: "RISKY",
        rules,
        evidence: `${out.evidence === "" ? "" : out.evidence + "; "}via script chain to "${name}": ${inner.evidence}`,
      };
    }
  }
  return out;
}

/**
 * Verdict calibration (Round 1, P-003 and P-004; Round 2, P-018).
 * COMPROMISED-PATTERN requires strong evidence inside a single finding:
 *   (a) a severe rule: fetched or decoded content executed directly as
 *       code (curl piped to an interpreter, base64 decode piped to an
 *       interpreter, eval of fetched content), or a verified exfil flow
 *       (ENV-EXFIL, CRED-EXFIL), or
 *   (b) credential STORE access (CRED-ACCESS: actual credential files
 *       and stores) combined with network behavior.
 * Round 2 narrowed path (b): in v0.1.2 and v0.1.3 any credential evidence
 * counted, including a credential shaped env NAME next to a URL. On real
 * estates that is the normal shape of a repo's own authenticated
 * automation (a release step reading its token and pushing to its own
 * repo), and it drove every one of the 15 false COMPROMISED drivers
 * hand-read in Round 2. Env references plus network behavior are RISKY
 * and verdict REVIEW; the verdict now needs the value to actually move
 * (path a) or an actual credential store to be touched (path b).
 * Weak signals alone (a remote URL, a localhost fetch, an ordinary env
 * read, a download by itself) classify RISKY at most, and a RISKY-only
 * estate verdicts REVIEW, never COMPROMISED-PATTERN.
 */
export function computeVerdict(findings: HookFinding[]): Verdict {
  let review = false;
  for (const f of findings) {
    if (f.classification === "RISKY") {
      const metas = f.rules.map(ruleMeta);
      const hasSevere = metas.some((x) => x.severe);
      const hasCredStore = f.rules.includes("CRED-ACCESS");
      const hasNet = metas.some((x) => x.remote);
      if (hasSevere || (hasCredStore && hasNet)) return "COMPROMISED-PATTERN";
      review = true;
    } else if (f.classification === "UNKNOWN") {
      review = true;
    }
  }
  return review ? "REVIEW" : "CLEAN";
}

function makeFinding(root: string, file: string, source: HookSource, hook: string, command: string, idSuffix?: string, line?: number, baseAbs: string = root): HookFinding {
  const c = classifyCommand(command);
  const id = `${file}:${hook}${idSuffix !== undefined ? `:${idSuffix}` : ""}`;
  const base: HookFinding = {
    id, file, source, hook, command,
    ...(line !== undefined ? { line } : {}),
    classification: c.classification, rules: c.rules,
    evidence: c.evidence,
  };
  return escalateWithLocalFile(root, base, baseAbs);
}

function readText(abs: string): string | null {
  try { return readFileSync(abs, "utf8"); } catch { return null; }
}

/**
 * Read a file the scanner has decided to inventory, warning loudly when
 * it cannot be read (P-049). A file that exists but cannot be read (the
 * classic case is mode 000) must never vanish silently: the warning
 * names the file, and scanHooks floors the verdict at REVIEW whenever
 * any warning carries the Unreadable prefix, so a partial scan never
 * presents as a complete all-clear.
 */
function readTextWarn(abs: string, rel: string, warnings: string[]): string | null {
  try { return readFileSync(abs, "utf8"); } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code ?? "error";
    warnings.push(`Unreadable file skipped: ${rel} could not be read (${code}); the scan is partial and this file was not inventoried`);
    return null;
  }
}

function readJson(root: string, rel: string, warnings: string[]): unknown | null {
  const raw = readTextWarn(join(root, rel), rel, warnings);
  if (raw === null) return null;
  // Strip a UTF-8 BOM first: Windows editors add one, JSON.parse rejects it,
  // and skipping the file would hide every hook inside it.
  // Strip simple JSONC comments and trailing commas for VS Code style files.
  const cleaned = raw
    .replace(/^\uFEFF/, "")
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/,\s*([}\]])/g, "$1");
  try { return JSON.parse(cleaned); } catch {
    warnings.push(`Malformed JSON in ${rel}: file skipped for structured parsing`);
    return null;
  }
}

function scanOnePackageJson(root: string, rel: string, findings: HookFinding[], warnings: string[]): void {
  if (!existsSync(join(root, rel))) return;
  const data = readJson(root, rel, warnings) as { scripts?: Record<string, unknown> } | null;
  if (!data) {
    // readJson already warned when the file exists but is malformed or
    // unreadable. If it parsed to a non object, note it as well.
    if (readText(join(root, rel)) !== null && !warnings.some((w) => w.includes(rel))) {
      warnings.push(`Could not parse ${rel} as an object`);
    }
    return;
  }
  if (typeof data !== "object" || Array.isArray(data)) {
    warnings.push(`${rel} root is not a JSON object: file skipped for structured parsing`);
    return;
  }
  if (data.scripts !== undefined && (typeof data.scripts !== "object" || data.scripts === null || Array.isArray(data.scripts))) {
    warnings.push(`scripts key in ${rel} is not an object: install hooks skipped`);
    return;
  }
  const scripts = (data.scripts ?? {}) as Record<string, unknown>;
  const watched = ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"];
  // Referenced local files resolve against this package's own directory:
  // a nested workspace package runs its scripts from its own folder.
  const baseAbs = dirname(join(root, rel));
  for (const name of watched) {
    const cmd = scripts[name];
    if (typeof cmd === "string" && cmd.trim()) {
      const finding = makeFinding(root, rel, "package.json", name, cmd, undefined, undefined, baseAbs);
      findings.push(escalateWithScriptChain(root, scripts, name, finding, baseAbs));
    }
  }
}

/**
 * Nested package.json discovery (P-032). Install scripts in workspace
 * subpackages (packages/foo, apps/web) run on a root install, so a
 * root-only scan misses exactly the surface a worm would persist in.
 * The walk is bounded so a hostile or giant tree cannot explode the
 * report: directories are visited in sorted order to depth
 * PACKAGE_MAX_DEPTH (the package.json directory depth below the root),
 * node_modules, .git, and dot directories are never entered, symlinked
 * directories are never followed (a symlink loop cannot hang the scan),
 * and at most PACKAGE_MAX_NESTED nested files are inventoried, with the
 * cap reported as a warning when it is hit.
 */
export const PACKAGE_MAX_DEPTH = 4;
export const PACKAGE_MAX_NESTED = 200;

function discoverNestedPackageJson(root: string, warnings: string[]): string[] {
  const found: string[] = [];
  const skipDirs = new Set(["node_modules", ".git"]);
  const stack: Array<{ abs: string; rel: string; depth: number }> = [{ abs: root, rel: "", depth: 0 }];
  while (stack.length > 0) {
    const cur = stack.pop() as { abs: string; rel: string; depth: number };
    let entries: string[] = [];
    try { entries = readdirSync(cur.abs); } catch {
      if (cur.rel) warnings.push(`Unreadable directory skipped: ${cur.rel} could not be listed; the scan is partial`);
      continue;
    }
    entries.sort();
    if (cur.depth >= 1 && entries.includes("package.json")) {
      found.push(cur.rel === "" ? "package.json" : `${cur.rel}/package.json`);
    }
    if (cur.depth >= PACKAGE_MAX_DEPTH) continue;
    // Push in reverse so the stack pops in sorted order.
    for (let i = entries.length - 1; i >= 0; i--) {
      const name = entries[i];
      if (skipDirs.has(name) || name.startsWith(".")) continue;
      const childAbs = join(cur.abs, name);
      let lst; try { lst = lstatSync(childAbs); } catch { continue; }
      if (lst.isSymbolicLink() || !lst.isDirectory()) continue;
      stack.push({ abs: childAbs, rel: cur.rel === "" ? name : `${cur.rel}/${name}`, depth: cur.depth + 1 });
    }
  }
  found.sort();
  if (found.length > PACKAGE_MAX_NESTED) {
    warnings.push(`Nested package.json inventory capped at ${PACKAGE_MAX_NESTED} files (${found.length} found); the remaining nested package.json files were not inventoried and the scan is partial`);
    return found.slice(0, PACKAGE_MAX_NESTED);
  }
  return found;
}

function scanPackageJson(root: string, findings: HookFinding[], warnings: string[]): void {
  scanOnePackageJson(root, "package.json", findings, warnings);
  for (const rel of discoverNestedPackageJson(root, warnings)) {
    scanOnePackageJson(root, rel, findings, warnings);
  }
}

function collectClaudeHooks(node: unknown, file: string, root: string, findings: HookFinding[], prefix: string): void {
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  if (typeof obj.command === "string" && obj.command.trim()) {
    findings.push(makeFinding(root, file, "claude-settings", prefix || "hook", obj.command, String(findings.length)));
    return;
  }
  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value)) {
      value.forEach((item, i) => collectClaudeHooks(item, file, root, findings, prefix ? `${prefix}:${key}` : key));
    } else if (value && typeof value === "object") {
      collectClaudeHooks(value, file, root, findings, prefix ? `${prefix}:${key}` : key);
    }
  }
}

/**
 * Claude settings locations (P-007). Beyond the standard .claude dir:
 * the GNU stow layout used by real dotfiles repos (claude/settings.json,
 * no dot), and a settings file nested one level under a config dir
 * (config/.claude/settings.json). A settings path that exists as a
 * directory is reported as a warning, never silently skipped.
 */
function claudeSettingsCandidates(root: string): string[] {
  const rels = [
    ".claude/settings.json", ".claude/settings.local.json",
    "claude/settings.json", "claude/settings.local.json",
  ];
  let entries: string[] = [];
  try { entries = readdirSync(root); } catch { entries = []; }
  for (const name of entries.sort()) {
    if (name === "node_modules" || name === ".git") continue;
    let st; try { st = statSync(join(root, name)); } catch { continue; }
    if (!st.isDirectory()) continue;
    for (const f of ["settings.json", "settings.local.json"]) {
      rels.push(`${name}/.claude/${f}`);
    }
  }
  return Array.from(new Set(rels));
}

function scanClaude(root: string, findings: HookFinding[], warnings: string[]): void {
  for (const rel of claudeSettingsCandidates(root)) {
    const abs = join(root, rel);
    if (!existsSync(abs)) continue;
    let st; try { st = statSync(abs); } catch { continue; }
    if (st.isDirectory()) {
      warnings.push(`${rel} is a directory, not a settings file: any hooks inside it cannot be parsed as Claude settings`);
      continue;
    }
    if (!st.isFile()) continue;
    const data = readJson(root, rel, warnings) as Record<string, unknown> | null;
    if (!data || typeof data !== "object") continue;
    if (!("hooks" in data)) { warnings.push(`No hooks key in ${rel}`); continue; }
    const hooks = data.hooks;
    if (!hooks || typeof hooks !== "object") {
      warnings.push(`hooks key in ${rel} is not an object: hooks skipped`);
      continue;
    }
    collectClaudeHooks(hooks, rel, root, findings, "");
  }
}

function scanVscode(root: string, findings: HookFinding[], warnings: string[]): void {
  const rel = ".vscode/tasks.json";
  if (existsSync(join(root, rel))) {
    const data = readJson(root, rel, warnings) as { tasks?: unknown } | null;
    if (data && data.tasks !== undefined && !Array.isArray(data.tasks)) {
      warnings.push(`tasks key in ${rel} is not an array: tasks skipped`);
    }
    const tasks = Array.isArray(data?.tasks) ? data.tasks : [];
    tasks.forEach((rawTask, idx) => {
      // Malformed entries (null, strings, numbers) are skipped, never fatal:
      // one bad task must not hide every other surface in the repo.
      if (!rawTask || typeof rawTask !== "object") return;
      const task = rawTask as Record<string, unknown>;
      const runOptions = (task.runOptions ?? {}) as Record<string, unknown>;
      const options = (task.options ?? {}) as Record<string, unknown>;
      const optionsRunOptions = (options.runOptions ?? {}) as Record<string, unknown>;
      // folderOpen lives in runOptions in the standard schema, but real
      // world files also nest it under options or put runOn on the task.
      const runOn = runOptions.runOn ?? optionsRunOptions.runOn ?? task.runOn;
      const isFolderOpen = runOn === "folderOpen" || (Array.isArray(runOn) && runOn.includes("folderOpen"));
      const command = typeof task.command === "string" ? task.command : "";
      const args = Array.isArray(task.args) ? task.args.filter((a) => typeof a === "string").join(" ") : "";
      const full = [command, args].filter(Boolean).join(" ").trim();
      if (!full) return;
      const label = typeof task.label === "string" ? task.label : `task-${idx}`;
      if (isFolderOpen) {
        findings.push(makeFinding(root, rel, "vscode-tasks", `folderOpen:${label}`, full, String(idx)));
      } else {
        // Inventory non auto-run tasks at lower weight: still record them so
        // explain can find them, classified by their command.
        const f = makeFinding(root, rel, "vscode-tasks", label, full, String(idx));
        findings.push(f);
      }
    });
  }
  // MCP config inside .vscode
  scanMcpFile(root, ".vscode/mcp.json", findings, warnings);
}

function scanDirFiles(root: string, dirRel: string, source: HookSource, findings: HookFinding[], warnings: string[]): void {
  const abs = join(root, dirRel);
  if (!existsSync(abs)) return;
  let entries: string[] = [];
  try { entries = readdirSync(abs); } catch {
    warnings.push(`Unreadable directory skipped: ${dirRel} could not be listed; the scan is partial`);
    return;
  }
  for (const name of entries.sort()) {
    const fileAbs = join(abs, name);
    let st; try { st = statSync(fileAbs); } catch { continue; }
    if (!st.isFile()) continue;
    if (name === "_" || name.startsWith(".")) continue;
    const content = readTextWarn(fileAbs, `${dirRel}/${name}`, warnings);
    if (content === null) continue;
    const firstMeaningful = content.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("set -")).join(" ");
    const fileRel = `${dirRel}/${name}`;
    // Entire file content is the command surface for husky style hooks.
    // Classify generously deep into the file: a payload hidden behind
    // padding must still be seen. Display code truncates separately.
    findings.push(makeFinding(root, fileRel, source, name, content.trim().slice(0, 200000)));
    void firstMeaningful;
  }
}

function scanLefthook(root: string, findings: HookFinding[], warnings: string[]): void {
  for (const rel of ["lefthook.yml", "lefthook.yaml", ".lefthook.yml"]) {
    if (!existsSync(join(root, rel))) continue;
    const raw = (readTextWarn(join(root, rel), rel, warnings) ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const runRe = /^\s*run:\s*(.+)$/gm;
    let m: RegExpExecArray | null; let i = 0;
    while ((m = runRe.exec(raw)) !== null) {
      findings.push(makeFinding(root, rel, "lefthook", "run", m[1].trim().replace(/^["']|["']$/g, ""), String(i++)));
    }
  }
}

function scanPreCommit(root: string, findings: HookFinding[], warnings: string[]): void {
  const rel = ".pre-commit-config.yaml";
  if (!existsSync(join(root, rel))) return;
  const raw = (readTextWarn(join(root, rel), rel, warnings) ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const entryRe = /^\s*entry:\s*(.+)$/gm;
  let m: RegExpExecArray | null; let i = 0;
  while ((m = entryRe.exec(raw)) !== null) {
    findings.push(makeFinding(root, rel, "pre-commit", "entry", m[1].trim().replace(/^["']|["']$/g, ""), String(i++)));
  }
  const repoRe = /^\s*-\s*repo:\s*(https?:\/\/\S+)$/gm;
  while ((m = repoRe.exec(raw)) !== null) {
    // A remote hook repo is the standard pre-commit pattern, not a finding
    // of compromise: the URL alone is inventoried as UNKNOWN so a human can
    // review the pinned rev. Classifying the bare URL with the command
    // rules would verdict every normal pre-commit config COMPROMISED.
    findings.push({
      id: `${rel}:remote-repo:${i++}`,
      file: rel,
      source: "pre-commit",
      hook: "remote-repo",
      command: m[1].trim(),
      classification: "UNKNOWN",
      rules: [],
      evidence: "remote pre-commit hook repo (standard pattern): its hooks run locally at commit time; hookcheck cannot verify remote contents, review the pinned rev",
    });
  }
}

function scanAgentDirs(root: string, findings: HookFinding[], warnings: string[]): void {
  for (const [dir, source] of [[".cursor", "cursor"], [".codex", "codex"]] as Array<[string, HookSource]>) {
    const abs = join(root, dir);
    if (!existsSync(abs)) continue;
    let entries: string[] = [];
    try { entries = readdirSync(abs); } catch { continue; }
    for (const name of entries.sort()) {
      const fileAbs = join(abs, name);
      let st; try { st = statSync(fileAbs); } catch { continue; }
      if (!st.isFile()) continue;
      const rel = `${dir}/${name}`;
      // mcp.json is an MCP config surface, inventoried exactly once by
      // the central scanMcpFile pass in scanHooks (P-035). Running it
      // through the generic command walk here as well counted every
      // .cursor/mcp.json server twice.
      if (name === "mcp.json") continue;
      if (name.endsWith(".json")) {
        const data = readJson(root, rel, warnings);
        if (data) collectGenericCommands(data, rel, root, findings, source);
      } else {
        const content = readTextWarn(fileAbs, rel, warnings);
        if (content && content.trim()) {
          findings.push(makeFinding(root, rel, source, name, content.trim().slice(0, 200000)));
        }
      }
    }
  }
}

function collectGenericCommands(node: unknown, file: string, root: string, findings: HookFinding[], source: HookSource, prefix = ""): void {
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  if (typeof obj.command === "string" && obj.command.trim()) {
    const args = Array.isArray(obj.args) ? obj.args.filter((a) => typeof a === "string").join(" ") : "";
    findings.push(makeFinding(root, file, source, prefix || "command", [obj.command, args].filter(Boolean).join(" "), String(findings.length)));
  }
  for (const [key, value] of Object.entries(obj)) {
    if (value && typeof value === "object") collectGenericCommands(value, file, root, findings, source, prefix ? `${prefix}:${key}` : key);
  }
}

function scanMcpFile(root: string, rel: string, findings: HookFinding[], warnings: string[]): void {
  if (!existsSync(join(root, rel))) return;
  const data = readJson(root, rel, warnings) as Record<string, unknown> | null;
  if (!data) return;
  const servers = (data.mcpServers ?? data.servers ?? {}) as Record<string, unknown>;
  if (!servers || typeof servers !== "object") return;
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== "object") continue;
    const c = cfg as Record<string, unknown>;
    const command = typeof c.command === "string" ? c.command : "";
    const args = Array.isArray(c.args) ? c.args.filter((a) => typeof a === "string").join(" ") : "";
    const full = [command, args].filter(Boolean).join(" ").trim();
    if (full) findings.push(makeFinding(root, rel, "mcp-config", `mcp:${name}`, full));
    if (typeof c.url === "string" && c.url) {
      findings.push(makeFinding(root, rel, "mcp-config", `mcp:${name}:url`, c.url));
    }
  }
}

/**
 * Workflow run steps (P-002). Both single line run values and block
 * scalars are inventoried. Block scalars (run: |, run: >, with the |-
 * and >- and |+ chomping variants) are the dominant style for real
 * multi-line steps; their bodies are collected by indentation, dedented,
 * and classified exactly like the same commands on one line. Every
 * finding carries the 1-based line number of its run: key.
 *
 * Line endings are normalized before parsing (P-048): CRLF is a
 * semantics preserving encoding for YAML and GitHub Actions, but the
 * line parser keyed on patterns that a trailing carriage return broke,
 * so a Windows authored workflow inventoried as total 0. A CRLF file
 * now produces exactly the findings of its LF twin.
 *
 * YAML anchors defined in the same file are resolved (P-033): a scalar
 * alias used as a run value (run: *name) resolves to the anchored
 * scalar, a step that is only an alias (- *name) resolves to the
 * anchored mapping's run value, and a merge key step (<<: *name) is
 * inventoried by its resolved content. The anchored definition itself
 * (an x- style key outside any step) is not double counted: it is
 * inventoried at each use site instead. An alias that cannot be
 * resolved is still inventoried, as the literal alias text at UNKNOWN,
 * so no executable step ever yields zero findings.
 */
function scanWorkflows(root: string, findings: HookFinding[], warnings: string[]): void {
  const dir = ".github/workflows";
  const abs = join(root, dir);
  if (!existsSync(abs)) return;
  let entries: string[] = [];
  try { entries = readdirSync(abs); } catch {
    warnings.push(`Unreadable directory skipped: ${dir} could not be listed; the scan is partial`);
    return;
  }
  for (const name of entries.sort()) {
    if (!/\.(yml|yaml)$/.test(name)) continue;
    const rel = `${dir}/${name}`;
    const rawFile = readTextWarn(join(root, rel), rel, warnings);
    if (rawFile === null) continue;
    const raw = rawFile.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const lines = raw.split("\n");
    const indentOf = (l: string): number => l.length - l.trimStart().length;
    const unquote = (s: string): string => {
      const t = s.trim();
      if (t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))) return t.slice(1, -1);
      return t;
    };

    // Anchor tables, filled by a first pass over the whole file so a
    // use site resolves regardless of definition order.
    const scalarAnchors = new Map<string, string>();
    const mapAnchors = new Map<string, string>();
    const definitionRunLines = new Set<number>();
    const resolveAlias = (value: string, depth = 0): string => {
      const t = value.trim();
      const am = t.match(/^\*([A-Za-z0-9_-]+)$/);
      if (am && depth < 5) {
        if (scalarAnchors.has(am[1])) return resolveAlias(scalarAnchors.get(am[1]) as string, depth + 1);
        if (mapAnchors.has(am[1])) return mapAnchors.get(am[1]) as string;
      }
      return unquote(t);
    };
    // Collect the dedented body of a block scalar whose header sits at
    // line hdrIdx with run indent runIndent. Returns body and end index.
    const collectBlock = (hdrIdx: number, runIndent: number): { body: string; end: number } => {
      const body: string[] = [];
      let j = hdrIdx + 1;
      for (; j < lines.length; j++) {
        const l = lines[j];
        if (l.trim() === "") { body.push(""); continue; }
        if (indentOf(l) <= runIndent) break;
        body.push(l);
      }
      const nonBlank = body.filter((l) => l.trim() !== "");
      if (nonBlank.length === 0) return { body: "", end: j };
      const minIndent = Math.min(...nonBlank.map((l) => l.length - l.trimStart().length));
      const dedented = body.map((l) => (l.trim() === "" ? "" : l.slice(minIndent))).join("\n").trim();
      return { body: dedented, end: j };
    };

    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      const scalarM = line.match(/^(\s*)(?:-\s*)?([A-Za-z0-9_-]+):\s*&([A-Za-z0-9_-]+)\s+(.+?)\s*$/);
      if (scalarM && scalarM[2] !== "run") {
        scalarAnchors.set(scalarM[3], unquote(scalarM[4]));
        continue;
      }
      const mapM = line.match(/^(\s*)(-\s*)?([A-Za-z0-9_-]+):\s*&([A-Za-z0-9_-]+)\s*(#.*)?$/);
      if (mapM) {
        const isListItem = mapM[2] !== undefined;
        const baseIndent = indentOf(line) + (isListItem ? 2 : 0);
        for (let j = idx + 1; j < lines.length; j++) {
          const l = lines[j];
          if (l.trim() === "") continue;
          if (indentOf(l) <= baseIndent) break;
          const rm = l.match(/^(\s*)-?\s*run:\s*(.*)$/);
          if (rm) {
            const rest = rm[2].trim();
            const bh = rest.match(/^([|>])([+-]?)\s*(#.*)?$/);
            const value = bh ? collectBlock(j, rm[1].length).body : resolveAlias(rest);
            if (value) mapAnchors.set(mapM[4], value);
            // A definition outside a step (an x- key) never runs on its
            // own; its run line is inventoried at the use sites, not
            // here. A list item anchor is a real step and stays live.
            if (!isListItem) definitionRunLines.add(j);
            break;
          }
        }
      }
    }

    let i = 0;
    for (let idx = 0; idx < lines.length; idx++) {
      if (definitionRunLines.has(idx)) continue;
      const line = lines[idx];
      const lineNo = idx + 1;
      const aliasStep = line.match(/^\s*-\s*\*([A-Za-z0-9_-]+)\s*(#.*)?$/);
      if (aliasStep) {
        const name = aliasStep[1];
        const resolved = scalarAnchors.has(name) || mapAnchors.has(name) ? resolveAlias(`*${name}`) : `*${name}`;
        findings.push(makeFinding(root, rel, "github-workflow", "run", resolved, String(i++), lineNo));
        continue;
      }
      const mergeKey = line.match(/^\s*<<:\s*\*([A-Za-z0-9_-]+)\s*(#.*)?$/);
      if (mergeKey) {
        const name = mergeKey[1];
        const resolved = scalarAnchors.has(name) || mapAnchors.has(name) ? resolveAlias(`*${name}`) : `*${name}`;
        findings.push(makeFinding(root, rel, "github-workflow", "run", resolved, String(i++), lineNo));
        continue;
      }
      const m = line.match(/^(\s*)-?\s*run:\s*(.*)$/);
      if (!m) continue;
      const runIndent = m[1].length;
      let rest = m[2].trim();
      const lineNoRun = idx + 1;
      // A run value that defines an anchor (run: &name cmd) is itself
      // executable; register the anchor and inventory the value.
      const anchorDef = rest.match(/^&([A-Za-z0-9_-]+)\s+(.+)$/);
      if (anchorDef) {
        scalarAnchors.set(anchorDef[1], unquote(anchorDef[2]));
        rest = anchorDef[2].trim();
      } else if (/^\*[A-Za-z0-9_-]+$/.test(rest)) {
        rest = resolveAlias(rest);
      }
      const blockHeader = rest.match(/^([|>])([+-]?)\s*(#.*)?$/);
      if (blockHeader) {
        const { body, end } = collectBlock(idx, runIndent);
        if (body) {
          findings.push(makeFinding(root, rel, "github-workflow", "run", body, String(i++), lineNoRun));
        }
        idx = end - 1;
        continue;
      }
      if (rest === "") continue;
      findings.push(makeFinding(root, rel, "github-workflow", "run", rest, String(i++), lineNoRun));
    }
  }
}

function scanGitHooks(root: string, findings: HookFinding[], warnings: string[]): void {
  scanDirFiles(root, ".githooks", "githooks", findings, warnings);
}

/**
 * Empty estate note (P-014, hookcheck half). A scan that inventories
 * nothing must say so next to the verdict, in JSON as well as in the
 * human output: CLEAN with total 0 is vacuously true and otherwise reads
 * as an all-clear.
 */
export const EMPTY_ESTATE_NOTE = "Nothing was found to audit: no auto-exec hooks were inventoried under this path, so the verdict covers an empty estate. This can mean a hook-free repo, an empty directory, or a path that is not a repo root.";

export function scanHooks(root: string): ScanReport {
  const findings: HookFinding[] = [];
  const warnings: string[] = [];
  let rootStat = null;
  try { rootStat = statSync(root); } catch { rootStat = null; }
  if (!rootStat) {
    warnings.push(`Path does not exist: ${root}`);
    return {
      path: root, verdict: "REVIEW", findings, warnings,
      counts: { total: 0, safe: 0, risky: 0, unknown: 0 },
      scannedAt: new Date().toISOString(),
      note: EMPTY_ESTATE_NOTE,
    };
  }
  if (!rootStat.isDirectory()) {
    warnings.push(`Path is not a directory: ${root}`);
    return {
      path: root, verdict: "REVIEW", findings, warnings,
      counts: { total: 0, safe: 0, risky: 0, unknown: 0 },
      scannedAt: new Date().toISOString(),
      note: EMPTY_ESTATE_NOTE,
    };
  }
  scanPackageJson(root, findings, warnings);
  scanClaude(root, findings, warnings);
  scanVscode(root, findings, warnings);
  scanDirFiles(root, ".husky", "husky", findings, warnings);
  scanLefthook(root, findings, warnings);
  scanPreCommit(root, findings, warnings);
  scanAgentDirs(root, findings, warnings);
  // MCP config surfaces, each inventoried exactly once (P-035).
  // .windsurf/mcp.json joined the covered surfaces in v0.1.6 (P-034);
  // .vscode/mcp.json is handled inside scanVscode.
  for (const rel of [".mcp.json", "mcp.json", ".cursor/mcp.json", ".windsurf/mcp.json", ".codex/mcp.json"]) scanMcpFile(root, rel, findings, warnings);
  scanWorkflows(root, findings, warnings);
  scanGitHooks(root, findings, warnings);

  // Dedupe identical ids (agent dir scan may double count mcp.json).
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.id}|${f.command}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });

  const counts = {
    total: deduped.length,
    safe: deduped.filter((f) => f.classification === "SAFE").length,
    risky: deduped.filter((f) => f.classification === "RISKY").length,
    unknown: deduped.filter((f) => f.classification === "UNKNOWN").length,
  };
  // Partial scan floor (P-049): when any inventoried file or directory
  // could not be read, the scan did not see the whole estate, so a bare
  // CLEAN is not an honest verdict. Floor at REVIEW; the warnings name
  // exactly what was missed.
  let verdict = computeVerdict(deduped);
  if (verdict === "CLEAN" && warnings.some((w) => w.startsWith("Unreadable"))) {
    verdict = "REVIEW";
  }
  return {
    path: root,
    verdict,
    findings: deduped,
    counts,
    warnings,
    scannedAt: new Date().toISOString(),
    ...(counts.total === 0 ? { note: EMPTY_ESTATE_NOTE } : {}),
  };
}

export function explainHook(root: string, idOrFile: string): { finding: HookFinding | null; explanation: string; report: ScanReport } {
  const report = scanHooks(root);
  const finding = report.findings.find((f) => f.id === idOrFile || f.file === idOrFile || f.id.startsWith(idOrFile)) ?? null;
  if (!finding) {
    return { finding: null, explanation: `No hook matched "${idOrFile}". ${report.findings.length} hook(s) found in this repo.`, report };
  }
  const parts = [
    `Hook ${finding.id} in ${finding.file} (${finding.source}, event ${finding.hook}).`,
    `Command: ${finding.command}`,
    `Classification: ${finding.classification}.`,
    `Evidence: ${finding.evidence || "none"}.`,
    finding.classification === "RISKY"
      ? "This hook runs automatically and matched risky patterns. Treat the repo as untrusted until this hook is removed or proven benign."
      : finding.classification === "SAFE"
        ? "This hook matches known safe dev tooling patterns and matched no risky rules."
        : "This hook matched neither safe nor risky patterns. Read the command and any file it invokes before trusting this repo.",
  ];
  return { finding, explanation: parts.join(" "), report };
}

export function renderReport(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`hookcheck ${report.path}: ${report.verdict}`);
  lines.push(`  ${report.counts.total} hook(s): ${report.counts.safe} SAFE, ${report.counts.risky} RISKY, ${report.counts.unknown} UNKNOWN`);
  if (report.note) lines.push(`  note: ${report.note}`);
  for (const f of report.findings) {
    lines.push(`  [${f.classification}] ${f.id} (${f.source}${f.line !== undefined ? `, line ${f.line}` : ""})`);
    lines.push(`      command: ${f.command.slice(0, 200)}`);
    if (f.rules.length) lines.push(`      rules: ${f.rules.join(", ")}`);
    lines.push(`      evidence: ${f.evidence}`);
  }
  for (const w of report.warnings) lines.push(`  [warn] ${w}`);
  if (report.verdict === "CLEAN") lines.push("CLEAN: no risky or unknown auto-exec hooks found.");
  else if (report.verdict === "REVIEW") lines.push("REVIEW: at least one hook needs manual review.");
  else lines.push("COMPROMISED-PATTERN: at least one risky hook shows strong evidence: fetched or decoded content executed as code, credential values flowing into an outbound send, or credential store access combined with network behavior. Treat as a Shai-Hulud style persistence pattern until proven otherwise.");
  return lines.join("\n");
}

export { relative };
export type { Classification, HookFinding, ScanReport, Verdict };
