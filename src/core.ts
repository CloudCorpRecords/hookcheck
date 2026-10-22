/**
 * hookcheck core: deterministic local scan for auto-exec hooks.
 *
 * No network, no LLM. Every classification comes from explicit pattern
 * rules so the same repo always produces the same report.
 */
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import type { Classification, HookFinding, HookSource, ScanReport, Verdict } from "./types.js";

export const VERSION = "0.1.16";

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
  // NET-FETCH (P-062): the curl and wget alternatives are NOT in this
  // pattern. A fetch binary counts only in command position (see
  // fetchPositions below): the token curl naming a package in an install
  // line (pacman -S curl, apt-get install curl) is a package name being
  // installed, not a command being run, and matching it anywhere in the
  // step manufactured a phantom fetch on evilmartians/lefthook.
  { id: "NET-FETCH", pattern: /\bfetch\s*\(|https?\s*\.get\s*\(|requests\.(get|post)\b|Invoke-WebRequest\b|Invoke-RestMethod\b/, evidence: "performs a network fetch", remote: true },
  { id: "REMOTE-URL", pattern: /https?:\/\/[^\s"'`]+/, evidence: "references a remote URL", remote: true },
  { id: "OBFUSCATION", pattern: /base64\s+(-d|--decode)|atob\s*\(|Buffer\.from\s*\([^)]*base64|\\x[0-9a-fA-F]{2}|\beval\b\s*\(|\beval\b\s+["'$(]|Function\s*\(/, evidence: "uses decoding or dynamic evaluation often used to hide payloads" },
  { id: "WRITE-OUTSIDE", pattern: /(>>?|tee)\s+~\/|(>>?|tee)\s+\$HOME\/|chmod\s+\+x/, evidence: "writes outside the repo or changes executable bits" },
  // DOWNLOAD-EXEC is detected procedurally (see detectDownloadExec):
  // inline code execution counts only when the evaluated content itself
  // carries a download or remote reference (P-064). A constant
  // node -e version comparison downloads nothing.
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
  return refOutsideRanges(seg, name, segStart, dataRanges);
}

/**
 * Positions (global indices) of genuine references to `name` inside
 * `seg`: occurrences that do not begin inside an excluded range, are
 * not a property name (obj.name reads a property of obj, never the
 * variable), and are not an object or dict KEY or a parameter
 * declaration (a name followed by ":" whose previous non-space
 * character is "{", ",", "(", or a line start is a binding or a key,
 * not a read). The key rule is the n8n set-latest shape (P-110): a
 * response variable named `body` tainted by a local helper call made
 * every fetch options object with a `body:` key read as a flow of
 * that variable into the send. A ternary value (cond ? name : other)
 * keeps counting: its previous character is "?", not a key context.
 */
function refPositions(seg: string, name: string, segStart: number, ranges: TextRange[]): number[] {
  const out: number[] = [];
  const re = new RegExp(`\\b${name.replace(/\$/g, "\\$")}\\b`, "g");
  for (const m of seg.matchAll(re)) {
    const idx = m.index ?? 0;
    if (inRanges(segStart + idx, ranges)) continue;
    if (idx > 0 && seg[idx - 1] === ".") continue;
    let j = idx + name.length;
    while (j < seg.length && (seg[j] === " " || seg[j] === "\t")) j++;
    if (seg[j] === ":") {
      let k = idx - 1;
      while (k >= 0 && (seg[k] === " " || seg[k] === "\t")) k--;
      if (k < 0 || seg[k] === "{" || seg[k] === "," || seg[k] === "(" || seg[k] === "\n") continue;
    }
    // An assignment target is a binding, not a read: a name at a
    // statement position followed by a single "=" (not "==" or
    // "=>") is being bound by this statement, so a send statement
    // that ASSIGNS its result from a command substitution carrying
    // an authenticated curl (id_token_status="$(curl ...)") does not
    // flow the variable anywhere by mentioning its own name.
    if (seg[j] === "=" && seg[j + 1] !== "=" && seg[j + 1] !== ">") {
      let k = idx - 1;
      while (k >= 0 && (seg[k] === " " || seg[k] === "\t")) k--;
      if (k < 0 || seg[k] === ";" || seg[k] === "\n" || seg[k] === "," || seg[k] === "{" || seg[k] === "(") continue;
      const prevWord = seg.slice(Math.max(0, k - 6), k + 1).match(/(?:^|\s)(?:let|const|var|export)$/);
      if (prevWord) continue;
    }
    out.push(segStart + idx);
  }
  return out;
}

function refOutsideRanges(seg: string, name: string, segStart: number, ranges: TextRange[]): boolean {
  return refPositions(seg, name, segStart, ranges).length > 0;
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
 * Command position for fetch binaries (P-062). The word curl inside a
 * step is not necessarily a fetch: in `pacman -S --noconfirm openssh
 * git curl` it is a package name in argument position, and counting it
 * as NET-FETCH manufactured an exfil verdict on evilmartians/lefthook
 * (the phantom fetch combined with a credential store write in the same
 * step). A fetch counts only when curl or wget is the invoked command:
 * the head of a statement or pipeline segment, after wrappers (sudo,
 * env, command, xargs, shell keywords) and environment assignments, or
 * the head of a command string literal (the string handed to
 * bash -c, execSync, os.system, and friends IS a command). Positions
 * are returned as indices of the fetch word in the input text.
 */
const FETCH_WRAPPERS = new Set(["sudo", "doas", "env", "command", "builtin", "exec", "time", "nice", "nohup", "xargs", "if", "then", "else", "elif", "while", "until", "do", "!"]);
const WRAPPER_ARG_FLAGS = new Set(["-u", "-I", "-n", "-L", "-P", "-s", "-E", "-e", "-C", "-S"]);

/** Head word of one pipeline segment, with the fetch word offset. */
function segmentHead(seg: string): { word: string; idx: number } | null {
  let i = 0;
  let lastWrapper = "";
  for (let iter = 0; iter < 16; iter++) {
    while (i < seg.length && /[\s'"`([{\\]/.test(seg[i])) i++;
    if ((seg[i] === "$" && seg[i + 1] === "{") || (seg[i] === "$" && seg[i + 1] === "(")) { i += 2; continue; }
    if (i >= seg.length) return null;
    const m = seg.slice(i).match(/^[^\s|;&]+/);
    if (!m) return null;
    const tok = m[0];
    if (tok.startsWith("-") && lastWrapper) {
      // A flag belonging to the wrapper (env -u NAME, xargs -n 1):
      // skip the flag and, for flags that take a value, its argument.
      i += tok.length;
      if (WRAPPER_ARG_FLAGS.has(tok)) {
        while (i < seg.length && /\s/.test(seg[i])) i++;
        const arg = seg.slice(i).match(/^[^\s|;&]+/);
        if (arg) i += arg[0].length;
      }
      continue;
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) { i += tok.length; lastWrapper = ""; continue; }
    const base = (tok.split("/").pop() ?? tok).replace(/['"`)\]]+$/, "");
    if (FETCH_WRAPPERS.has(base)) { lastWrapper = base; i += tok.length; continue; }
    const slash = tok.lastIndexOf("/");
    return { word: base, idx: i + (slash === -1 ? 0 : slash + 1) };
  }
  return null;
}

/** Quoted literal content ranges (simple scanner, escape aware). */
function quotedContentRanges(text: string): TextRange[] {
  const ranges: TextRange[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      let depth = 0;
      while (j < text.length) {
        if (text[j] === "\\") { j += 2; continue; }
        if (c === "`" && text[j] === "$" && text[j + 1] === "{") { depth++; j += 2; continue; }
        if (depth > 0 && text[j] === "}") { depth--; j++; continue; }
        if (text[j] === c && depth === 0) break;
        j++;
      }
      ranges.push({ start: i + 1, end: j });
      i = j + 1;
      continue;
    }
    i++;
  }
  return ranges;
}

/**
 * Indices of curl and wget words in command position in `text`.
 * Command string literals are searched recursively (depth 2): a literal
 * is a command string when code hands it to an interpreter, and the
 * views this runs on have already blanked data literals in script
 * files and echo arguments in shell text, so a quoted mention of the
 * word in data does not produce a position.
 */
function fetchPositions(text: string, depth = 0): Set<number> {
  const out = new Set<number>();
  for (const stmt of splitShell(text, ["\n", ";", "&&", "||"])) {
    const stmtText = text.slice(stmt.start, stmt.end);
    for (const seg of splitShell(stmtText, ["|"])) {
      const segText = stmtText.slice(seg.start, seg.end);
      const head = segmentHead(segText);
      if (head && (head.word === "curl" || head.word === "wget")) {
        out.add(stmt.start + seg.start + head.idx);
      }
    }
  }
  if (depth < 2) {
    for (const r of quotedContentRanges(text)) {
      const inner = text.slice(r.start, r.end);
      if (!/\b(?:curl|wget)\b/.test(inner)) continue;
      for (const p of fetchPositions(inner, depth + 1)) out.add(r.start + p);
    }
    // Interpreter -c and -e tails are command strings too, even when
    // the quotes are not visible in the text under analysis: an MCP
    // config's command and args are joined with spaces, so a server
    // configured as sh with args [-c, "curl ... | sh"] reaches the
    // classifier as the unquoted text `sh -c curl ... | sh`, whose
    // pipeline head is sh. The tail after the -c flag is the program.
    for (const m of text.matchAll(/\b(?:sh|bash|zsh|dash)\s+-c\s+|\b(?:node|bun|python3?|perl|ruby)\s+-(?:e|c)\s+/g)) {
      const start = m.index + m[0].length;
      const tail = text.slice(start);
      if (!/\b(?:curl|wget)\b/.test(tail)) continue;
      for (const p of fetchPositions(tail, depth + 1)) out.add(start + p);
    }
  }
  return out;
}

/**
 * True when a CURL-PIPE-SH match starts a real fetch and feeds an
 * interpreter that executes stdin. Matches run on the newline
 * preserving code text (the same text fetchPositions indexes), so
 * the pipe target's own line bounds its argument tail: the next
 * line of a block step is a new statement, never a target operand.
 */
function curlPipeIsCommandFetch(codeText: string, positions: Set<number>): boolean {
  if (positions.size === 0) return false;
  for (const m of codeText.matchAll(/\b(curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(sh|bash|zsh|node|python3?|perl|ruby)\b/g)) {
    const at = m.index + m[0].indexOf(m[1]);
    if (!positions.has(at)) continue;
    if (pipeTargetExecutesStdin(m[2], pipeTail(codeText, m.index + m[0].length))) return true;
  }
  return false;
}

/** True when any DECODE-PIPE-SH match feeds an interpreter that executes stdin. */
function decodePipeExecutesStdin(codeText: string): boolean {
  for (const m of codeText.matchAll(/\bbase64\s+(?:-d|--decode|-D)\b[^|]*\|\s*(?:sudo\s+)?(sh|bash|zsh|node|python3?|perl|ruby)\b/g)) {
    if (pipeTargetExecutesStdin(m[1], pipeTail(codeText, m.index + m[0].length))) return true;
  }
  return false;
}

/**
 * The text of the pipeline segment that follows a pipe target
 * interpreter word, cut at the next unquoted pipe, statement
 * separator, or redirection (quoted program text is kept whole).
 */
function pipeTail(text: string, from: number): string {
  let quote = "";
  for (let i = from; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === "\\" && quote === '"') { i++; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { quote = c; continue; }
    if (c === "|" || c === ";" || c === "&" || c === ">" || c === "<" || c === "\n") return text.slice(from, i);
  }
  return text.slice(from);
}

/** Quote aware spans of the whitespace separated tokens in `seg`. */
function shellTokenSpans(seg: string): Array<{ start: number; end: number; text: string }> {
  const out: Array<{ start: number; end: number; text: string }> = [];
  let i = 0;
  while (i < seg.length) {
    while (i < seg.length && /\s/.test(seg[i])) i++;
    if (i >= seg.length) break;
    const start = i;
    let quote = "";
    while (i < seg.length) {
      const c = seg[i];
      if (quote) {
        if (c === "\\" && quote === '"') { i += 2; continue; }
        if (c === quote) quote = "";
        i++;
        continue;
      }
      if (c === "'" || c === '"' || c === "`") { quote = c; i++; continue; }
      if (/\s/.test(c)) break;
      i++;
    }
    out.push({ start, end: i, text: seg.slice(start, i) });
  }
  return out;
}

function unquoteToken(t: string): string {
  if (t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))) return t.slice(1, -1);
  return t;
}

/**
 * True when an inline program handed to an interpreter (-e, -c)
 * itself executes what arrives on stdin: an exec or eval construct
 * combined with a stdin reference. A constant program that only
 * READS stdin as data (the MC-6 shape: JSON.parse of the piped
 * response) does not execute it.
 */
function programExecutesStdin(program: string): boolean {
  const execy = /\bexec\w*\s*\(|\beval\s*\(|\bFunction\s*\(|runInThisContext|runInNewContext|\bVM\b.*\brun\b/;
  const stdiny = /stdin|\/dev\/stdin|<&0|os\.read\(\s*0|read\(\s*0\s*[,)]/;
  return execy.test(program) && stdiny.test(program);
}

/**
 * Pipe target analysis (P-109d, completing the MC-6 calibration).
 * A pipe into an interpreter is download-then-execute only when the
 * interpreter reads its PROGRAM from stdin: a bare interpreter, a
 * lone dash, or an interpreter carrying only mode flags (-s, -x,
 * -u and friends). When the invocation supplies its program
 * another way, stdin is data the program parses, not code it runs:
 *   - a -c or -e inline program (unless that program itself
 *     executes stdin, which programExecutesStdin catches);
 *   - a -m module (python3 -m json.tool is the canonical data
 *     parser shape, the jq role with a different binary);
 *   - a script file operand (node script.js, bash setup.sh).
 * The OpenHands mock LLM health checks pipe a loopback curl
 * response into python3 -m json.tool; on 0.1.11 that match alone
 * carried CURL-PIPE-SH and the top verdict.
 */
function pipeTargetExecutesStdin(interp: string, tail: string): boolean {
  // The interpreter word can sit inside a quoted command string
  // handed to an interpreter (execSync('curl ... | sh')): the tail
  // then opens with the string's closing quote and call punctuation,
  // which is the end of the target invocation, not an operand.
  const tt = tail.trimStart();
  if (tt === "" || /^['"`)\];,}]/.test(tt)) return true;
  const toks = shellTokenSpans(tt);
  if (toks.length === 0) return true;
  const shell = interp === "sh" || interp === "bash" || interp === "zsh";
  for (let i = 0; i < toks.length; i++) {
    const t = unquoteToken(toks[i].text);
    if (t === "-") return true; // a lone dash: the program comes from stdin
    if (t === "--") return true; // only positional arguments follow; the program is still stdin
    if (t.startsWith("-") && t.length > 1) {
      const cluster = t.replace(/^-+/, "");
      const name = cluster.split("=")[0];
      const attached = cluster.includes("=") ? cluster.slice(cluster.indexOf("=") + 1) : cluster.length > name.length ? cluster.slice(name.length) : "";
      const programOf = (): string => {
        if (attached) return attached;
        const next = toks[i + 1];
        return next ? unquoteToken(next.text) : "";
      };
      if (shell) {
        // sh and bash take their program from -c; -o takes a value.
        if (/(^|[^a-zA-Z])c$/.test(name) || name === "c") return programExecutesStdin(programOf());
        if (name.endsWith("o")) { i++; continue; }
        continue;
      }
      if (interp === "node" || interp === "bun") {
        if (name === "e" || name === "eval" || name === "p" || name === "print") return programExecutesStdin(programOf());
        continue;
      }
      if (interp === "python" || interp === "python3") {
        if (name === "c") return programExecutesStdin(programOf());
        if (name === "m") return false; // a module is the program; stdin is its data
        if (name === "W" || name === "X") { i++; continue; }
        continue;
      }
      // perl and ruby take their program from -e.
      if (name === "e") return programExecutesStdin(programOf());
      continue;
    }
    // A bare operand is a script file: it is the program, stdin is data.
    return false;
  }
  return true;
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

const SEARCH_HEADS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack"]);
/** Short search flags whose next token is a value that is not the pattern (counts, context widths). */
const SEARCH_VALUE_FLAGS = new Set(["m", "A", "B", "C", "d", "D"]);

/**
 * Search pattern and search input ranges in shell text (P-108).
 * A search command (grep, egrep, fgrep, rg, ag, ack in command
 * position, the P-062 discipline) reads its pattern as DATA to
 * match against, and its file operands as data to search: neither
 * is behavior. github/docs lints its lockfile by grepping .npmrc
 * and package-lock.json for Microsoft feed URL patterns so it can
 * BLOCK them; on 0.1.11 the .npmrc operand fired CRED-ACCESS and a
 * URL inside a pattern could fire REMOTE-URL, and the pair fed
 * verdict path (b) to COMPROMISED-PATTERN. Content inside a search
 * pattern is pattern text, not behavior, for both halves of a
 * strong evidence combination, and a credential path string used
 * as a search target is a reference, not credential access.
 *
 * Ranges are per pipeline segment: the pattern operand (the first
 * bare token, or the value of -e, -f, --regexp, --file, or
 * --pattern) and the file operands after it. A token containing a
 * command substitution is left visible (its content can execute),
 * parsing stops at a redirection (its target is a write, judged on
 * its own text), and other statements in the same step are
 * untouched: a grep followed by a cat of a credential file, or by
 * a fetch of the grepped URL, still fires on those statements.
 */
function searchRanges(text: string): { pattern: TextRange[]; operands: TextRange[] } {
  const pattern: TextRange[] = [];
  const operands: TextRange[] = [];
  for (const stmt of splitShell(text, ["\n", ";", "&&", "||"])) {
    const stmtText = text.slice(stmt.start, stmt.end);
    for (const seg of splitShell(stmtText, ["|"])) {
      const segText = stmtText.slice(seg.start, seg.end);
      const head = segmentHead(segText);
      if (!head || !SEARCH_HEADS.has(head.word)) continue;
      const afterHead = head.idx + head.word.length;
      const base = stmt.start + seg.start + afterHead;
      const toks = shellTokenSpans(segText.slice(afterHead));
      let patternSeen = false;
      let expect: "pattern" | "other" | null = null;
      let afterDashDash = false;
      for (const tok of toks) {
        const g = { start: base + tok.start, end: base + tok.end };
        const dynamic = tok.text.includes("$(") || tok.text.includes("`");
        const t = unquoteToken(tok.text);
        if (expect === "pattern") {
          if (!dynamic) pattern.push(g);
          patternSeen = true;
          expect = null;
          continue;
        }
        if (expect === "other") { expect = null; continue; }
        if (!afterDashDash && t === "--") { afterDashDash = true; continue; }
        if (!afterDashDash && /^(?:\d+)?[<>]/.test(t)) break;
        if (!afterDashDash && t.startsWith("--")) {
          const eq = t.indexOf("=");
          const name = eq === -1 ? t : t.slice(0, eq);
          if (name === "--regexp" || name === "--file" || name === "--pattern") {
            if (eq !== -1) { if (!dynamic) pattern.push(g); patternSeen = true; } else expect = "pattern";
          } else if (["--max-count", "--after-context", "--before-context", "--context", "--directory", "--devices", "--exclude", "--include", "--type", "--glob", "--max-filesize"].includes(name)) {
            if (eq === -1) expect = "other";
          }
          continue;
        }
        if (!afterDashDash && t.startsWith("-") && t.length > 1) {
          const cluster = t.slice(1);
          const ei = cluster.search(/[ef]/);
          if (ei !== -1 && !patternSeen) {
            if (ei < cluster.length - 1) { if (!dynamic) pattern.push(g); patternSeen = true; } else expect = "pattern";
            continue;
          }
          if (SEARCH_VALUE_FLAGS.has(cluster[cluster.length - 1])) { expect = "other"; continue; }
          continue;
        }
        if (dynamic) {
          if (!patternSeen) patternSeen = true;
          continue;
        }
        if (!patternSeen) { pattern.push(g); patternSeen = true; } else operands.push(g);
      }
    }
  }
  return { pattern, operands };
}

interface Views {
  codeText: string;
  credText: string;
  dataRanges: TextRange[];
  /**
   * View the REMOTE-URL rule matches on (P-064). For script files this
   * is the code view with the contents of literals handed to network
   * calls spliced back: a URL passed to fetch, requests, http.get,
   * urlopen, axios, or sendBeacon is a fetch target (code position),
   * while a URL sitting in any other string literal (an error message,
   * a documentation constant, a docstring) is data and stays blanked.
   * For shell text, command arguments are code position, so the URL
   * view is the full text.
   */
  urlText: string;
}

const NETWORK_CALL_RES: RegExp[] = [
  /\bfetch\s*\(/g,
  /\baxios(?:\s*\.\s*\w+)?\s*\(/g,
  /\brequests\s*\.\s*\w+\s*\(/g,
  /\bhttpx\s*\.\s*\w+\s*\(/g,
  /\bhttps?\s*\.\s*(?:request|get)\s*\(/g,
  /\burlopen\s*\(/g,
  /\bsendBeacon\s*\(/g,
  /\bWebSocket\s*\(/g,
];

/**
 * Echo and printf output ranges for the credential view (P-108
 * follow-on, v0.1.13): the quoted output text with command
 * substitution interiors carved back out. A printed message that
 * NAMES a credential file (the github/docs lint error "Could not
 * scan .npmrc and package-lock.json for package feed URLs") is a
 * reference, not credential access, the same doctrine as a search
 * target and as a data literal in a script file, whose contents the
 * credential view already blanks. A substitution inside the message
 * ($(cat ~/.npmrc), or the backtick form) is code that runs when
 * the message prints, so its interior stays visible and still
 * fires. When the pipeline ends in a bare interpreter the echo
 * ranges are empty by construction (the printed text is the
 * program) and nothing is blanked here either.
 */
function echoCredRanges(text: string, echoRanges: TextRange[]): TextRange[] {
  const out: TextRange[] = [];
  for (const r of echoRanges) {
    let cur = r.start;
    let i = r.start;
    while (i < r.end) {
      const isSub = text[i] === "$" && text[i + 1] === "(";
      const isTick = text[i] === "`";
      if (!isSub && !isTick) { i++; continue; }
      let subEnd: number;
      if (isSub) {
        subEnd = consumeBalanced(text, i + 1);
      } else {
        let k = i + 1;
        while (k < r.end && text[k] !== "`") { if (text[k] === "\\") k++; k++; }
        subEnd = Math.min(k + 1, r.end);
      }
      if (i > cur) out.push({ start: cur, end: i });
      cur = Math.max(cur, Math.min(subEnd, r.end));
      i = cur;
    }
    if (r.end > cur) out.push({ start: cur, end: r.end });
  }
  return out;
}

function buildViews(text: string, lang: Lang): Views {
  if (lang === "shell") {
    const echoRanges = shellEchoDataRanges(text);
    // Search text is data (P-108): pattern contents are blanked in
    // the behavior and URL views, and pattern plus search input
    // operands are blanked in the credential view, so a defensive
    // grep supplies neither half of a strong evidence combination.
    // Output text is data for the credential view too (P-108
    // follow-on): echo and printf argument text is blanked there,
    // minus command substitution interiors, which are code.
    const search = searchRanges(text);
    const dataRanges = [...echoRanges, ...search.pattern];
    return {
      codeText: blankRanges(text, dataRanges),
      credText: blankRanges(text, [...search.pattern, ...search.operands, ...echoCredRanges(text, echoRanges)]),
      dataRanges,
      urlText: blankRanges(text, search.pattern),
    };
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
  const codeText = blankRanges(text, codeBlank);
  // URL view (P-064): restore literal contents handed to network calls.
  const netSpans: TextRange[] = [];
  for (const re of NETWORK_CALL_RES) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) netSpans.push(callSpan(text, m.index + m[0].length - 1));
  }
  const urlChars = codeText.split("");
  for (const lit of literals) {
    if (!netSpans.some((s) => lit.contentStart >= s.start && lit.contentEnd <= s.end)) continue;
    for (const r of contentRanges(lit)) {
      for (let i = r.start; i < r.end && i < urlChars.length; i++) urlChars[i] = text[i];
    }
  }
  return { codeText, credText: blankRanges(text, credBlank), dataRanges, urlText: urlChars.join("") };
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
function detectEnvAccess(cmd: string, dataRanges: TextRange[]): { cred: boolean; bulk: boolean; bulkInheritanceOnly: boolean } {
  let cred = false;
  let bulk = false;
  // Bulk form tracking (P-091): the evidence sentence must describe
  // the form that actually fired. A spread ({**os.environ, ...}), a
  // dict() or list() copy, or an os.environ.copy() handed on (the
  // environment inheritance idiom, typically as a subprocess env=) is
  // bulk access, but it is not a serialization or a dump, and the
  // v0.1.8 evidence called every bulk form one. bulkInheritanceOnly
  // is true when every bulk hit is an inheritance or copy form and no
  // serialization or dump form (JSON.stringify, printenv, a bare env
  // statement, str(os.environ)) fired.
  let bulkDump = false;
  let bulkCopy = false;
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
  if (/(JSON\.stringify|Object\.(keys|values|entries|assign)|util\.inspect)\s*\([^)]*(process\.env|os\.environ)/.test(cmd)) { bulk = true; bulkDump = true; }
  if (/\bprintenv\b/.test(cmd) && !inRanges(cmd.search(/\bprintenv\b/), dataRanges)) { bulk = true; bulkDump = true; }
  if (/(^|[;&|]\s*)env\s*($|[|>;])/m.test(cmd)) { bulk = true; bulkDump = true; }
  if (/\bstr\s*\(\s*os\.environ\s*\)/.test(cmd)) { bulk = true; bulkDump = true; }
  if (/\b(?:dict|list)\s*\(\s*os\.environ\s*\)/.test(cmd)) { bulk = true; bulkCopy = true; }
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
    if (/^\s*\.copy\s*\(/.test(after)) { bulk = true; bulkCopy = true; continue; } // whole copy is a bulk read
    const before = cmd.slice(Math.max(0, em.index - 24), em.index);
    if (/env\s*=\s*$/.test(before)) continue; // subprocess env inheritance
    bulk = true;
    // A spread occurrence ({**os.environ, ...}) is the inheritance
    // idiom in dict form; anything else here is an unqualified whole
    // environment use, counted with the dump forms for wording.
    if (/\*\*\s*$/.test(before)) bulkCopy = true; else bulkDump = true;
  }
  return { cred, bulk, bulkInheritanceOnly: bulk && bulkCopy && !bulkDump };
}

interface Atom extends TextRange {
  kind: "cred" | "bulk";
  inData: boolean;
  /**
   * True when this bulk atom sits inside an environment inheritance
   * expression (P-091): a spread ({**os.environ, ...} or
   * {...process.env}), dict(os.environ), os.environ.copy(), or a bare
   * os.environ / process.env value, where that expression is passed
   * as a subprocess env= (directly, or via a variable assigned from
   * it). Inheritance moves the environment into a child process the
   * code itself starts; it is not serialization into a payload.
   */
  pure?: boolean;
}

/**
 * Text ranges of environment inheritance expressions that are passed
 * as a subprocess environment (P-091). Two shapes count: a value used
 * directly as env= or env: (env={**os.environ, ...},
 * env=os.environ.copy()), and a variable assigned from an inheritance
 * expression that is itself passed as env= somewhere in the same
 * text (ENV = {**os.environ, ...}; subprocess.Popen(..., env=ENV)).
 * The same forms in any other position (a request body, a printed
 * value) are NOT inheritance ranges: dict(os.environ) handed to
 * requests.post as data is serialization into a payload and keeps
 * full exfil weight.
 */
function isInheritanceExpr(expr: string): boolean {
  const t = expr.trim();
  if (/^(?:os\.environ|process\.env)$/.test(t)) return true;
  if (/^(?:os\.environ|process\.env)\.copy\(\s*\)$/.test(t)) return true;
  if (/^dict\(\s*(?:os\.environ|process\.env)\s*\)$/.test(t)) return true;
  if (/^Object\.assign\(\s*\{\s*\}\s*,\s*(?:process\.env|os\.environ)\b/.test(t)) return true;
  if (t.startsWith("{") && (/\*\*\s*(?:os\.environ|process\.env)\b/.test(t) || /\.\.\.\s*(?:process\.env|os\.environ)\b/.test(t))) return true;
  return false;
}

function inheritanceRanges(text: string): TextRange[] {
  const ranges: TextRange[] = [];
  for (const m of text.matchAll(/\benv\s*[:=]\s*/g)) {
    const start = m.index + m[0].length;
    const end = consumeValueExpr(text, start);
    if (end > start && isInheritanceExpr(text.slice(start, end))) ranges.push({ start, end });
  }
  const assignRe = /(?:^|[;\n,])\s*(?:export\s+|const\s+|let\s+|var\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=(?![=<>])\s*/g;
  let m: RegExpExecArray | null;
  while ((m = assignRe.exec(text)) !== null) {
    const rhsStart = m.index + m[0].length;
    const end = consumeValueExpr(text, rhsStart);
    if (end <= rhsStart) continue;
    if (!isInheritanceExpr(text.slice(rhsStart, end))) continue;
    const name = m[1].replace(/\$/g, "\\$");
    let usedAsEnv = false;
    for (const em of text.matchAll(/\benv\s*[:=]\s*/g)) {
      if (envValueRegionMentions(text, em.index + em[0].length, name)) { usedAsEnv = true; break; }
    }
    if (usedAsEnv) ranges.push({ start: rhsStart, end });
  }
  return ranges;
}

/**
 * True when every network destination visible in the text is
 * loopback and at least one destination is visible at all (P-091).
 * Destinations are URL hosts plus netcat target hosts. An unknown
 * destination (a URL held in a variable) is not loopback-only: the
 * discount applies only when the flow's destinations are provably
 * all local, the same standard as the P-004 loopback downgrade.
 */
function loopbackOnlyDestinations(text: string, views: Views): boolean {
  // URL destinations come from the URL view (P-064): a URL inside a
  // data literal (a stand-in server's canned payload in a test
  // script, an error message) is not a destination of any send in
  // the flow, while a URL handed to a network call is restored into
  // the view and counts. In shell text the URL view is the full text.
  const hosts: string[] = [];
  for (const m of views.urlText.matchAll(/https?:\/\/([^\s"'`\/:?#]+)/g)) hosts.push(m[1]);
  for (const m of text.matchAll(/\b(?:nc|netcat)\s+(?:-\S+\s+)*([A-Za-z0-9._-]+)/g)) hosts.push(m[1]);
  if (hosts.length === 0) return false;
  return hosts.every((h) => isLoopbackHost(h));
}

/**
 * The value region of an env= or env: argument: the text from the
 * value start to the next top-level comma, closing bracket, or line
 * end (bounded). A variable counts as passed as the subprocess
 * environment when its name appears in that region, including inside
 * a fallback expression: the xod CLI test wrapper runs its subprocess
 * with env=env or ENV, where ENV is the inherited-environment dict
 * and env is the wrapper's own parameter.
 */
function envValueRegionMentions(text: string, from: number, name: string): boolean {
  let depth = 0;
  let quote = "";
  let end = from;
  const cap = Math.min(text.length, from + 200);
  while (end < cap) {
    const c = text[end];
    if (quote) {
      if (c === "\\") { end += 2; continue; }
      if (c === quote) quote = "";
      end++;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { quote = c; end++; continue; }
    if (c === "(" || c === "{" || c === "[") depth++;
    else if (c === ")" || c === "}" || c === "]") { if (depth === 0) break; depth--; }
    else if ((c === "," || c === "\n" || c === ";") && depth === 0) break;
    end++;
  }
  return new RegExp(`\\b${name}\\b`).test(text.slice(from, end));
}

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
/** Consume a balanced bracket span starting at the opener index. */
function consumeBalanced(text: string, openIdx: number): number {
  const open = text[openIdx];
  const close = open === "(" ? ")" : open === "{" ? "}" : open === "[" ? "]" : "";
  if (!close) return openIdx + 1;
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
    if (c === open) depth++;
    else if (c === close) { depth--; if (depth === 0) return j + 1; }
  }
  return text.length;
}

/** Consume one string literal starting at (or just before) index i. */
function consumeLiteral(text: string, i: number): number {
  let j = i;
  while (j < text.length && /[furbFURB]/.test(text[j])) j++;
  const q = text[j];
  if (q !== "'" && q !== '"' && q !== "`") return i;
  const triple = text.startsWith(q + q + q, j);
  const qLen = triple ? 3 : 1;
  let k = j + qLen;
  let depth = 0;
  while (k < text.length) {
    if (text[k] === "\\") { k += 2; continue; }
    if ((q === "`" && text[k] === "$" && text[k + 1] === "{") || (q !== "`" && depth >= 0 && text[k] === "{" && /[fF]/.test(text.slice(Math.max(0, j - 1), j + 1)))) { depth++; k += q === "`" ? 2 : 1; continue; }
    if (depth > 0 && text[k] === "}") { depth--; k++; continue; }
    if (depth > 0 && (text[k] === "'" || text[k] === '"' || text[k] === "`")) { k = consumeLiteral(text, k); continue; }
    if (triple ? text.startsWith(q + q + q, k) : text[k] === q) return k + qLen;
    if (!triple && text[k] === "\n" && q !== "`") return k;
    k++;
  }
  return k;
}

/**
 * Consume a value expression starting at `start`: a string literal
 * (including template and f-string forms), a bare variable or dotted
 * chain, a call, a bracketed value, or a +-concatenation of those.
 * Returns the end index. Capped so a malformed value cannot run away.
 */
function consumeValueExpr(text: string, start: number): number {
  let i = start;
  const cap = Math.min(text.length, start + 400);
  for (let part = 0; part < 6; part++) {
    while (i < cap && /\s/.test(text[i])) i++;
    if (i >= cap) break;
    const c = text[i];
    if (c === "'" || c === '"' || c === "`" || (/[furbFURB]/.test(c) && /["'`]/.test(text[i + 1] ?? ""))) {
      i = consumeLiteral(text, i);
    } else if (c === "(" || c === "{" || c === "[") {
      i = consumeBalanced(text, i);
    } else if (/[A-Za-z0-9_$]/.test(c)) {
      while (i < cap && /[A-Za-z0-9_$.]/.test(text[i])) i++;
      if (text[i] === "[") i = consumeBalanced(text, i);
      while (i < cap && /\s/.test(text[i])) i++;
      if (text[i] === "(") i = consumeBalanced(text, i);
      // A template literal directly after a chain (tag or suffix).
      while (i < cap && /\s/.test(text[i])) i++;
      if (text[i] === "`") i = consumeLiteral(text, i);
    } else {
      break;
    }
    let j = i;
    while (j < cap && /\s/.test(text[j])) j++;
    if (text[j] === "+") { i = j + 1; continue; }
    break;
  }
  return i;
}

const AUTH_HEADER_KEY = /^(authorization|proxy-authorization|auth|api[-_]?key|apikey|x-api-key|x-auth[-_]?token|auth[-_]?token|x-access[-_]?token|access[-_]?token|x-session[-_]?token|session[-_]?token)$/i;

function isAuthHeaderKey(key: string): boolean {
  const k = key.toLowerCase();
  return AUTH_HEADER_KEY.test(k) || k.endsWith("-api-key") || k.endsWith("-apikey") || k.endsWith("-auth-token") || k.endsWith("-access-token");
}

/**
 * Spans where a credential is used as authentication for the destination
 * it belongs to: the userinfo of a URL (x-access-token pushes and clones
 * to the repo's own host), the value of an Authorization header, and the
 * value of a CLI auth flag (--token, --auth, --api-key). A token in one
 * of these positions authenticates the send; it is not the payload, and
 * Round 2 showed it driving false exfil verdicts on langfuse, PostHog,
 * and cas release automation (P-018).
 *
 * Wave B (P-061): the v0.1.4 scrubbing recognized only the literal
 * Authorization spelling in shell text. Real estates also authenticate
 * with custom header names (statsig-api-key, x-api-key, any name at
 * all) and with headers dictionaries inside one hop Python and
 * TypeScript files, and those shapes still fired ENV-EXFIL on
 * anthropics/claude-code, hesreallyhim/awesome-claude-code, and
 * Aider-AI/aider. Authentication positions now also include:
 *   - any curl -H or --header argument, whatever the header name: the
 *     whole header value is an authentication position;
 *   - a dict or object entry whose key is an authentication header
 *     name (Authorization, *-api-key, *-auth-token, and friends),
 *     whatever the surrounding code;
 *   - any header-shaped entry (a header name key) inside a headers
 *     construction: a dict assigned to a variable named like headers,
 *     a headers= keyword argument, or a headers property of a fetch
 *     or request options object;
 *   - header setter calls (set, append, setHeader) and Python
 *     requests-style auth= tuples.
 * A credential that reaches a payload position (body, a data named
 * query parameter, a partial URL path segment, printed output next
 * to a send) still fires: only the value expressions of these
 * positions are scrubbed.
 *
 * Mega-corpus (P-106, P-107): the scrub now also covers curl -u and
 * --user basic auth pairs, the argument following a git
 * http.extraheader key, and ::add-mask:: registrations; and
 * destination positions inside the URL of a send (entire path
 * segments, the whole URL, the URL origin, authentication named
 * query parameters, the curl URL operand, and the destination first
 * argument of a fetch style call) are computed separately in
 * destAuthRanges, always subject to the body test.
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
  // curl -H and --header arguments: any header name is authentication.
  for (const m of text.matchAll(/(?:^|[\s;|&])(?:-H|--header)(?:\s+|=)/g)) {
    let i = m.index + m[0].length;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (i >= text.length) continue;
    if (text[i] === "'" || text[i] === '"' || text[i] === "`") {
      const end = consumeLiteral(text, i);
      ranges.push({ start: i + 1, end: Math.max(i + 1, end - 1) });
    } else {
      ranges.push(valueAfter(i));
    }
  }
  // curl -u and --user basic authentication pairs (P-107): the flag
  // value (user:password, usually a variable pair) is the credential
  // presented to the destination as authentication, in exactly the
  // position the protocol reserves for it. nodejs/node uploads its
  // own WPT report with -u "$USER:$PASSWORD" and n8n posts to its own
  // internal webhook with -u "name:$WEBHOOK_PASSWORD"; both fired
  // ENV-EXFIL on 0.1.10 because the scrubber knew --token style flags
  // but not the basic auth pair.
  const flagValue = (from: number): void => {
    let i = from;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (i >= text.length) return;
    if (text[i] === "'" || text[i] === '"' || text[i] === "`") {
      const end = consumeLiteral(text, i);
      ranges.push({ start: i + 1, end: Math.max(i + 1, end - 1) });
    } else {
      ranges.push(valueAfter(i));
    }
  };
  for (const m of text.matchAll(/(?:^|[\s;|&])(?:-u|--user|--http-user|--http-password)(?:\s+|=)/g)) {
    flagValue(m.index + m[0].length);
  }
  // git http.extraheader indirection (P-107): the value configured
  // for an extraheader key IS an Authorization header value, however
  // it was built (microsoft/TypeScript base64-encodes its app token
  // into a variable, registers it with add-mask, and configures it as
  // http.https://github.com/.extraheader "AUTHORIZATION: basic ...").
  // The argument following the extraheader key is scrubbed.
  for (const m of text.matchAll(/extraheader\b/gi)) {
    let i = m.index + m[0].length;
    while (i < text.length && /[\s"']/.test(text[i])) i++;
    if (text[i] === "=" || text[i] === ":") {
      i++;
      while (i < text.length && /[\s"']/.test(text[i])) i++;
    }
    if (i >= text.length) continue;
    if (text[i] === "'" || text[i] === '"' || text[i] === "`") {
      const end = consumeLiteral(text, i);
      ranges.push({ start: i + 1, end: Math.max(i + 1, end - 1) });
    } else {
      ranges.push(valueAfter(i));
    }
  }
  // add-mask registrations: an echo whose argument is the workflow
  // command ::add-mask::<value> registers the value for masking in
  // the log; printing it there is the masking idiom itself, not a
  // disclosure of the value as data.
  for (const m of text.matchAll(/::add-mask::/g)) {
    const start = m.index + m[0].length;
    let end = start;
    while (end < text.length && text[end] !== "\n" && text[end] !== '"' && text[end] !== "'") end++;
    if (end > start) ranges.push({ start, end });
  }
  // Header setter calls and requests-style auth= tuples.
  for (const m of text.matchAll(/\b(?:set|append|setHeader|addHeader|header)\s*\(\s*["'][A-Za-z0-9-]+["']\s*,\s*/g)) {
    const end = consumeValueExpr(text, m.index + m[0].length);
    if (end > m.index + m[0].length) ranges.push({ start: m.index + m[0].length, end });
  }
  for (const m of text.matchAll(/\bauth\s*=\s*\(/g)) {
    ranges.push({ start: m.index, end: consumeBalanced(text, m.index + m[0].length - 1) });
  }
  // Credential hand-off positions (P-111). A credential.helper
  // definition is the credential protocol of the tool performing the
  // send: git invokes the helper and reads username and password
  // lines from its stdout, so a token echoed inside a credential
  // helper is presented as authentication, exactly like a header or
  // a -u pair. The v0.1.11 auth model scrubbed headers, -u pairs,
  // extraheader, and URL userinfo, but saw the helper's echoed
  // password as print disclosure next to a send, which fired
  // ENV-EXFIL on All-Hands-AI/OpenHands (the Publish live E2E media
  // step, whose push token is used only inside such a helper). The
  // same protocol family covers core.askPass values, askpass
  // environment assignments, input piped or heredoc-fed into a
  // git credential invocation, and the body of a shell function a
  // credential.helper value names. Only the hand-off span itself is
  // scrubbed: the same token echoed to a log, or posted by a curl
  // statement elsewhere in the step, keeps full exfil weight.
  const configValueAfter = (from: number): TextRange | null => {
    let i = from;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text[i] === "=" || text[i] === ":") {
      i++;
      while (i < text.length && /\s/.test(text[i])) i++;
    }
    if (i >= text.length) return null;
    if (text[i] === "'" || text[i] === '"' || text[i] === "`") {
      const end = consumeLiteral(text, i);
      return end > i ? { start: i, end } : null;
    }
    let end = i;
    while (end < text.length && !/[\s;"']/.test(text[end])) end++;
    return end > i ? { start: i, end } : null;
  };
  const helperNames: string[] = [];
  for (const m of text.matchAll(/\bcredential\.helper\b/gi)) {
    const v = configValueAfter(m.index + m[0].length);
    if (!v) continue;
    ranges.push(v);
    const rawVal = text.slice(v.start, v.end).replace(/^['"`]/, "").replace(/^!/, "");
    const tok = rawVal.split(/\s+/)[0] ?? "";
    if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(tok)) helperNames.push(tok);
  }
  for (const m of text.matchAll(/\bcore\.askpass\b/gi)) {
    const v = configValueAfter(m.index + m[0].length);
    if (v) ranges.push(v);
  }
  for (const m of text.matchAll(/\b(?:GIT_ASKPASS|SSH_ASKPASS|SUDO_ASKPASS)\s*=\s*/g)) {
    const v = configValueAfter(m.index + m[0].length);
    if (v) ranges.push(v);
  }
  // A shell function a credential.helper value names by bare word:
  // its body is the helper program, so its echoed password lines are
  // protocol output. Builtin helper names (cache, store, manager)
  // simply have no definition in the text and match nothing.
  for (const name of helperNames) {
    const fnRe = new RegExp(`(?:^|[\\n;])\\s*(?:function\\s+)?${name}\\s*(?:\\(\\s*\\))?\\s*\\{`, "g");
    let fm: RegExpExecArray | null;
    while ((fm = fnRe.exec(text)) !== null) {
      const brace = fm.index + fm[0].length - 1;
      const end = consumeBalanced(text, brace);
      if (end > fm.index) ranges.push({ start: fm.index, end });
    }
  }
  // Input handed to a git credential invocation: every earlier
  // segment of a pipeline whose later segment runs git credential
  // is protocol input (protocol, host, username, password lines),
  // not a disclosure to a log.
  for (const stmt of splitShell(text, ["\n", ";", "&&", "||"])) {
    const stmtText = text.slice(stmt.start, stmt.end);
    const segs = splitShell(stmtText, ["|"]);
    if (segs.length < 2) continue;
    for (let k = 1; k < segs.length; k++) {
      const segText = stmtText.slice(segs[k].start, segs[k].end);
      if (!/^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:sudo\s+)?git\s+credential\b/.test(segText)) continue;
      for (let e = 0; e < k; e++) {
        ranges.push({ start: stmt.start + segs[e].start, end: stmt.start + segs[e].end });
      }
    }
  }
  // A heredoc feeding git credential is protocol input as well:
  // the body up to the delimiter line is read by git as credential
  // fields, never printed to a log.
  for (const m of text.matchAll(/\bgit\s+credential\b[^\n]*<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/g)) {
    const bodyStart = m.index + m[0].length;
    const rest = text.slice(bodyStart);
    const endMatch = rest.match(new RegExp(`\\n[ \\t]*${m[1]}\\b`));
    if (endMatch && (endMatch.index ?? 0) > 0) {
      ranges.push({ start: bodyStart, end: bodyStart + (endMatch.index ?? 0) });
    }
  }
  // Dict and object entries: authentication header keys anywhere, and
  // any header-shaped key inside a headers construction.
  const entryRe = /(?:^|[{,;\n])\s*(?:(["'])([A-Za-z][A-Za-z0-9_-]*)\1|([A-Za-z][A-Za-z0-9_-]*))\s*:\s*/g;
  let em: RegExpExecArray | null;
  while ((em = entryRe.exec(text)) !== null) {
    const key = em[2] ?? em[3] ?? "";
    if (!key) continue;
    const valueStart = em.index + em[0].length;
    let auth = isAuthHeaderKey(key);
    if (!auth) {
      // Headers construction context: the nearest opening brace before
      // this entry is introduced by a headers assignment, property, or
      // keyword argument.
      const brace = text.lastIndexOf("{", em.index);
      if (brace !== -1 && em.index - brace < 2000) {
        const before = text.slice(Math.max(0, brace - 90), brace);
        auth = /(?:^|[\s{,;])(?:[A-Za-z_$][A-Za-z0-9_$]*headers[A-Za-z0-9_$]*|headers)\s*[:=]\s*$/i.test(before)
          || /[A-Za-z_$][A-Za-z0-9_$]*[Hh]eaders[A-Za-z0-9_$]*\s*=\s*$/.test(before);
      }
    }
    if (!auth) continue;
    const end = consumeValueExpr(text, valueStart);
    if (end > valueStart) ranges.push({ start: valueStart, end });
  }
  return ranges;
}

/**
 * Variables assigned (transitively) from a credential value expression,
 * mapped to their inheritance purity (P-091): a variable is pure when
 * every taint source in its assignment chain is an inheritance atom
 * or another pure variable (ENV = {**os.environ, ...} is pure; a
 * payload built by serializing that same environment is not, because
 * the serializing atom in its own right-hand side is impure).
 * References inside authentication positions do not propagate taint
 * (P-061): a headers dict whose only credential use is its
 * Authorization value is an authentication container, not a tainted
 * payload, and passing it to fetch does not become exfil.
 */
interface LocalFn { name: string; bodyStart: number; bodyEnd: number }

/**
 * Functions defined in the same text (P-110). Python `def` bodies are
 * line ranges bounded by indentation; JavaScript `function` bodies
 * and arrow function bodies are the balanced brace span after the
 * signature. Only plain (non-method) definitions are collected.
 */
function localFunctions(text: string): LocalFn[] {
  const fns: LocalFn[] = [];
  const lines = text.split("\n");
  const lineStart: number[] = [];
  let off = 0;
  for (const l of lines) { lineStart.push(off); off += l.length + 1; }
  for (let li = 0; li < lines.length; li++) {
    const dm = lines[li].match(/^(\s*)def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
    if (!dm) continue;
    const indent = dm[1].length;
    let endLine = lines.length - 1;
    for (let lj = li + 1; lj < lines.length; lj++) {
      const l = lines[lj];
      if (l.trim() === "") continue;
      const ind = l.match(/^\s*/)?.[0].length ?? 0;
      if (ind <= indent) { endLine = lj - 1; break; }
    }
    fns.push({ name: dm[2], bodyStart: lineStart[li], bodyEnd: lineStart[endLine] + lines[endLine].length });
  }
  const jsRe = /\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(|(?:^|[;\n])\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>/g;
  let jm: RegExpExecArray | null;
  while ((jm = jsRe.exec(text)) !== null) {
    const name = jm[1] ?? jm[2];
    if (!name) continue;
    const brace = text.indexOf("{", jm.index + jm[0].length);
    if (brace === -1) continue;
    fns.push({ name, bodyStart: jm.index, bodyEnd: consumeBalanced(text, brace) });
  }
  return fns;
}

/**
 * True when a locally defined function returns tainted data: a return
 * expression inside its body that references a credential atom or a
 * tainted variable at a genuine reference position (outside data and
 * authentication ranges), or returns the result of another local
 * function that does (one level of recursion, depth capped).
 */
function fnReturnsTaint(fn: LocalFn, text: string, live: Atom[], tainted: Map<string, boolean>, dataRanges: TextRange[], auth: TextRange[], fns: LocalFn[], depth: number): boolean {
  const body = text.slice(fn.bodyStart, fn.bodyEnd);
  for (const m of body.matchAll(/\breturn\b/g)) {
    const exprStart = fn.bodyStart + (m.index ?? 0) + m[0].length;
    let exprEnd = text.indexOf("\n", exprStart);
    if (exprEnd === -1) exprEnd = fn.bodyEnd;
    const semi = text.indexOf(";", exprStart);
    if (semi !== -1 && semi < exprEnd) exprEnd = semi;
    exprEnd = Math.min(exprEnd, fn.bodyEnd);
    const expr = text.slice(exprStart, exprEnd);
    for (const x of live) {
      if (x.start >= exprStart && x.start < exprEnd) return true;
    }
    for (const [v] of tainted) {
      if (refOutsideRanges(expr, v, exprStart, [...dataRanges, ...auth])) return true;
    }
    if (depth < 2) {
      for (const cm of expr.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
        const inner = fns.find((f) => f.name === cm[1] && f !== fn);
        if (inner && fnReturnsTaint(inner, text, live, tainted, dataRanges, auth, fns, depth + 1)) return true;
      }
    }
  }
  return false;
}

/**
 * The innermost plain call whose argument list contains `pos`
 * within the assignment right-hand side, when that call is to a
 * function defined in the same text. Returns the function, or null
 * when the position is not inside a local call's arguments.
 */
function localCallAt(text: string, rhsStart: number, rhsEnd: number, pos: number, fns: LocalFn[]): LocalFn | null {
  const rhs = text.slice(rhsStart, rhsEnd);
  let best: { fn: LocalFn; open: number } | null = null;
  for (const m of rhs.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    const nameStart = rhsStart + (m.index ?? 0);
    if (nameStart > 0 && text[nameStart - 1] === ".") continue;
    const fn = fns.find((f) => f.name === m[1]);
    if (!fn) continue;
    const open = nameStart + m[0].length - 1;
    const span = callSpan(text, open);
    if (pos > open && pos < span.end && (!best || open > best.open)) best = { fn, open };
  }
  return best?.fn ?? null;
}

function taintedVars(text: string, atoms: Atom[], dataRanges: TextRange[], auth: TextRange[] = []): Map<string, boolean> {
  const tainted = new Map<string, boolean>();
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
  const fns = localFunctions(text);
  // Local helper taint (P-110). Passing a credential as an ARGUMENT
  // to a function defined in the same text does not taint that call's
  // result, unless the helper itself returns tainted data: the
  // helper's own body is part of the analyzed text, so a credential
  // it posts from inside is caught there directly, and a credential
  // it only presents as authentication (the davila7 and ticker
  // shapes: fetch_stargazers(token) and fetch_repos(token), whose
  // results are star dates and repo metadata) never becomes the
  // result's value. Calls to functions NOT defined in the text
  // (JSON.stringify, encodeURIComponent, library helpers) keep the
  // conservative rule: their result carries their arguments' taint.
  const consumedByLocalCall = (a: { rhsStart: number; rhsEnd: number }, pos: number): boolean => {
    if (fns.length === 0) return false;
    const fn = localCallAt(text, a.rhsStart, a.rhsEnd, pos, fns);
    if (!fn) return false;
    return !fnReturnsTaint(fn, text, live, tainted, dataRanges, auth, fns, 0);
  };
  for (let pass = 0; pass < 4; pass++) {
    for (const a of assigns) {
      if (tainted.has(a.name)) continue;
      const sources: boolean[] = [];
      // Destination positions inside the right-hand side do not
      // taint the RESULT of a call or command substitution either
      // (P-106): a variable assigned a send's result (a status code,
      // a response) does not carry the credential that was presented
      // in the send's URL. The skip applies only inside a call or
      // substitution span: a plain string or expression that
      // CONTAINS a destination atom (a capability URL built into a
      // variable) keeps its taint, because printing or posting that
      // variable would disclose the credential.
      const dest = destAuthRanges(text, { start: a.rhsStart, end: a.rhsEnd }, true)
        .filter((r) => {
          const rhs = text.slice(a.rhsStart, a.rhsEnd);
          for (const cm of rhs.matchAll(/\$\(|[A-Za-z_$][A-Za-z0-9_$]*\s*\(/g)) {
            const open = a.rhsStart + (cm.index ?? 0) + cm[0].length - 1;
            const span = callSpan(text, open);
            if (r.start >= span.start && r.start < span.end) return true;
          }
          return false;
        });
      for (const x of live) {
        if (x.start >= a.rhsStart && x.start < a.rhsEnd && !consumedByLocalCall(a, x.start) && !inRanges(x.start, dest)) sources.push(x.pure === true);
      }
      const rhs = text.slice(a.rhsStart, a.rhsEnd);
      for (const [v, vPure] of tainted) {
        const positions = refPositions(rhs, v, a.rhsStart, [...dataRanges, ...auth]);
        if (positions.some((p) => !consumedByLocalCall(a, p) && !inRanges(p, dest))) sources.push(vPure);
      }
      if (sources.length > 0) tainted.set(a.name, sources.every(Boolean));
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

/**
 * Taint inside one span, with inheritance purity (P-091): pure is
 * true only when every taint hit in the span is inheritance purity.
 * A span carrying even one impure hit (a credential shaped read, a
 * serialization of the whole environment) is an impure flow.
 */
function spanHasTaint(text: string, span: TextRange, atoms: Atom[], tainted: Map<string, boolean>, dataRanges: TextRange[], auth: TextRange[] = [], extra: TextRange[] = []): { found: boolean; pure: boolean } {
  let found = false;
  let pure = true;
  for (const a of atoms) {
    if (!a.inData && a.start >= span.start && a.start < span.end && !inRanges(a.start, extra)) {
      found = true;
      if (a.pure !== true) pure = false;
    }
  }
  if (tainted.size > 0) {
    const seg = text.slice(span.start, span.end);
    for (const [v, vPure] of tainted) {
      if (refOutsideRanges(seg, v, span.start, [...dataRanges, ...auth, ...extra])) {
        found = true;
        if (!vPure) pure = false;
      }
    }
  }
  return { found, pure };
}

/**
 * Body ranges inside one send span or statement: the values handed
 * to curl data flags (-d, --data*, -F, --form, --json) and to body,
 * data, json, or payload properties and keyword arguments. A
 * credential inside a body range is payload by construction; the
 * destination rules below never scrub inside a body range, which is
 * what makes the body test decisive (P-106): a capability URL shape
 * PLUS credential data in the body still fires.
 */
function bodyRanges(text: string, span: TextRange): TextRange[] {
  const ranges: TextRange[] = [];
  const seg = text.slice(span.start, span.end);
  for (const m of seg.matchAll(/(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode|-ascii)?|--form(?:-string)?|-F|--json)(?:\s+|=)/g)) {
    let i = span.start + (m.index ?? 0) + m[0].length;
    while (i < span.end && /\s/.test(text[i])) i++;
    if (i >= span.end) continue;
    if (text[i] === "'" || text[i] === '"' || text[i] === "`") {
      ranges.push({ start: i, end: Math.min(span.end, consumeLiteral(text, i)) });
    } else {
      let end = i;
      while (end < span.end && !/[\s,;]/.test(text[end])) end++;
      ranges.push({ start: i, end });
    }
  }
  for (const m of seg.matchAll(/\b(?:body|data|json|payload)\s*[:=]\s*/g)) {
    const start = span.start + (m.index ?? 0) + m[0].length;
    const end = consumeValueExpr(text, start);
    if (end > start) ranges.push({ start, end: Math.min(end, span.end) });
  }
  return ranges;
}

const AUTH_PARAM_NAME = /^(?:.*[-_])?(?:token|api[-_]?key|access[-_]?token|auth|secret|signature|sig|key|session[-_]?id)$/i;

/** True when a URL path segment is exactly one reference (a variable, an Actions expression, a template or f-string hole). */
function segmentRefRange(seg: string, segGlobalStart: number): TextRange | null {
  const t = seg.replace(/^["'`(]+/, "").replace(/["'`),;]+$/, "");
  const lead = seg.length - seg.replace(/^["'`(]+/, "").length;
  const base = segGlobalStart + lead;
  if (/^\$\{\{[^}]*\}\}$/.test(t) || /^\$\{[^}]*\}$/.test(t) || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(t) || /^\{[A-Za-z_][A-Za-z0-9_.]*\}$/.test(t)) {
    return { start: base, end: base + t.length };
  }
  return null;
}

/**
 * Destination authentication ranges inside one send span or
 * statement (P-106, P-107). A credential PRESENTED in the URL of a
 * send authenticates that send to the destination: capability URLs
 * are credentials by design (a Netlify build hook URL, a preview
 * token as a path segment, a token query parameter), and the URL a
 * configuration expression expands to is the destination itself.
 * Recognized presentations:
 *   - a reference that is an entire URL path segment;
 *   - the value of an authentication named query parameter (token,
 *     api_key, access_token, auth, secret, signature, key, and their
 *     prefixed forms); a data named parameter (?t=, ?q=, ?payload=)
 *     is NOT a presentation and keeps firing;
 *   - a reference at the start of a URL token, in the origin position
 *     (an expression or variable the rest of the URL is built on);
 *   - the whole URL token when it is exactly one reference;
 *   - in a curl or wget statement, a bare reference token in the URL
 *     operand position (not a flag value): the Actions OIDC request
 *     URL variable shape.
 * Nothing inside a body range is scrubbed here, and a reference in
 * any other URL position (a partial path segment, a data parameter)
 * is payload and keeps full exfil weight.
 */
function destAuthRanges(text: string, span: TextRange, isStatement: boolean): TextRange[] {
  const ranges: TextRange[] = [];
  const bodies = bodyRanges(text, span);
  const inBody = (r: TextRange): boolean => bodies.some((b) => r.start >= b.start && r.start < b.end);
  const seg = text.slice(span.start, span.end);
  const tokenRe = /[^\s]+/g;
  let tm: RegExpExecArray | null;
  while ((tm = tokenRe.exec(seg)) !== null) {
    const tokStart = span.start + (tm.index ?? 0);
    const tok = tm[0];
    const tokEnd = tokStart + tok.length;
    if (inBody({ start: tokStart, end: tokEnd })) continue;
    const schemeAt = tok.indexOf("://");
    if (schemeAt !== -1) {
      // Authority ends at the first path, query, or fragment char.
      let authEnd = tok.length;
      for (let i = schemeAt + 3; i < tok.length; i++) {
        if (tok[i] === "/" || tok[i] === "?" || tok[i] === "#") { authEnd = i; break; }
      }
      // Path segments that are exactly one reference.
      let p = authEnd;
      while (p < tok.length && tok[p] === "/") {
        let q = p + 1;
        while (q < tok.length && tok[q] !== "/" && tok[q] !== "?" && tok[q] !== "#") q++;
        const r = segmentRefRange(tok.slice(p + 1, q), tokStart + p + 1);
        if (r) ranges.push(r);
        p = q;
        if (tok[p] === "?" || tok[p] === "#") break;
      }
      // Authentication named query parameters.
      const qAt = tok.indexOf("?");
      if (qAt !== -1) {
        let qs = tok.slice(qAt + 1);
        const hash = qs.indexOf("#");
        if (hash !== -1) qs = qs.slice(0, hash);
        let off = qAt + 1;
        for (const part of qs.split("&")) {
          const eq = part.indexOf("=");
          if (eq > 0 && AUTH_PARAM_NAME.test(part.slice(0, eq))) {
            ranges.push({ start: tokStart + off + eq + 1, end: tokStart + off + part.length });
          }
          off += part.length + 1;
        }
      }
      continue;
    }
    // Expression or variable led token: the leading reference in the
    // origin position, or the whole token as one reference.
    const lead = tok.replace(/^["'`(]+/, "");
    const leadOff = tok.length - lead.length;
    const ref = lead.match(/^\$\{\{[^}]*\}\}|^\$\{[^}]*\}|^\$[A-Za-z_][A-Za-z0-9_]*/);
    if (ref) {
      const after = lead[ref[0].length] ?? "";
      if (after === "" || after === "/" || after === "?" || after === "#") {
        ranges.push({ start: tokStart + leadOff, end: tokStart + leadOff + ref[0].length });
      }
      continue;
    }
    // A bare reference token in a curl statement's operand position.
    if (isStatement) {
      const bare = tok.replace(/^["'`(]+/, "").replace(/["'`),;]+$/, "");
      if (/^\{[A-Za-z_][A-Za-z0-9_.]*\}$/.test(bare)) {
        ranges.push({ start: tokStart, end: tokEnd });
      }
    }
  }
  if (isStatement) {
    // Bare operand variables: tokenize with flag value awareness.
    const VALUE_FLAGS = new Set(["-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "-F", "--form", "--form-string", "-H", "--header", "-u", "--user", "-o", "--output", "-X", "--request", "-e", "--referer", "-A", "--user-agent", "-b", "--cookie", "-c", "--cookie-jar", "--cert", "--key", "--cacert", "--connect-timeout", "--max-time", "--retry", "--url", "-T", "--upload-file", "--json", "--oauth2-bearer", "-m", "-E"]);
    const toks = Array.from(seg.matchAll(/[^\s]+/g));
    let prevWasValueFlag = false;
    for (const t of toks) {
      const raw = t[0];
      const start = span.start + (t.index ?? 0);
      const clean = raw.replace(/^["'`(]+/, "").replace(/["'`),;]+$/, "");
      if (!prevWasValueFlag && /^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]*\}|\$\{\{[^}]*\}\})$/.test(clean) && !inBody({ start, end: start + raw.length })) {
        ranges.push({ start, end: start + raw.length });
      }
      if (raw.includes("=") && raw.startsWith("--")) prevWasValueFlag = false;
      else if (VALUE_FLAGS.has(raw)) prevWasValueFlag = true;
      else prevWasValueFlag = false;
    }
  }
  return ranges;
}

/** The first argument span of a call whose "(" is at openIdx. */
function firstArgSpan(text: string, openIdx: number): TextRange {
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
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") { depth--; if (depth === 0) return { start: openIdx + 1, end: j }; }
    else if (c === "," && depth === 1) return { start: openIdx + 1, end: j };
  }
  return { start: openIdx + 1, end: text.length };
}

/**
 * Aggregate ranges inside a printed argument (P-110): a length or
 * count of a value is metadata about the value, not the value (the
 * P-020 principle: ${#NAME} is a length, not a read). References
 * inside len(...), count(...), or size(...) calls, and the object of
 * a .length or .size property, do not count as print disclosure.
 */
function aggregateRanges(argText: string, argStart: number): TextRange[] {
  const ranges: TextRange[] = [];
  for (const m of argText.matchAll(/\b(?:len|count|size)\s*\(/g)) {
    const openLocal = (m.index ?? 0) + m[0].length - 1;
    const local = callSpan(argText, openLocal);
    ranges.push({ start: argStart + (m.index ?? 0), end: argStart + local.end });
  }
  for (const m of argText.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?:length|size)\b/g)) {
    ranges.push({ start: argStart + (m.index ?? 0), end: argStart + (m.index ?? 0) + m[1].length });
  }
  return ranges.filter((r) => r.end > r.start);
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
  const rawAtoms = findAtoms(text, dataRanges).filter((a) => !inRanges(a.start, auth));
  // Bound-clean shell variables (P-107, the n8n OIDC probe shape):
  // a $NAME occurrence is a credential atom by NAME, but when the
  // same text assigns that name from a value that contains no
  // credential atom at all, the name is bound to a known
  // non-credential value in this scope: ID_TOKEN_RESPONSE bound to
  // "$RUNNER_TEMP/npm-oidc-id-token.json" is a response FILE PATH
  // (used as a curl --output sink), not a token. A name bound from a
  // credential (TOKEN2="$API_TOKEN") keeps its atom, and a name never
  // assigned in the text (a runner or environment provided value)
  // keeps it too.
  const boundClean = new Set<string>();
  {
    const assignRe = /(?:^|[;\n,])\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=<>])\s*/g;
    let am: RegExpExecArray | null;
    while ((am = assignRe.exec(text)) !== null) {
      const rhsStart = am.index + am[0].length;
      let rhsEnd = rhsStart;
      while (rhsEnd < text.length && text[rhsEnd] !== ";" && text[rhsEnd] !== "\n") rhsEnd++;
      // Atoms of names already proven bound-clean (a literal path
      // variable used as an output sink) are not credential atoms
      // for this test either: cleanliness is transitive.
      const inRhs = rawAtoms.filter((x) => {
        if (x.start < rhsStart || x.start >= rhsEnd) return false;
        const nm = text.slice(x.start, x.end).match(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/);
        return !(nm && boundClean.has(nm[1]));
      });
      if (inRhs.length === 0) { boundClean.add(am[1]); continue; }
      // A name bound to the RESULT of a command substitution whose
      // only credential atoms sit in destination positions of the
      // substituted send is bound to that result (the OIDC probe's
      // id_token_status is an HTTP status code), not to the
      // credential presented in the URL. A name bound to a plain
      // string or expression that CONTAINS a destination atom (a
      // capability URL held in a variable) is not clean: printing
      // that variable would print the credential.
      const rhsText = text.slice(rhsStart, rhsEnd);
      if (rhsText.includes("$(")) {
        const dest = destAuthRanges(text, { start: rhsStart, end: rhsEnd }, true);
        if (inRhs.every((x) => inRanges(x.start, dest))) boundClean.add(am[1]);
      }
    }
  }
  const atoms = rawAtoms.filter((a) => {
    if (a.kind !== "cred") return true;
    const m = text.slice(a.start, a.end).match(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/);
    return !(m && boundClean.has(m[1]));
  });
  // Inheritance purity (P-091): a bulk atom inside an inheritance
  // expression passed as a subprocess env= is marked pure. Flows are
  // accumulated with their purity instead of returning at the first
  // hit: an impure flow fires ENV-EXFIL unconditionally (the v0.1.4
  // rule), while a flow whose taint is exclusively inheritance purity
  // fires only when the flow has a non-loopback destination. The
  // distilled failure was CloudCorpRecords/xod: a test script builds
  // ENV = {**os.environ, ...}, passes it as env= to the project's own
  // server and CLI, and every network call is loopback to the server
  // it just started; the inherited env tainted the subprocess result
  // variable, whose print next to the loopback urlopen read as exfil.
  const inhRanges = inheritanceRanges(text);
  for (const a of atoms) {
    if (a.kind === "bulk" && inRanges(a.start, inhRanges)) a.pure = true;
  }
  const tainted = taintedVars(text, atoms, dataRanges, auth);
  let sawPureFlow = false;
  let sawImpureFlow = false;
  const note = (r: { found: boolean; pure: boolean }): void => {
    if (!r.found) return;
    if (r.pure) sawPureFlow = true; else sawImpureFlow = true;
  };
  const has = (span: TextRange): void => note(spanHasTaint(text, span, atoms, tainted, dataRanges, auth));
  // Destination aware variant (P-106): taint that sits only in a
  // destination position (a capability URL presentation, the URL
  // operand, or the destination first argument of a fetch style
  // call) is authentication, not a flow into a send. Taint anywhere
  // else in the span - above all in a body range - fires as before.
  const hasDest = (span: TextRange, isStatement: boolean, firstArg: boolean): void => {
    const extra = destAuthRanges(text, span, isStatement);
    if (firstArg) {
      const open = text.indexOf("(", span.start);
      if (open !== -1 && open < span.end) {
        const fa = firstArgSpan(text, open);
        const faText = text.slice(fa.start, fa.end).trim();
        const bodies = bodyRanges(text, span);
        const faHasBody = bodies.some((b) => b.start >= fa.start && b.start < fa.end);
        if (!faText.startsWith("{") && !faHasBody) extra.push(fa);
      }
    }
    note(spanHasTaint(text, span, atoms, tainted, dataRanges, auth, extra));
  };

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
      const span = callSpan(text, m.index + m[0].length - 1);
      // XHR .send( takes the BODY as its argument, so it keeps the
      // plain rule; every other send call takes its destination
      // first, so its first argument is a destination position.
      if (re.source.includes("send")) has(span);
      else hasDest(span, false, true);
    }
  }

  // Fetch positions run on the code view with data blanked (indices
  // align with `text`: every view transform preserves length). A curl
  // word in argument position (P-062) opens no exfil path.
  const positionText = blankRanges(views.codeText, dataRanges);
  const positions = fetchPositions(positionText);
  const statements = splitShell(text, ["\n", ";", "&&", "||"]);
  for (const stmt of statements) {
    let isFetchStmt = false;
    for (const p of positions) { if (p >= stmt.start && p < stmt.end) { isFetchStmt = true; break; } }
    if (!isFetchStmt) continue;
    hasDest(stmt, true, false);
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
        has(early);
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
  const gateText = positionText;
  const hasSendConstruct = /\b(?:fetch|axios|requests\s*\.|urlopen|https?\s*\.\s*(?:request|get)|nc|netcat)\b/.test(gateText) || positions.size > 0;
  if (hasSendConstruct) {
    for (const m of text.matchAll(/(?:^|[;\n|&]\s*)(?:echo|printf)\s+([^\n;|]*)/g)) {
      const span: TextRange = { start: m.index, end: m.index + m[0].length };
      const argText = m[1] ?? "";
      const argStart = m.index + m[0].length - argText.length;
      const agg = aggregateRanges(argText, argStart);
      for (const a of atoms) {
        if (a.start >= span.start && a.start < span.end && !inRanges(a.start, agg)) note({ found: true, pure: a.pure === true });
      }
      for (const [v, vPure] of tainted) {
        // Shell echo arguments are the printed values themselves, so
        // a reference inside a quoted argument still counts; what
        // does not count is a reference inside an authentication or
        // masking position (the add-mask registration) or inside an
        // aggregate (a printed length or count).
        const ranges = lang === "shell" ? [...auth, ...agg] : [...dataRanges, ...auth, ...agg];
        if (refOutsideRanges(argText, v, argStart, ranges)) note({ found: true, pure: vPure });
      }
    }
    for (const m of text.matchAll(/\b(?:console\.(?:log|info|debug)|print)\s*\(([^)]*)\)/g)) {
      const span: TextRange = { start: m.index, end: m.index + m[0].length };
      const argText = m[1] ?? "";
      const argStart = m.index + m[0].indexOf(argText);
      const agg = aggregateRanges(argText, argStart);
      for (const a of atoms) {
        if (a.start >= span.start && a.start < span.end && (lang === "shell" || !a.inData) && !inRanges(a.start, agg)) note({ found: true, pure: a.pure === true });
      }
      for (const [v, vPure] of tainted) {
        const ranges = lang === "shell" ? [...auth, ...agg] : [...dataRanges, ...auth, ...agg];
        if (refOutsideRanges(argText, v, argStart, ranges)) note({ found: true, pure: vPure });
      }
    }
  }
  if (sawImpureFlow) return true;
  if (sawPureFlow) return !loopbackOnlyDestinations(text, views);
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

/**
 * DOWNLOAD-EXEC (P-064). Inline code execution (node -e, python -c,
 * deno eval, bun -e) is download-exec only when the evaluated content
 * itself carries a download or remote reference: a URL, a fetch or
 * request call, a network module. Constant inline code (a node -e
 * version comparison in modelcontextprotocol/servers, uv run python -c
 * file parsers in wshobson/agents) downloads nothing and is not
 * download-exec; labeling it RISKY was pure noise.
 */
function detectDownloadExec(codeText: string): boolean {
  const re = /\b(?:node|bun)\s+-(?:e|-eval)\b|\bdeno\s+eval\b|\bpython3?\s+-c\b/g;
  const netRef = /https?:\/\/|\bfetch\s*\(|\bcurl\b|\bwget\b|\brequests\b|urllib|urlopen|\baxios\b|https?\s*\.\s*(?:get|request)|XMLHttpRequest|\bnet\s*\.\s*connect|\bsocket\b/i;
  let m: RegExpExecArray | null;
  while ((m = re.exec(codeText)) !== null) {
    let i = m.index + m[0].length;
    while (i < codeText.length && /\s/.test(codeText[i])) i++;
    let content = "";
    if (codeText[i] === "'" || codeText[i] === '"' || codeText[i] === "`") {
      const end = consumeLiteral(codeText, i);
      content = codeText.slice(i, end);
    } else {
      let j = i;
      while (j < codeText.length && codeText[j] !== "\n" && codeText[j] !== ";" && codeText[j] !== "|") j++;
      content = codeText.slice(i, j);
    }
    if (netRef.test(content)) return true;
  }
  return false;
}

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
  const urlJoined = views.urlText.replace(/\n/g, " ");
  // Fetch positions are computed on the newline preserving code view:
  // newlines are statement separators, and flattening them first would
  // glue an install line and the curl command after it into one
  // statement whose head is the package manager. Indices align with
  // the joined views because joining only swaps newline for space.
  const positions = fetchPositions(views.codeText);
  const fired: Array<{ id: string; evidence: string }> = [];
  for (const rule of RISKY_RULES) {
    if (rule.id === "NET-FETCH") {
      // P-062: the pattern covers the non-curl fetch forms; curl and
      // wget count only in command position.
      if (rule.pattern.test(codeJoined) || positions.size > 0) fired.push({ id: rule.id, evidence: rule.evidence });
      continue;
    }
    if (rule.id === "CURL-PIPE-SH") {
      if (curlPipeIsCommandFetch(views.codeText, positions)) fired.push({ id: rule.id, evidence: rule.evidence });
      continue;
    }
    if (rule.id === "DECODE-PIPE-SH") {
      // Same pipe target analysis as CURL-PIPE-SH (P-109d): decoded
      // content piped into an interpreter that is given its program
      // is data for that program, not executed code.
      if (decodePipeExecutesStdin(views.codeText)) fired.push({ id: rule.id, evidence: rule.evidence });
      continue;
    }
    const hay = rule.id === "REMOTE-URL" ? urlJoined : codeJoined;
    if (rule.pattern.test(hay)) fired.push({ id: rule.id, evidence: rule.evidence });
  }
  if (detectDownloadExec(views.codeText)) {
    fired.push({ id: "DOWNLOAD-EXEC", evidence: "executes inline code that itself downloads or references remote content" });
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
    fired.push({
      id: "ENV-BULK",
      evidence: env.bulkInheritanceOnly
        ? "accesses the whole environment at once in inheritance or copy form (a spread, dict(), list(), or copy() of the whole environment handed on, for example as a subprocess environment); bulk access, not by itself a serialization or dump"
        : "accesses the whole environment at once (serialization, printenv, or env dump)",
    });
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
/**
 * Vendor installer pipe calibration (P-063, Wave B; composition
 * completed in P-109). A CI workflow step whose ONLY severe evidence
 * is a curl pipe to a named vendor's official installer over HTTPS
 * (the uv installer at astral.sh, the opencode installer) is the same
 * family as the esbuild and puppeteer download-own-binary installers
 * the v0.1.2 calibration already holds at REVIEW: the pattern match
 * is literal and the finding stays RISKY, but nothing about the step
 * exfils, persists, or touches a credential. The narrowing is
 * deliberately tight; ALL of these must hold:
 *   - the finding is a GitHub workflow run step (CI context). The same
 *     pipe on an auto-exec hook surface (package.json script, Claude
 *     settings or plugin hook, folderOpen task) keeps the top verdict:
 *     a hook runs on a developer machine at open or install time,
 *     which is exactly the Shai-Hulud persistence shape;
 *   - CURL-PIPE-SH is the only severe rule, and every rule present is
 *     part of the pipe shape itself or of the install's own footprint
 *     in the same step: CURL-PIPE-SH, NET-FETCH, and REMOTE-URL are
 *     the pipe; WRITE-OUTSIDE is the footprint (P-109c: the rollup
 *     nvm step that sources the profile it just installed and
 *     chmods the binary it just built; an installer writing under
 *     $HOME is its shape, not a second signal). Any credential rule
 *     (CRED-ACCESS, ENV-ACCESS, ENV-BULK, either exfil rule), any
 *     obfuscation, or a second severe signal disqualifies the
 *     finding on its own merits;
 *   - the piped URL is HTTPS and installer shaped or same-repo
 *     shaped (see installerUrlShape).
 * A curl pipe to an unversioned or non-vendor source (payload.sh on an
 * arbitrary host) never qualifies.
 *
 * Composition (P-109d): the calibration is a property of the single
 * finding, evaluated at the verdict layer per finding. A calibrated
 * pipe never drives the top verdict, and no other finding can
 * re-arm it; every other finding in the estate stands or falls on
 * its own merits (an unrelated ENV-EXFIL finding verdicts the repo
 * COMPROMISED-PATTERN by itself, a DOWNLOAD-EXEC only finding does
 * not, and neither outcome changes what the pipes contribute).
 */
const KNOWN_INSTALLER_HOSTS = new Set(["sh.rustup.rs", "get.docker.com", "install.python-poetry.org", "astral.sh", "opencode.ai", "pyenv.run"]);
/**
 * Installer endpoints are conventionally served from a dedicated
 * subdomain of the vendor domain whose first label names the
 * installer role: get.docker.com, install.python-poetry.org,
 * sh.rustup.rs, and (P-109a) get.maestro.mobile.dev, the Maestro
 * installer host that verdicts meteor/meteor on 0.1.11. pyenv.run
 * sits in the known list above instead: it is the documented pyenv
 * installer endpoint (the pyenv README install command is
 * `curl https://pyenv.run | bash`) with no subdomain to generalize.
 */
const INSTALLER_SUBDOMAINS = new Set(["get", "install", "installer", "setup", "sh"]);
const OWN_REPO_REF = /(?:\$\{\{\s*github\.repository\s*\}\}|\$\{\s*GITHUB_REPOSITORY\s*\}|\$GITHUB_REPOSITORY\b)/;
const OWN_SHA_REF = /(?:\$\{\{\s*github\.sha\s*\}\}|\$\{\s*GITHUB_SHA\s*\}|\$GITHUB_SHA\b)/;

/**
 * True when one piped URL is a calibrated download source:
 *   - installer shaped (P-063, generalized in P-109a): any path
 *     segment carries install, installer, or setup as a whole
 *     hyphen, underscore, or dot delimited token (install.sh,
 *     setup_lts.x, and astral's cargo-hawk-installer.sh, whose
 *     segment is not exactly an installer word), or the host is a
 *     documented installer host (the known list, or the installer
 *     subdomain convention). A segment that merely CONTAINS an
 *     installer word inside a larger token (uninstall.sh) is not an
 *     installer shape;
 *   - or the repo's own script at the immutable commit under test
 *     (P-109b): the URL is on github.com or
 *     raw.githubusercontent.com, names the repo through the
 *     repository variable or expression, and pins the ref through
 *     the SHA variable or expression (${GITHUB_SHA} or
 *     ${{ github.sha }}). nodejs/node pipes its own start-ci and
 *     release-proposal scripts this way; content at the commit
 *     already being tested adds no trust surface beyond the code
 *     already running. A literal other repo, or the same repo at a
 *     mutable ref, is not verified same-repo content and does not
 *     qualify.
 */
function installerUrlShape(url: string): boolean {
  const m = url.match(/^https:\/\/([^\s"'`/:?#]+)([^\s"'`]*)/i);
  if (!m) return false;
  const host = m[1].toLowerCase();
  const path = (m[2] ?? "").toLowerCase();
  if ((host === "github.com" || host === "raw.githubusercontent.com") && OWN_REPO_REF.test(url) && OWN_SHA_REF.test(url)) return true;
  for (const seg of path.split("/")) {
    if (!seg) continue;
    const tokens = seg.split(/[-_.]+/).filter(Boolean);
    if (tokens.some((t) => t === "install" || t === "installer" || t === "setup")) return true;
  }
  if (KNOWN_INSTALLER_HOSTS.has(host)) return true;
  return INSTALLER_SUBDOMAINS.has(host.split(".")[0]);
}

function isVendorInstallerPipeOnly(f: HookFinding): boolean {
  if (f.source !== "github-workflow") return false;
  if (!f.rules.includes("CURL-PIPE-SH")) return false;
  const allowed = new Set(["CURL-PIPE-SH", "NET-FETCH", "REMOTE-URL", "WRITE-OUTSIDE"]);
  if (!f.rules.every((r) => allowed.has(r))) return false;
  // The piped URL is the URL inside a curl pipe segment of the
  // command. When the pipe segment holds no literal URL (the URL is
  // in a variable assigned earlier in the step), fall back to the
  // URLs elsewhere in the command, as before P-109. Actions
  // expressions are whitespace collapsed first, the same
  // normalization classification applies, so a URL spelled with
  // ${{ github.repository }} and ${{ github.sha }} parses whole.
  const cmd = f.command.replace(/\$\{\{([\s\S]*?)\}\}/g, (_m, inner: string) => "${{" + inner.replace(/\s+/g, "") + "}}");
  const pipedUrls: string[] = [];
  for (const m of cmd.matchAll(/\b(?:curl|wget)\b[^|]*\|/g)) {
    pipedUrls.push(...(m[0].match(/https:\/\/[^\s"'`]+/gi) ?? []));
  }
  const candidates = pipedUrls.length > 0 ? pipedUrls : (cmd.match(/https:\/\/[^\s"'`]+/gi) ?? []);
  return candidates.some((u) => installerUrlShape(u));
}

export function computeVerdict(findings: HookFinding[]): Verdict {
  let review = false;
  for (const f of findings) {
    if (f.classification === "RISKY") {
      const metas = f.rules.map(ruleMeta);
      const hasSevere = metas.some((x) => x.severe);
      const hasCredStore = f.rules.includes("CRED-ACCESS");
      const hasNet = metas.some((x) => x.remote);
      // P-063 and P-109: the installer pipe calibration is per
      // finding. A calibrated pipe is strong pattern evidence but
      // not, on its own, a compromise pattern; it neither drives
      // the top verdict nor is re-armed by any other finding.
      const vendorPipeOnly = isVendorInstallerPipeOnly(f);
      if ((hasSevere && !vendorPipeOnly) || (hasCredStore && hasNet)) return "COMPROMISED-PATTERN";
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

/**
 * Stat-type guard (P-069). A file the scanner has decided to read is
 * checked by stat type BEFORE it is opened, and only regular files are
 * ever opened. Opening a FIFO (named pipe) blocks until a writer
 * appears, so a pipe planted at a surface path (.github/workflows/
 * pipe.yml, a package.json, an .mcp.json) hung the scan forever with
 * no internal timeout to catch it; sockets and device files are the
 * same hazard. injectcheck already stats before opening; every read
 * path in hookcheck now goes through readText or readTextWarn, which
 * enforce the check centrally, and the per surface scanners that stat
 * first (Claude settings, husky and githooks files, agent dirs, the
 * one hop follower) keep their own isFile checks as well.
 */
function statIsRegularFile(abs: string): boolean | null {
  try { return statSync(abs).isFile(); } catch { return null; }
}

function readText(abs: string): string | null {
  if (statIsRegularFile(abs) === false) return null;
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
  if (statIsRegularFile(abs) === false) {
    warnings.push(`Non-regular file skipped: ${rel} is not a regular file (FIFO, socket, or device); it was not opened or inventoried`);
    return null;
  }
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
 * Unified nested discovery (P-032, P-060, P-065). Every surface the
 * tool inventories at the scan root is also inventoried when it
 * appears inside a subdirectory: before v0.1.8 only nested package.json
 * files (P-032) and plugin hooks files (P-060) were recursed, so a
 * parent scan of a monorepo or workspace silently missed nested
 * .claude/settings.json, .vscode/tasks.json, workflows, husky and
 * githooks directories, lefthook and pre-commit configs, and MCP
 * configs, and a tree holding only nested surfaces scanned CLEAN with
 * the empty estate note attached (P-065).
 *
 * One bounded walk enumerates every project root (each directory at
 * most NESTED_MAX_DEPTH levels below the scan root, the scan root
 * itself included) plus the nested package.json and plugin hooks file
 * lists. Per surface scanners then run once per project root with the
 * root prefix carried into every finding file path, so findings carry
 * their real relative paths. The walk is bounded so a hostile or
 * giant tree cannot explode the report: directories are visited in
 * sorted order, node_modules, .git, and dot directories are never
 * entered, symlinked directories are never followed (a symlink loop
 * cannot hang the scan), and each surface family inventories at most
 * NESTED_MAX_FILES_PER_SURFACE nested files, with the cap reported as
 * a warning when it is hit. When directories remain below the depth
 * bound the walk says so in a warning naming the bound, and it probes
 * the directories just below the bound (names only, no file reads) so
 * surfaces sitting there are counted in the warning instead of being
 * silently dropped.
 *
 * The bound itself was raised from 4 to 8 in v0.1.9 (P-072): at depth
 * 4, realistic monorepo nesting (apps/<team>/<app>, packages grouped
 * by area, fixture trees) sat below the bound, so a package.json
 * dropper at depth 5 floored at REVIEW via the probe and a depth 8
 * chain verdicted CLEAN with only the warning. Depth 8 covers those
 * layouts; the walk cost stays linear in the number of directories
 * actually present, and the 2,000 file tree and 5 MB workflow perf
 * spot checks for v0.1.9 showed no material regression against
 * v0.1.8. Whatever bound remains keeps the warning and the
 * never-bare-CLEAN rule when the probe detects surface below it.
 */
export const NESTED_MAX_DEPTH = 8;
export const NESTED_MAX_FILES_PER_SURFACE = 200;
export const PACKAGE_MAX_DEPTH = NESTED_MAX_DEPTH;
export const PACKAGE_MAX_NESTED = NESTED_MAX_FILES_PER_SURFACE;
export const PLUGIN_HOOKS_MAX_DEPTH = NESTED_MAX_DEPTH;
export const PLUGIN_HOOKS_MAX_FILES = NESTED_MAX_FILES_PER_SURFACE;

const SURFACE_FILE_INDICATORS = new Set([
  "package.json", "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml",
  ".pre-commit-config.yaml", ".pre-commit-config.yml", ".mcp.json", "mcp.json",
]);
const SURFACE_DIR_INDICATORS = new Set([
  ".claude", "claude", ".vscode", ".github", ".husky", ".githooks",
  "hooks", ".cursor", ".windsurf", ".codex",
]);

export interface Discovery {
  /** Project root prefixes, scan root ("") first, then sorted. */
  projectRoots: string[];
  /** Nested package.json relative paths (scan root excluded), sorted, uncapped. */
  packageFiles: string[];
  /** Plugin hooks file relative paths, sorted, uncapped. */
  pluginHookFiles: string[];
  /** Directories just below the depth bound that were not entered. */
  frontierDirs: number;
  /** Frontier directories whose listing shows a hook surface file or config directory. */
  surfacesBelowBound: number;
  /** True when the depth bound left directories unentered. */
  depthBoundHit: boolean;
}

function discoverSurfaces(root: string, warnings: string[]): Discovery {
  const projectRoots: string[] = [];
  const packageFiles: string[] = [];
  const pluginSet = new Set<string>();
  let frontierDirs = 0;
  let surfacesBelowBound = 0;
  let probes = 0;
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
    projectRoots.push(cur.rel);
    if (cur.depth >= 1 && entries.includes("package.json")) {
      packageFiles.push(`${cur.rel}/package.json`);
    }
    // Plugin hooks files sit in a hooks directory one level below the
    // plugin root, so they are spotted from the plugin root listing
    // (the hooks directory itself can sit at depth bound plus one).
    if (entries.includes("hooks")) {
      const hooksAbs = join(cur.abs, "hooks");
      let lst = null;
      try { lst = lstatSync(hooksAbs); } catch { lst = null; }
      if (lst && lst.isDirectory() && !lst.isSymbolicLink()) {
        let hookEntries: string[] = [];
        try { hookEntries = readdirSync(hooksAbs); } catch { hookEntries = []; }
        for (const name of ["hooks.json", "hooks-cursor.json"]) {
          if (hookEntries.includes(name)) pluginSet.add(cur.rel === "" ? `hooks/${name}` : `${cur.rel}/hooks/${name}`);
        }
      }
    }
    const children: Array<{ abs: string; rel: string; depth: number }> = [];
    for (const name of entries) {
      if (skipDirs.has(name) || name.startsWith(".")) continue;
      const childAbs = join(cur.abs, name);
      const childRel = cur.rel === "" ? name : `${cur.rel}/${name}`;
      let lst; try { lst = lstatSync(childAbs); } catch { continue; }
      if (lst.isSymbolicLink()) {
        // No-follow policy (P-074): a symlinked directory is never
        // entered, but the skip is no longer silent. One warning per
        // skipped directory names the path and the reason, when the
        // link resolves to a directory (the container shape that can
        // hold hook surfaces) or when a surface-shaped name cannot
        // be resolved at all. A link to a regular file is not a
        // directory container and is judged by the surface scanners
        // at its own path, so it earns no warning here.
        let targetIsDir = false;
        let unresolved = false;
        try { targetIsDir = statSync(childAbs).isDirectory(); } catch { unresolved = true; }
        if (targetIsDir) {
          warnings.push(`Symlinked directory skipped: ${childRel} is a symbolic link to a directory; symlinked directories are not followed, so any hook surfaces inside it were not inventoried`);
        } else if (unresolved && SURFACE_DIR_INDICATORS.has(name)) {
          warnings.push(`Symlinked directory skipped: ${childRel} is a symbolic link that could not be resolved; it was not inventoried`);
        }
        continue;
      }
      if (!lst.isDirectory()) continue;
      children.push({ abs: childAbs, rel: childRel, depth: cur.depth + 1 });
    }
    if (cur.depth >= NESTED_MAX_DEPTH) {
      frontierDirs += children.length;
      for (const child of children) {
        if (probes >= 1000) break;
        probes++;
        let sub: string[] = [];
        try { sub = readdirSync(child.abs); } catch { continue; }
        if (sub.some((n) => SURFACE_FILE_INDICATORS.has(n) || SURFACE_DIR_INDICATORS.has(n))) surfacesBelowBound++;
      }
      continue;
    }
    // Push in reverse so the stack pops in sorted order.
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
  }
  projectRoots.sort((a, b) => (a === b ? 0 : a === "" ? -1 : b === "" ? 1 : a < b ? -1 : 1));
  packageFiles.sort();
  return {
    projectRoots,
    packageFiles,
    pluginHookFiles: Array.from(pluginSet).sort(),
    frontierDirs,
    surfacesBelowBound,
    depthBoundHit: frontierDirs > 0,
  };
}

/**
 * Shared per scan state for nested inventory: the discovery result,
 * the set of files already inventoried (a surface file is inventoried
 * exactly once however many discovery paths reach it, the P-035
 * lesson), per family nested counts for the file cap, and a partial
 * flag set whenever a cap or bound left part of the estate unscanned.
 */
interface ScanState {
  disc: Discovery;
  inventoried: Set<string>;
  familyFound: Map<string, number>;
  familyCapped: Map<string, number>;
  partial: boolean;
}

const FAMILY_LABELS: Record<string, string> = {
  settings: "Claude settings",
  tasks: "VS Code tasks",
  workflows: "workflow",
  husky: "husky hook",
  githooks: "githooks hook",
  lefthook: "lefthook config",
  "pre-commit": "pre-commit config",
  mcp: "MCP config",
  agent: "agent config",
};

/**
 * Claim one surface file for inventory. Returns false when the file
 * was already inventoried through another discovery path, or when the
 * nested file cap for its family is already spent (the skip is
 * counted, and scanHooks warns once per capped family).
 */
function claimFile(state: ScanState, family: string, rel: string, isNested: boolean): boolean {
  if (state.inventoried.has(rel)) return false;
  if (isNested) {
    const found = (state.familyFound.get(family) ?? 0) + 1;
    state.familyFound.set(family, found);
    if (found > NESTED_MAX_FILES_PER_SURFACE) {
      state.familyCapped.set(family, (state.familyCapped.get(family) ?? 0) + 1);
      state.partial = true;
      return false;
    }
  }
  state.inventoried.add(rel);
  return true;
}

function scanPackageJson(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  scanOnePackageJson(root, "package.json", findings, warnings);
  state.inventoried.add("package.json");
  let nested = state.disc.packageFiles;
  if (nested.length > PACKAGE_MAX_NESTED) {
    warnings.push(`Nested package.json inventory capped at ${PACKAGE_MAX_NESTED} files (${nested.length} found); the remaining nested package.json files were not inventoried and the scan is partial`);
    state.partial = true;
    nested = nested.slice(0, PACKAGE_MAX_NESTED);
  }
  for (const rel of nested) {
    state.inventoried.add(rel);
    scanOnePackageJson(root, rel, findings, warnings);
  }
}

function collectClaudeHooks(node: unknown, file: string, root: string, findings: HookFinding[], prefix: string, source: HookSource = "claude-settings", baseAbs: string = root): void {
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  if (typeof obj.command === "string" && obj.command.trim()) {
    findings.push(makeFinding(root, file, source, prefix || "hook", obj.command, String(findings.length), undefined, baseAbs));
    return;
  }
  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value)) {
      value.forEach((item, i) => collectClaudeHooks(item, file, root, findings, prefix ? `${prefix}:${key}` : key, source, baseAbs));
    } else if (value && typeof value === "object") {
      collectClaudeHooks(value, file, root, findings, prefix ? `${prefix}:${key}` : key, source, baseAbs);
    }
  }
}

/**
 * Claude settings locations (P-007). Beyond the standard .claude dir:
 * the GNU stow layout used by real dotfiles repos (claude/settings.json,
 * no dot), and a settings file nested one level under a config dir
 * (config/.claude/settings.json). A settings path that exists as a
 * directory is reported as a warning, never silently skipped. Since
 * v0.1.8 (P-065) the candidates are computed per project root, so the
 * same locations are inventoried in every subdirectory within the
 * discovery bound; the inventoried set in ScanState keeps a file
 * reachable by two paths (a parent root one level candidate and its
 * own project root) counted exactly once.
 */
function claudeSettingsCandidates(root: string, prefix: string): string[] {
  const base = prefix === "" ? "" : `${prefix}/`;
  const rels = [
    `${base}.claude/settings.json`, `${base}.claude/settings.local.json`,
    `${base}claude/settings.json`, `${base}claude/settings.local.json`,
  ];
  let entries: string[] = [];
  try { entries = readdirSync(join(root, prefix)); } catch { entries = []; }
  for (const name of entries.sort()) {
    if (name === "node_modules" || name === ".git") continue;
    let st; try { st = statSync(join(root, prefix, name)); } catch { continue; }
    if (!st.isDirectory()) continue;
    for (const f of ["settings.json", "settings.local.json"]) {
      rels.push(`${base}${name}/.claude/${f}`);
    }
  }
  return Array.from(new Set(rels));
}

function scanClaude(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  for (const prefix of state.disc.projectRoots) {
    const baseAbs = prefix === "" ? root : join(root, prefix);
    for (const rel of claudeSettingsCandidates(root, prefix)) {
      const abs = join(root, rel);
      // lstat first (P-074): a candidate that is absent is the normal
      // case and stays silent, but a candidate that EXISTS in some
      // form and cannot be examined (a symlink loop, a dangling
      // link, an unreadable parent directory) was skipped silently
      // before v0.1.15; it now warns by name, once per path.
      let lst; try { lst = lstatSync(abs); } catch { continue; }
      void lst;
      let st; try { st = statSync(abs); } catch (err) {
        if (!state.inventoried.has(rel)) {
          state.inventoried.add(rel);
          const code = (err as NodeJS.ErrnoException | undefined)?.code ?? "error";
          warnings.push(`Unreadable surface skipped: ${rel} could not be examined (${code}); it was not inventoried`);
        }
        continue;
      }
      if (st.isDirectory()) {
        if (!state.inventoried.has(rel)) {
          state.inventoried.add(rel);
          warnings.push(`${rel} is a directory, not a settings file: any hooks inside it cannot be parsed as Claude settings`);
        }
        continue;
      }
      if (!st.isFile()) {
        if (!state.inventoried.has(rel)) {
          state.inventoried.add(rel);
          warnings.push(`Non-regular surface skipped: ${rel} is not a regular file; it was not inventoried`);
        }
        continue;
      }
      if (!claimFile(state, "settings", rel, prefix !== "")) continue;
      const data = readJson(root, rel, warnings) as Record<string, unknown> | null;
      if (!data || typeof data !== "object") continue;
      if (!("hooks" in data)) { warnings.push(`No hooks key in ${rel}`); continue; }
      const hooks = data.hooks;
      if (!hooks || typeof hooks !== "object") {
        warnings.push(`hooks key in ${rel} is not an object: hooks skipped`);
        continue;
      }
      collectClaudeHooks(hooks, rel, root, findings, "", "claude-settings", baseAbs);
    }
  }
}

/**
 * Claude Code plugin hook files (P-060, BLOCKER). Plugins distribute
 * hooks in a hooks/ directory at the plugin root: hooks/hooks.json at
 * the repo root for a single plugin repo (obra/superpowers), or
 * plugins/<name>/hooks/hooks.json inside a marketplace or monorepo
 * (anthropics/claude-code carries 9 such files, wshobson/agents 2 among
 * 92 plugin directories). Before v0.1.7 none of these files was scanned
 * at any depth: a SessionStart curl pipe in hooks/hooks.json scanned
 * CLEAN with total 0 while the identical payload in .claude/settings.json
 * verdicts COMPROMISED-PATTERN. The file carries the same schema as the
 * hooks key of .claude/settings.json (an events map of command hooks:
 * SessionStart, PreToolUse, PostToolUse, Stop, UserPromptSubmit, and
 * the rest of the Claude Code event set), so commands are classified
 * exactly as settings hooks are. The sibling hooks/hooks-cursor.json
 * variant shipped by the same plugins (superpowers) carries the same
 * command object shape under Cursor event names, so it is inventoried
 * the same way.
 *
 * Discovery is part of the unified bounded walk (P-065): the file
 * list comes from discoverSurfaces, with the plugin root at most
 * PLUGIN_HOOKS_MAX_DEPTH directories below the scan root (the hooks
 * directory itself sits one level below its plugin root), and the
 * same cap with a warning applies.
 */
function scanPluginHooks(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  let files = state.disc.pluginHookFiles;
  if (files.length > PLUGIN_HOOKS_MAX_FILES) {
    warnings.push(`Plugin hooks inventory capped at ${PLUGIN_HOOKS_MAX_FILES} files (${files.length} found); the remaining plugin hook files were not inventoried and the scan is partial`);
    state.partial = true;
    files = files.slice(0, PLUGIN_HOOKS_MAX_FILES);
  }
  for (const rel of files) {
    state.inventoried.add(rel);
    const data = readJson(root, rel, warnings) as Record<string, unknown> | null;
    if (!data || typeof data !== "object" || Array.isArray(data)) continue;
    // The events map lives under the hooks key when one is present;
    // some plugin files put the events map at the top level.
    const eventsNode = ("hooks" in data && data.hooks && typeof data.hooks === "object" && !Array.isArray(data.hooks))
      ? data.hooks
      : data;
    // Referenced local files resolve against the plugin root (the
    // directory holding the hooks folder), which is where
    // ${CLAUDE_PLUGIN_ROOT} points at runtime.
    const pluginRootAbs = dirname(dirname(join(root, rel)));
    collectClaudeHooks(eventsNode, rel, root, findings, "", "claude-plugin", pluginRootAbs);
  }
}

function scanVscode(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  for (const prefix of state.disc.projectRoots) {
    const base = prefix === "" ? "" : `${prefix}/`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    const rel = `${base}.vscode/tasks.json`;
    if (existsSync(join(root, rel)) && claimFile(state, "tasks", rel, prefix !== "")) {
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
        findings.push(makeFinding(root, rel, "vscode-tasks", isFolderOpen ? `folderOpen:${label}` : label, full, String(idx), undefined, baseAbs));
      });
    }
    // MCP config inside .vscode
    scanMcpFile(root, `${base}.vscode/mcp.json`, findings, warnings, state, baseAbs, prefix !== "");
  }
}

function scanDirFiles(root: string, dirName: string, source: HookSource, family: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  for (const prefix of state.disc.projectRoots) {
    const dirRel = prefix === "" ? dirName : `${prefix}/${dirName}`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    const abs = join(root, dirRel);
    if (!existsSync(abs)) continue;
    let entries: string[] = [];
    try { entries = readdirSync(abs); } catch {
      warnings.push(`Unreadable directory skipped: ${dirRel} could not be listed; the scan is partial`);
      continue;
    }
    for (const name of entries.sort()) {
      const fileAbs = join(abs, name);
      const fileRel = `${dirRel}/${name}`;
      // An entry the directory listing proved exists but stat cannot
      // examine (a dangling symlink, a symlink loop) was skipped
      // silently before v0.1.15 (P-074); it now warns by name.
      let st; try { st = statSync(fileAbs); } catch (err) {
        const code = (err as NodeJS.ErrnoException | undefined)?.code ?? "error";
        warnings.push(`Unreadable surface skipped: ${fileRel} could not be examined (${code}); it was not inventoried`);
        continue;
      }
      if (!st.isFile()) continue;
      if (name === "_" || name.startsWith(".")) continue;
      if (!claimFile(state, family, fileRel, prefix !== "")) continue;
      const content = readTextWarn(fileAbs, fileRel, warnings);
      if (content === null) continue;
      // Entire file content is the command surface for husky style hooks.
      // Classify generously deep into the file: a payload hidden behind
      // padding must still be seen. Display code truncates separately.
      findings.push(makeFinding(root, fileRel, source, name, content.trim().slice(0, 200000), undefined, undefined, baseAbs));
    }
  }
}

function scanLefthook(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  for (const prefix of state.disc.projectRoots) {
    const base = prefix === "" ? "" : `${prefix}/`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    for (const name of ["lefthook.yml", "lefthook.yaml", ".lefthook.yml"]) {
      const rel = `${base}${name}`;
      if (!existsSync(join(root, rel))) continue;
      if (!claimFile(state, "lefthook", rel, prefix !== "")) continue;
      const raw = (readTextWarn(join(root, rel), rel, warnings) ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      const runRe = /^\s*run:\s*(.+)$/gm;
      let m: RegExpExecArray | null; let i = 0;
      while ((m = runRe.exec(raw)) !== null) {
        findings.push(makeFinding(root, rel, "lefthook", "run", m[1].trim().replace(/^["']|["']$/g, ""), String(i++), undefined, baseAbs));
      }
    }
  }
}

function scanPreCommit(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  for (const prefix of state.disc.projectRoots) {
    const base = prefix === "" ? "" : `${prefix}/`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    const rel = `${base}.pre-commit-config.yaml`;
    if (!existsSync(join(root, rel))) continue;
    if (!claimFile(state, "pre-commit", rel, prefix !== "")) continue;
    const raw = (readTextWarn(join(root, rel), rel, warnings) ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const entryRe = /^\s*entry:\s*(.+)$/gm;
    let m: RegExpExecArray | null; let i = 0;
    while ((m = entryRe.exec(raw)) !== null) {
      findings.push(makeFinding(root, rel, "pre-commit", "entry", m[1].trim().replace(/^["']|["']$/g, ""), String(i++), undefined, baseAbs));
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
}

function scanAgentDirs(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  for (const prefix of state.disc.projectRoots) {
    const base = prefix === "" ? "" : `${prefix}/`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    for (const [dir, source] of [[".cursor", "cursor"], [".codex", "codex"]] as Array<[string, HookSource]>) {
      const abs = join(root, base, dir);
      if (!existsSync(abs)) continue;
      let entries: string[] = [];
      try { entries = readdirSync(abs); } catch {
        warnings.push(`Unreadable directory skipped: ${base}${dir} could not be listed; the scan is partial`);
        continue;
      }
      for (const name of entries.sort()) {
        const fileAbs = join(abs, name);
        const rel = `${base}${dir}/${name}`;
        let st; try { st = statSync(fileAbs); } catch (err) {
          const code = (err as NodeJS.ErrnoException | undefined)?.code ?? "error";
          warnings.push(`Unreadable surface skipped: ${rel} could not be examined (${code}); it was not inventoried`);
          continue;
        }
        if (!st.isFile()) continue;
        // mcp.json is an MCP config surface, inventoried exactly once by
        // the central scanMcpFile pass in scanHooks (P-035). Running it
        // through the generic command walk here as well counted every
        // .cursor/mcp.json server twice.
        if (name === "mcp.json") continue;
        if (!claimFile(state, "agent", rel, prefix !== "")) continue;
        if (name.endsWith(".json")) {
          const data = readJson(root, rel, warnings);
          if (data) collectGenericCommands(data, rel, root, findings, source, "", baseAbs);
        } else {
          const content = readTextWarn(fileAbs, rel, warnings);
          if (content && content.trim()) {
            findings.push(makeFinding(root, rel, source, name, content.trim().slice(0, 200000), undefined, undefined, baseAbs));
          }
        }
      }
    }
  }
}

function collectGenericCommands(node: unknown, file: string, root: string, findings: HookFinding[], source: HookSource, prefix = "", baseAbs: string = root): void {
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  if (typeof obj.command === "string" && obj.command.trim()) {
    const args = Array.isArray(obj.args) ? obj.args.filter((a) => typeof a === "string").join(" ") : "";
    findings.push(makeFinding(root, file, source, prefix || "command", [obj.command, args].filter(Boolean).join(" "), String(findings.length), undefined, baseAbs));
  }
  for (const [key, value] of Object.entries(obj)) {
    if (value && typeof value === "object") collectGenericCommands(value, file, root, findings, source, prefix ? `${prefix}:${key}` : key, baseAbs);
  }
}

function scanMcpFile(root: string, rel: string, findings: HookFinding[], warnings: string[], state: ScanState, baseAbs: string, isNested: boolean): void {
  if (!existsSync(join(root, rel))) return;
  if (!claimFile(state, "mcp", rel, isNested)) return;
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
    if (full) findings.push(makeFinding(root, rel, "mcp-config", `mcp:${name}`, full, undefined, undefined, baseAbs));
    if (typeof c.url === "string" && c.url) {
      findings.push(makeFinding(root, rel, "mcp-config", `mcp:${name}:url`, c.url, undefined, undefined, baseAbs));
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
function scanWorkflows(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  for (const prefix of state.disc.projectRoots) {
    const base = prefix === "" ? "" : `${prefix}/`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    const dir = `${base}.github/workflows`;
    const abs = join(root, dir);
    if (!existsSync(abs)) continue;
    let entries: string[] = [];
    try { entries = readdirSync(abs); } catch {
      warnings.push(`Unreadable directory skipped: ${dir} could not be listed; the scan is partial`);
      continue;
    }
    for (const name of entries.sort()) {
      if (!/\.(yml|yaml)$/.test(name)) continue;
      const rel = `${dir}/${name}`;
      if (!claimFile(state, "workflows", rel, prefix !== "")) continue;
      scanOneWorkflow(root, rel, baseAbs, findings, warnings);
    }
  }
}

function scanOneWorkflow(root: string, rel: string, baseAbs: string, findings: HookFinding[], warnings: string[]): void {
  {
    const rawFile = readTextWarn(join(root, rel), rel, warnings);
    if (rawFile === null) return;
    const raw = rawFile.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    // Trailing whitespace is not YAML content (P-075): a line that
    // differs from its twin only by trailing spaces must parse
    // identically. Before v0.1.15 a map anchor line carrying only
    // trailing whitespace after the anchor name matched the scalar
    // anchor pattern with a whitespace "value", so the mapping
    // anchor never registered, its definition run line was
    // inventoried as a live step, and alias and merge-key steps
    // resolved to an empty command at UNKNOWN.
    const lines = raw.split("\n").map((l) => l.replace(/[ \t]+$/, ""));
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
      const scalarM = line.match(/^(\s*)(?:-\s*)?([A-Za-z0-9_-]+):\s*&([A-Za-z0-9_-]+)\s+(\S.*?)\s*$/);
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
        findings.push(makeFinding(root, rel, "github-workflow", "run", resolved, String(i++), lineNo, baseAbs));
        continue;
      }
      const mergeKey = line.match(/^\s*<<:\s*\*([A-Za-z0-9_-]+)\s*(#.*)?$/);
      if (mergeKey) {
        const name = mergeKey[1];
        const resolved = scalarAnchors.has(name) || mapAnchors.has(name) ? resolveAlias(`*${name}`) : `*${name}`;
        findings.push(makeFinding(root, rel, "github-workflow", "run", resolved, String(i++), lineNo, baseAbs));
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
      // A plain quoted scalar is the same command as its unquoted
      // form (P-076): run: "echo single-line" is echo single-line.
      // Strip one pair of surrounding quotes before classification
      // and storage, so both forms produce the identical finding.
      rest = unquote(rest);
      const blockHeader = rest.match(/^([|>])([+-]?)\s*(#.*)?$/);
      if (blockHeader) {
        const { body, end } = collectBlock(idx, runIndent);
        if (body) {
          findings.push(makeFinding(root, rel, "github-workflow", "run", body, String(i++), lineNoRun, baseAbs));
        }
        idx = end - 1;
        continue;
      }
      if (rest === "") continue;
      findings.push(makeFinding(root, rel, "github-workflow", "run", rest, String(i++), lineNoRun, baseAbs));
    }
  }
}

function scanGitHooks(root: string, findings: HookFinding[], warnings: string[], state: ScanState): void {
  scanDirFiles(root, ".githooks", "githooks", "githooks", findings, warnings, state);
}

/**
 * SAFE finding aggregation (P-070). A single 5 MB workflow of about
 * 92,000 repeated benign steps produced one finding record per step
 * on 0.1.14: 91,980 findings, 35,390,354 bytes of JSON, 23.7 seconds
 * of wall time on the published binary, nearly all of it inventory
 * noise (every finding the same SAFE step). Repetition at that scale
 * is one fact, not 92,000: when at least AGGREGATE_MIN identical
 * SAFE findings (same file, source, hook, command, rules, and
 * evidence) repeat, they collapse into a single aggregate record
 * that keeps the first finding's id and line and carries count (the
 * number folded in) and lastLine (the last folded line). Groups of
 * two stay individual: a pair is ordinary inventory, not mass
 * repetition.
 *
 * Only SAFE findings are ever aggregated. A RISKY or UNKNOWN finding
 * is a per-occurrence fact (its line is where a human must look),
 * and collapsing one could hide the one occurrence that matters.
 * The verdict is computed on the full inventory BEFORE aggregation,
 * so verdicts and exit codes are unchanged by the collapse; counts
 * in the report describe the reported records, and the aggregation
 * object preserves the pre-aggregation total and states the
 * collapse in words, in JSON and in the human renderer. The
 * collapse is never silent.
 */
export const AGGREGATE_MIN = 3;

function aggregateSafeFindings(findings: HookFinding[]): { findings: HookFinding[]; aggregation?: ScanReport["aggregation"] } {
  const keyOf = (f: HookFinding): string => [f.file, f.source, f.hook, f.command, f.classification, f.rules.join(","), f.evidence].join("\u0001");
  const groups = new Map<string, number[]>();
  findings.forEach((f, i) => {
    if (f.classification !== "SAFE") return;
    const key = keyOf(f);
    const arr = groups.get(key) ?? [];
    arr.push(i);
    groups.set(key, arr);
  });
  let aggregateRecords = 0;
  let collapsedFindings = 0;
  const out: HookFinding[] = [];
  findings.forEach((f, i) => {
    if (f.classification !== "SAFE") { out.push(f); return; }
    const idxs = groups.get(keyOf(f)) as number[];
    if (idxs.length < AGGREGATE_MIN) { out.push(f); return; }
    if (idxs[0] !== i) return; // folded into the group's first record
    aggregateRecords++;
    collapsedFindings += idxs.length - 1;
    const last = findings[idxs[idxs.length - 1]];
    out.push({
      ...f,
      count: idxs.length,
      ...(last.line !== undefined && f.line !== undefined && last.line !== f.line ? { lastLine: last.line } : {}),
    });
  });
  if (aggregateRecords === 0) return { findings: out };
  const folded = collapsedFindings + aggregateRecords;
  return {
    findings: out,
    aggregation: {
      findingsBeforeAggregation: findings.length,
      aggregateRecords,
      collapsedFindings,
      note: `${folded} identical SAFE findings were collapsed into ${aggregateRecords} counted aggregate record(s); ${collapsedFindings} finding record(s) were folded away. Only SAFE findings are aggregated; RISKY and UNKNOWN findings are always reported individually. The verdict was computed on the full inventory of ${findings.length} findings before aggregation, so the verdict and exit codes are unchanged.`,
    },
  };
}

/**
 * Empty estate note (P-014, hookcheck half). A scan that inventories
 * nothing must say so next to the verdict, in JSON as well as in the
 * human output: CLEAN with total 0 is vacuously true and otherwise reads
 * as an all-clear.
 */
export const EMPTY_ESTATE_NOTE = "Nothing was found to audit: no auto-exec hooks were inventoried under this path, so the verdict covers an empty estate. This can mean a hook-free repo, an empty directory, or a path that is not a repo root.";

/**
 * Surface paths checked for unresolvable symbolic links at every
 * project root before scanning (P-074 completion, v0.1.16). The
 * discovery walk never descends into dot-named directories (they
 * are surface containers, scanned directly), and the surface
 * scanners key off existence checks that are false for a dangling
 * link, so a link planted AT a surface path (.claude ->
 * /nonexistent, .husky -> /nonexistent, .pre-commit-config.yaml ->
 * /nonexistent; the chaos hostile-fs shapes) made the surface
 * vanish silently on 0.1.15: verdict CLEAN, warnings []. The sweep
 * lstats each surface path; a path that is a symbolic link whose
 * target cannot be resolved earns one warning naming the path and
 * the reason. A link that DOES resolve keeps the long-standing
 * behavior: the surface scanners follow it (a repo may
 * legitimately symlink its own hooks directory), with no warning.
 */
const SURFACE_LINK_PATHS = [
  ".github", ".claude", "claude", ".vscode", ".husky", ".githooks",
  ".cursor", ".codex", "package.json", ".pre-commit-config.yaml",
  "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".mcp.json", "mcp.json",
  ".claude/settings.json", ".claude/settings.local.json",
];

function warnUnresolvableSurfaceLinks(root: string, disc: Discovery, warnings: string[]): void {
  const warned = new Set<string>();
  for (const prefix of disc.projectRoots) {
    const base = prefix === "" ? "" : `${prefix}/`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    for (const rel of SURFACE_LINK_PATHS) {
      const abs = join(baseAbs, rel);
      let lst; try { lst = lstatSync(abs); } catch { continue; }
      if (!lst.isSymbolicLink()) continue;
      try { statSync(abs); continue; } catch (err) {
        const name = `${base}${rel}`;
        if (warned.has(name)) continue;
        warned.add(name);
        const code = (err as NodeJS.ErrnoException | undefined)?.code ?? "error";
        warnings.push(`Unreadable surface skipped: ${name} is a symbolic link that could not be resolved (${code}); it was not inventoried`);
      }
    }
  }
}

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
  const disc = discoverSurfaces(root, warnings);
  warnUnresolvableSurfaceLinks(root, disc, warnings);
  const state: ScanState = { disc, inventoried: new Set<string>(), familyFound: new Map(), familyCapped: new Map(), partial: false };
  scanPackageJson(root, findings, warnings, state);
  scanClaude(root, findings, warnings, state);
  scanPluginHooks(root, findings, warnings, state);
  scanVscode(root, findings, warnings, state);
  scanDirFiles(root, ".husky", "husky", "husky", findings, warnings, state);
  scanLefthook(root, findings, warnings, state);
  scanPreCommit(root, findings, warnings, state);
  scanAgentDirs(root, findings, warnings, state);
  // MCP config surfaces, each inventoried exactly once (P-035), at the
  // scan root and at every nested project root (P-065).
  // .windsurf/mcp.json joined the covered surfaces in v0.1.6 (P-034);
  // .vscode/mcp.json is handled inside scanVscode.
  for (const prefix of disc.projectRoots) {
    const base = prefix === "" ? "" : `${prefix}/`;
    const baseAbs = prefix === "" ? root : join(root, prefix);
    for (const name of [".mcp.json", "mcp.json", ".cursor/mcp.json", ".windsurf/mcp.json", ".codex/mcp.json"]) {
      scanMcpFile(root, `${base}${name}`, findings, warnings, state, baseAbs, prefix !== "");
    }
  }
  scanWorkflows(root, findings, warnings, state);
  scanGitHooks(root, findings, warnings, state);

  // Bounded scan honesty (P-065): a scan cut short by the discovery
  // bounds must say so, naming the bound, instead of presenting as
  // complete. Surfaces spotted just below the depth bound are counted
  // in the warning, never silently dropped.
  if (disc.depthBoundHit) {
    const below = disc.surfacesBelowBound > 0
      ? `; at least ${disc.surfacesBelowBound} of the directories just below the bound contain hook surface files or config directories that were not inventoried`
      : "";
    warnings.push(`Nested discovery bounded at depth ${NESTED_MAX_DEPTH}: project directories more than ${NESTED_MAX_DEPTH} levels below the scan root were not scanned (${disc.frontierDirs} ${disc.frontierDirs === 1 ? "directory" : "directories"} below the bound not entered${below}); the scan is partial (bounded)`);
  }
  for (const [family, capped] of state.familyCapped) {
    const label = FAMILY_LABELS[family] ?? family;
    warnings.push(`Nested ${label} inventory capped at ${NESTED_MAX_FILES_PER_SURFACE} files (${state.familyFound.get(family) ?? 0} found); the remaining nested ${label} files were not inventoried and the scan is partial`);
    void capped;
  }

  // Dedupe identical ids (agent dir scan may double count mcp.json).
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.id}|${f.command}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });

  // The verdict is computed on the full inventory, before any
  // aggregation (P-070): collapsing repeated SAFE records for
  // presentation must never move a verdict or an exit code.
  let verdict = computeVerdict(deduped);
  // Partial scan floor (P-049, extended by P-065 and P-074): when any
  // inventoried file or directory could not be read, when a file cap
  // left surface files uninventoried, when hook surfaces were
  // spotted just below the discovery depth bound, or when a
  // symlinked directory was skipped under the no-follow policy, the
  // scan did not see the whole estate, so a bare CLEAN is not an
  // honest verdict. Floor at REVIEW; the warnings name exactly what
  // was missed.
  if (verdict === "CLEAN" && (warnings.some((w) => w.startsWith("Unreadable") || w.startsWith("Symlinked directory skipped")) || state.partial || disc.surfacesBelowBound > 0)) {
    verdict = "REVIEW";
  }
  const { findings: reported, aggregation } = aggregateSafeFindings(deduped);
  const counts = {
    total: reported.length,
    safe: reported.filter((f) => f.classification === "SAFE").length,
    risky: reported.filter((f) => f.classification === "RISKY").length,
    unknown: reported.filter((f) => f.classification === "UNKNOWN").length,
  };
  return {
    path: root,
    verdict,
    findings: reported,
    counts,
    ...(aggregation ? { aggregation } : {}),
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
  if (report.aggregation) lines.push(`  aggregation: ${report.aggregation.note}`);
  if (report.note) lines.push(`  note: ${report.note}`);
  for (const f of report.findings) {
    const linePart = f.line !== undefined ? (f.lastLine !== undefined ? `, lines ${f.line}-${f.lastLine}` : `, line ${f.line}`) : "";
    const countPart = f.count !== undefined ? `, count ${f.count}` : "";
    lines.push(`  [${f.classification}] ${f.id} (${f.source}${linePart}${countPart})`);
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
