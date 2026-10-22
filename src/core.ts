/**
 * hookcheck core: deterministic local scan for auto-exec hooks.
 *
 * No network, no LLM. Every classification comes from explicit pattern
 * rules so the same repo always produces the same report.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Classification, HookFinding, HookSource, ScanReport, Verdict } from "./types.js";

export const VERSION = "0.1.0";

interface RuleDef {
  id: string;
  pattern: RegExp;
  evidence: string;
  /** True when this rule alone indicates remote code fetch. */
  remote?: boolean;
  /** True when this rule indicates credential store access. */
  credential?: boolean;
}

export const RISKY_RULES: RuleDef[] = [
  { id: "CURL-PIPE-SH", pattern: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/, evidence: "pipes a network download straight into a shell", remote: true },
  { id: "NET-FETCH", pattern: /\b(curl|wget)\b|\bfetch\s*\(|https?\s*\.get\s*\(|requests\.(get|post)\b|Invoke-WebRequest\b|Invoke-RestMethod\b/, evidence: "performs a network fetch", remote: true },
  { id: "REMOTE-URL", pattern: /https?:\/\/[^\s"'`]+/, evidence: "references a remote URL", remote: true },
  { id: "CRED-ACCESS", pattern: /~\/\.ssh|\$HOME\/\.ssh|\.aws\/|~\/\.aws|\.gnupg|id_rsa|id_ed25519|\.npmrc\b|\.netrc\b|credentials(\.json)?\b|\.config\/gh|keychain/i, evidence: "touches a credential store path", credential: true },
  { id: "ENV-ACCESS", pattern: /process\.env|os\.environ|getenv\s*\(|\benv\b.*\b(print|export)|\$\{?\s*(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)/, evidence: "reads environment variables that commonly hold secrets" },
  { id: "ENV-EXFIL", pattern: /(process\.env|os\.environ)[\s\S]{0,80}(fetch|https?|request|post|send|upload)/i, evidence: "combines environment access with an outbound send pattern", credential: true, remote: true },
  { id: "OBFUSCATION", pattern: /base64\s+(-d|--decode)|atob\s*\(|Buffer\.from\s*\([^)]*base64|\\x[0-9a-fA-F]{2}|eval\s*\(|Function\s*\(/, evidence: "uses decoding or dynamic evaluation often used to hide payloads" },
  { id: "SHELL-EXEC", pattern: /\b(child_process|execSync|spawnSync|exec\s*\()\b|\/bin\/(sh|bash)\b|powershell(\.exe)?\b|cmd\.exe\b/, evidence: "spawns a shell or child process" },
  { id: "WRITE-OUTSIDE", pattern: /(>>?|tee)\s+~\/|(>>?|tee)\s+\$HOME\/|chmod\s+\+x/, evidence: "writes outside the repo or changes executable bits" },
  { id: "DOWNLOAD-EXEC", pattern: /\bnode\s+-e\b|\bpython3?\s+-c\b|\bdeno\s+eval\b|\bbun\s+-e\b/, evidence: "executes inline code supplied on the command line" },
];

const SAFE_PATTERNS: RegExp[] = [
  /^(npm|npx|yarn|pnpm|bun)\s+(run\s+)?(test|lint|build|dev|start|typecheck|check|format|prepare:.*|prepublishOnly.*)$/i,
  /^(npx\s+)?(tsc|eslint|prettier|vitest|jest|mocha|husky|lint-staged|lefthook|pre-commit)(\s|$)/i,
  /^node\s+(--test|scripts\/|tools\/|build)/i,
  /^(echo|true|exit 0)\b/i,
  /^git\s+(config|rev-parse|status)/i,
  /^patch-package$/i,
  /^simple-git-hooks$/i,
];

export function classifyCommand(command: string): { classification: Classification; rules: string[]; evidence: string } {
  const cmd = command.trim();
  const fired: RuleDef[] = [];
  for (const rule of RISKY_RULES) {
    if (rule.pattern.test(cmd)) fired.push(rule);
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

/** If a command runs a local file, inspect that file for risky patterns too. */
function escalateWithLocalFile(root: string, finding: HookFinding): HookFinding {
  const m = /\b(?:node|bash|sh|python3?|deno run|bun run)\s+([^\s;&|]+\.(?:mjs|cjs|js|ts|sh|py))\b/.exec(finding.command);
  if (!m) return finding;
  const rel = m[1].replace(/^\.\//, "");
  const abs = join(root, rel);
  if (!existsSync(abs)) return finding;
  let content = "";
  try { content = readFileSync(abs, "utf8").slice(0, 20000); } catch { return finding; }
  const inner = classifyCommand(content.replace(/\n/g, " "));
  if (inner.classification === "RISKY") {
    const rules = Array.from(new Set([...finding.rules, ...inner.rules]));
    return {
      ...finding,
      classification: "RISKY",
      rules,
      evidence: `${finding.evidence === "" ? "" : finding.evidence + "; "}referenced local file ${rel} is RISKY: ${inner.evidence}`,
    };
  }
  return finding;
}

export function computeVerdict(findings: HookFinding[]): Verdict {
  let review = false;
  for (const f of findings) {
    if (f.classification === "RISKY") {
      const hasRemote = f.rules.some((id) => RISKY_RULES.find((r) => r.id === id)?.remote);
      const hasCred = f.rules.some((id) => RISKY_RULES.find((r) => r.id === id)?.credential);
      if (hasRemote || hasCred) return "COMPROMISED-PATTERN";
      review = true;
    } else if (f.classification === "UNKNOWN") {
      review = true;
    }
  }
  return review ? "REVIEW" : "CLEAN";
}

function makeFinding(root: string, file: string, source: HookSource, hook: string, command: string, idSuffix?: string): HookFinding {
  const c = classifyCommand(command);
  const id = `${file}:${hook}${idSuffix !== undefined ? `:${idSuffix}` : ""}`;
  const base: HookFinding = {
    id, file, source, hook, command,
    classification: c.classification, rules: c.rules,
    evidence: c.evidence,
  };
  return escalateWithLocalFile(root, base);
}

function readText(abs: string): string | null {
  try { return readFileSync(abs, "utf8"); } catch { return null; }
}

function readJson(root: string, rel: string, warnings: string[]): unknown | null {
  const raw = readText(join(root, rel));
  if (raw === null) return null;
  // Strip simple JSONC comments and trailing commas for VS Code style files.
  const cleaned = raw
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/,\s*([}\]])/g, "$1");
  try { return JSON.parse(cleaned); } catch {
    warnings.push(`Malformed JSON in ${rel}: file skipped for structured parsing`);
    return null;
  }
}

function scanPackageJson(root: string, findings: HookFinding[], warnings: string[]): void {
  const rel = "package.json";
  if (!existsSync(join(root, rel))) return;
  const data = readJson(root, rel, warnings) as { scripts?: Record<string, unknown> } | null;
  if (!data) {
    // readJson already warned when the file exists but is malformed. If it
    // parsed to a non object, note it as well.
    if (readText(join(root, rel)) !== null && !warnings.some((w) => w.includes(rel))) {
      warnings.push(`Could not parse ${rel} as an object`);
    }
    return;
  }
  const watched = ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"];
  for (const name of watched) {
    const cmd = data.scripts?.[name];
    if (typeof cmd === "string" && cmd.trim()) {
      findings.push(makeFinding(root, rel, "package.json", name, cmd));
    }
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

function scanClaude(root: string, findings: HookFinding[], warnings: string[]): void {
  for (const rel of [".claude/settings.json", ".claude/settings.local.json"]) {
    if (!existsSync(join(root, rel))) continue;
    const data = readJson(root, rel, warnings) as { hooks?: unknown } | null;
    if (!data) continue;
    if (data.hooks) collectClaudeHooks(data.hooks, rel, root, findings, "");
    else warnings.push(`No hooks key in ${rel}`);
  }
}

function scanVscode(root: string, findings: HookFinding[], warnings: string[]): void {
  const rel = ".vscode/tasks.json";
  if (!existsSync(join(root, rel))) return;
  const data = readJson(root, rel, warnings) as { tasks?: Array<Record<string, unknown>> } | null;
  if (!data?.tasks) return;
  data.tasks.forEach((task, idx) => {
    const runOptions = (task.runOptions ?? {}) as Record<string, unknown>;
    const runOn = runOptions.runOn;
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
  // MCP config inside .vscode
  scanMcpFile(root, ".vscode/mcp.json", findings, warnings);
}

function scanDirFiles(root: string, dirRel: string, source: HookSource, findings: HookFinding[]): void {
  const abs = join(root, dirRel);
  if (!existsSync(abs)) return;
  let entries: string[] = [];
  try { entries = readdirSync(abs); } catch { return; }
  for (const name of entries.sort()) {
    const fileAbs = join(abs, name);
    let st; try { st = statSync(fileAbs); } catch { continue; }
    if (!st.isFile()) continue;
    if (name === "_" || name.startsWith(".")) continue;
    const content = readText(fileAbs);
    if (content === null) continue;
    const firstMeaningful = content.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("set -")).join(" ");
    const fileRel = `${dirRel}/${name}`;
    // Entire file content is the command surface for husky style hooks.
    findings.push(makeFinding(root, fileRel, source, name, content.trim().slice(0, 500)));
    void firstMeaningful;
  }
}

function scanLefthook(root: string, findings: HookFinding[]): void {
  for (const rel of ["lefthook.yml", "lefthook.yaml", ".lefthook.yml"]) {
    if (!existsSync(join(root, rel))) continue;
    const raw = readText(join(root, rel)) ?? "";
    const runRe = /^\s*run:\s*(.+)$/gm;
    let m: RegExpExecArray | null; let i = 0;
    while ((m = runRe.exec(raw)) !== null) {
      findings.push(makeFinding(root, rel, "lefthook", "run", m[1].trim().replace(/^["']|["']$/g, ""), String(i++)));
    }
  }
}

function scanPreCommit(root: string, findings: HookFinding[]): void {
  const rel = ".pre-commit-config.yaml";
  if (!existsSync(join(root, rel))) return;
  const raw = readText(join(root, rel)) ?? "";
  const entryRe = /^\s*entry:\s*(.+)$/gm;
  let m: RegExpExecArray | null; let i = 0;
  while ((m = entryRe.exec(raw)) !== null) {
    findings.push(makeFinding(root, rel, "pre-commit", "entry", m[1].trim().replace(/^["']|["']$/g, ""), String(i++)));
  }
  const repoRe = /^\s*-\s*repo:\s*(https?:\/\/\S+)$/gm;
  while ((m = repoRe.exec(raw)) !== null) {
    findings.push(makeFinding(root, rel, "pre-commit", "remote-repo", m[1].trim(), String(i++)));
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
      if (name.endsWith(".json")) {
        const data = readJson(root, rel, warnings);
        if (data) collectGenericCommands(data, rel, root, findings, source);
      } else {
        const content = readText(fileAbs);
        if (content && content.trim()) {
          findings.push(makeFinding(root, rel, source, name, content.trim().slice(0, 500)));
        }
      }
      if (name === "mcp.json") scanMcpFile(root, rel, findings, warnings);
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

function scanWorkflows(root: string, findings: HookFinding[]): void {
  const dir = ".github/workflows";
  const abs = join(root, dir);
  if (!existsSync(abs)) return;
  let entries: string[] = [];
  try { entries = readdirSync(abs); } catch { return; }
  for (const name of entries.sort()) {
    if (!/\.(yml|yaml)$/.test(name)) continue;
    const rel = `${dir}/${name}`;
    const raw = readText(join(root, rel)) ?? "";
    const runRe = /^\s*-?\s*run:\s*(.+)$/gm;
    let m: RegExpExecArray | null; let i = 0;
    while ((m = runRe.exec(raw)) !== null) {
      const cmd = m[1].trim();
      if (cmd === "|" || cmd === ">" || cmd === "") continue;
      findings.push(makeFinding(root, rel, "github-workflow", "run", cmd, String(i++)));
    }
  }
}

function scanGitHooks(root: string, findings: HookFinding[]): void {
  scanDirFiles(root, ".githooks", "githooks", findings);
}

export function scanHooks(root: string): ScanReport {
  const findings: HookFinding[] = [];
  const warnings: string[] = [];
  if (!existsSync(root)) {
    warnings.push(`Path does not exist: ${root}`);
    return {
      path: root, verdict: "REVIEW", findings, warnings,
      counts: { total: 0, safe: 0, risky: 0, unknown: 0 },
      scannedAt: new Date().toISOString(),
    };
  }
  scanPackageJson(root, findings, warnings);
  scanClaude(root, findings, warnings);
  scanVscode(root, findings, warnings);
  scanDirFiles(root, ".husky", "husky", findings);
  scanLefthook(root, findings);
  scanPreCommit(root, findings);
  scanAgentDirs(root, findings, warnings);
  for (const rel of [".mcp.json", "mcp.json", ".cursor/mcp.json"]) scanMcpFile(root, rel, findings, warnings);
  scanWorkflows(root, findings);
  scanGitHooks(root, findings);

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
  return {
    path: root,
    verdict: computeVerdict(deduped),
    findings: deduped,
    counts,
    warnings,
    scannedAt: new Date().toISOString(),
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
  for (const f of report.findings) {
    lines.push(`  [${f.classification}] ${f.id} (${f.source})`);
    lines.push(`      command: ${f.command.slice(0, 200)}`);
    if (f.rules.length) lines.push(`      rules: ${f.rules.join(", ")}`);
    lines.push(`      evidence: ${f.evidence}`);
  }
  for (const w of report.warnings) lines.push(`  [warn] ${w}`);
  if (report.verdict === "CLEAN") lines.push("CLEAN: no risky or unknown auto-exec hooks found.");
  else if (report.verdict === "REVIEW") lines.push("REVIEW: at least one hook needs manual review.");
  else lines.push("COMPROMISED-PATTERN: at least one risky hook fetches remote code or touches credential stores. Treat as a Shai-Hulud style persistence pattern until proven otherwise.");
  return lines.join("\n");
}

export { relative };
export type { Classification, HookFinding, ScanReport, Verdict };
