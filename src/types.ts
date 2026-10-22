/**
 * hookcheck types.
 *
 * A HookFinding is one auto-exec hook discovered in a repo: where it lives,
 * the exact command text, how it was classified, and the rule ids plus
 * evidence that produced that classification. Nothing is inferred silently.
 */

export type Classification = "SAFE" | "RISKY" | "UNKNOWN";

export type Verdict = "CLEAN" | "REVIEW" | "COMPROMISED-PATTERN";

export type HookSource =
  | "package.json"
  | "claude-settings"
  | "claude-plugin"
  | "vscode-tasks"
  | "husky"
  | "lefthook"
  | "pre-commit"
  | "cursor"
  | "codex"
  | "mcp-config"
  | "github-workflow"
  | "githooks";

export interface HookFinding {
  /** Stable id, e.g. "package.json:postinstall" or ".claude/settings.json:SessionStart:0". */
  id: string;
  /** Repo relative file path the hook was found in. */
  file: string;
  source: HookSource;
  /** Hook name or event, e.g. postinstall, SessionStart, folderOpen. */
  hook: string;
  /** Exact command text that would auto-execute. */
  command: string;
  /** 1-based line number of the hook inside its file, when known (workflow run steps). */
  line?: number;
  /**
   * Aggregation (P-070, v0.1.15): when at least 3 identical SAFE
   * findings (same file, source, hook, command, rules, and evidence)
   * repeat, they collapse into one aggregate record carrying count
   * (the number of findings folded into it) and lastLine (the line
   * of the last folded finding; line keeps the first). Only SAFE
   * findings are ever aggregated. Absent on ordinary findings.
   */
  count?: number;
  /** Line of the last finding folded into an aggregate record. */
  lastLine?: number;
  classification: Classification;
  /** Rule ids that fired, e.g. ["NET-FETCH", "CRED-ACCESS"]. Empty for SAFE. */
  rules: string[];
  /** Human readable evidence for the classification. */
  evidence: string;
}

export interface ScanReport {
  path: string;
  verdict: Verdict;
  findings: HookFinding[];
  counts: { total: number; safe: number; risky: number; unknown: number };
  /**
   * Aggregation summary (P-070, v0.1.15), present only when at
   * least one group of identical SAFE findings was collapsed.
   * counts reflect the reported records; findingsBeforeAggregation
   * preserves the full inventory total, and the verdict was
   * computed on that full inventory before aggregation. The note
   * states the collapse in words so it is never silent.
   */
  aggregation?: {
    findingsBeforeAggregation: number;
    aggregateRecords: number;
    collapsedFindings: number;
    note: string;
  };
  warnings: string[];
  scannedAt: string;
  /**
   * Present when nothing was found to audit (total 0): the note states
   * plainly that the verdict covers an empty estate, so a hook-free repo,
   * an empty directory, and a wrong path do not read as an all-clear
   * (P-014, mirroring the actionpin fix).
   */
  note?: string;
}

export interface ExplainResult {
  finding: HookFinding | null;
  explanation: string;
  report: ScanReport;
}
