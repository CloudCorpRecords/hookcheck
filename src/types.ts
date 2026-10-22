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
  warnings: string[];
  scannedAt: string;
}

export interface ExplainResult {
  finding: HookFinding | null;
  explanation: string;
  report: ScanReport;
}
