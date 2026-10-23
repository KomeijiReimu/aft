import { expect, test } from "bun:test";
import { WatchBatchProgress, watchBatchHasContent } from "../bash-watch-progress.js";
import type { BashWatchLineBatch } from "../bridge.js";

function snapshot(id = "a"): BashWatchLineBatch {
  return {
    pending_id: id,
    version: 1,
    snapshot: true,
    lines: [{ stream: "stdout", offset: 0, end_offset: 8, text: "READY a", count: 1 }],
    dropped_lines: 7,
    skipped_long_lines: 2,
    first_dropped_offset: 8,
    first_dropped_stream: "stdout",
  };
}

test("watch progress dedups folded lines and cumulative counters after admission", () => {
  const progress = new WatchBatchProgress();
  const first = snapshot();
  expect(watchBatchHasContent(progress.unseen(first))).toBe(true);
  progress.admit(first);
  expect(watchBatchHasContent(progress.unseen(first))).toBe(false);
  const next = snapshot();
  next.lines[0].count = 3;
  next.dropped_lines = 10;
  next.skipped_long_lines = 3;
  next.version = 2;
  const unseen = progress.unseen(next);
  expect(unseen.lines).toEqual([
    { stream: "stdout", offset: 8, end_offset: 16, text: "READY a", count: 2 },
  ]);
  expect(unseen.dropped_lines).toBe(3);
  expect(unseen.skipped_long_lines).toBe(1);
});

test("watch progress does not reserve rows before admission or across pending generations", () => {
  const progress = new WatchBatchProgress();
  expect(progress.unseen(snapshot()).lines).toHaveLength(1);
  expect(progress.unseen(snapshot()).lines).toHaveLength(1);
  progress.admit(snapshot());
  const fresh = snapshot("b");
  fresh.dropped_lines = 10;
  expect(progress.unseen(fresh).dropped_lines).toBe(10);
  expect(progress.unseen(fresh).lines).toHaveLength(1);
});
