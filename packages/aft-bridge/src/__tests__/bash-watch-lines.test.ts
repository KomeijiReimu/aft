import { expect, test } from "bun:test";
import { formatWatchLineBatch, WATCH_EACH_LINE_NEEDS_BACKGROUND } from "../bash-watch-lines.js";
import type { BashWatchLineBatch } from "../bridge.js";

function batch(): BashWatchLineBatch {
  return {
    lines: [],
    dropped_lines: 0,
    first_dropped_stream: null,
    first_dropped_offset: null,
    skipped_long_lines: 0,
  };
}

test("each_line row wording golden omits a single-line count", () => {
  const value = batch();
  value.pending_id = "transport-only-generation";
  value.version = 999;
  value.lines.push({
    stream: "stdout",
    offset: 18234,
    end_offset: 18257,
    text: "ERROR db timeout",
    count: 1,
  });
  expect(formatWatchLineBatch("task", value, false)).toBe("stdout byte 18234: ERROR db timeout");
  value.lines[0].count = 3;
  expect(formatWatchLineBatch("task", value, false)).toBe("stdout byte 18234 ×3: ERROR db timeout");
});

test("each_line drop wording golden uses each host's cursor names", () => {
  const value = {
    ...batch(),
    dropped_lines: 7,
    first_dropped_stream: "stdout",
    first_dropped_offset: 18240,
  };
  expect(formatWatchLineBatch("task", value, false)).toBe(
    '7 matching lines dropped. Read them with bash_status({ task_id: "task", output_offset: 18240 }).',
  );
  expect(formatWatchLineBatch("task", value, true)).toBe(
    '7 matching lines dropped. Read them with bash_status({ taskId: "task", outputOffset: 18240 }).',
  );
  value.skipped_long_lines = 2;
  value.first_dropped_stream = "stderr";
  expect(formatWatchLineBatch("task", value, false)).toBe(
    '7 matching lines dropped. 2 lines longer than 64 KiB were skipped, so the scan is incomplete. Read them with bash_status({ task_id: "task", stderr_offset: 18240 }).',
  );
  expect(formatWatchLineBatch("task", value, true)).toBe(
    '7 matching lines dropped. 2 lines longer than 64 KiB were skipped, so the scan is incomplete. Read them with bash_status({ taskId: "task", stderrOffset: 18240 }).',
  );
});

test("each_line sync refusal wording golden", () => {
  expect(WATCH_EACH_LINE_NEEDS_BACKGROUND).toBe(
    'bash_watch: deliver: "each_line" needs background: true.',
  );
});
