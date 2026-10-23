import type { BashWatchLineBatch } from "./bridge.js";

const MAX_PENDING_WATCH_LINES = 50;

/** Live pushes are deltas; durable replay is a replacement snapshot. */
export function mergeWatchLineBatches(
  previous: BashWatchLineBatch,
  next: BashWatchLineBatch,
): BashWatchLineBatch {
  if (next.snapshot) return next;
  const merged = { ...previous, lines: previous.lines.map((line) => ({ ...line })) };
  let retained = merged.lines.reduce((sum, line) => sum + line.count, 0);
  for (const line of next.lines) {
    const keep = Math.min(line.count, MAX_PENDING_WATCH_LINES - retained);
    const dropped = line.count - keep;
    if (dropped > 0 && merged.first_dropped_offset === null) {
      merged.first_dropped_offset = line.offset + keep * (line.end_offset - line.offset);
      merged.first_dropped_stream = line.stream;
    }
    merged.dropped_lines += dropped;
    if (keep > 0) {
      const last = merged.lines.at(-1);
      if (
        last &&
        last.stream === line.stream &&
        last.text === line.text &&
        last.offset + last.count * (last.end_offset - last.offset) === line.offset
      )
        last.count += keep;
      else merged.lines.push({ ...line, count: keep });
      retained += keep;
    }
  }
  merged.dropped_lines += next.dropped_lines;
  merged.skipped_long_lines += next.skipped_long_lines;
  if (merged.first_dropped_offset === null) {
    merged.first_dropped_offset = next.first_dropped_offset;
    merged.first_dropped_stream = next.first_dropped_stream;
  }
  return merged;
}

/** Render masked source lines and copyable, host-specific byte-page recovery calls. */
export function formatWatchLineBatch(
  taskId: string,
  batch: BashWatchLineBatch,
  camelCase: boolean,
): string {
  const lines = batch.lines.map(
    (line) => `${line.stream} byte ${line.offset} (x${line.count}): ${line.text}`,
  );
  if (batch.dropped_lines > 0 || batch.skipped_long_lines > 0) {
    const taskKey = camelCase ? "taskId" : "task_id";
    const cursor = batch.first_dropped_stream === "stderr" ? "stderr" : "output";
    const offsetKey = camelCase ? `${cursor}Offset` : `${cursor}_offset`;
    const incomplete =
      batch.skipped_long_lines > 0
        ? ` ${batch.skipped_long_lines} lines longer than 64 KiB skipped (scan incomplete).`
        : "";
    lines.push(
      `${batch.dropped_lines} matching lines dropped.${incomplete} Read bash_status({ ${taskKey}: ${JSON.stringify(taskId)}, ${offsetKey}: ${batch.first_dropped_offset ?? 0} }).`,
    );
  }
  return lines.join("\n");
}

/** Page text is masked by the engine; never decode raw transport bytes for display. */
export function formatBashOutputPages(data: Record<string, unknown>, camelCase: boolean): string {
  const lines: string[] = [];
  for (const stream of ["output", "stderr"]) {
    if (typeof data[`${stream}_page_text`] !== "string") continue;
    const next = camelCase ? `${stream}Offset` : `${stream}_offset`;
    lines.push(
      `${stream} page (next ${next}: ${data[`${stream}_next_offset`]}, has_more: ${data[`${stream}_has_more`]}):\n${data[`${stream}_page_text`]}`,
    );
  }
  return lines.join("\n");
}
