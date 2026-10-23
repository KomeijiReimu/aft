import type { BashWatchLineBatch } from "./bridge.js";

type Stream = "stdout" | "stderr" | "pty";

function knownStream(stream: string): stream is Stream {
  return stream === "stdout" || stream === "stderr" || stream === "pty";
}

/** Admission watermarks for one pending watch generation; no line text is retained. */
export class WatchBatchProgress {
  private pendingID: string | undefined;
  private version: number | undefined;
  private ends: Record<Stream, number> = { stdout: 0, stderr: 0, pty: 0 };
  private dropped = 0;
  private skipped = 0;

  get admittedVersion(): number | undefined {
    return this.version;
  }

  unseen(batch: BashWatchLineBatch): BashWatchLineBatch {
    const same = this.pendingID === (batch.pending_id ?? "legacy");
    const obsolete =
      same &&
      !batch.snapshot &&
      batch.version !== undefined &&
      this.version !== undefined &&
      batch.version <= this.version;
    const lines: BashWatchLineBatch["lines"] = [];
    if (!obsolete)
      for (const line of batch.lines) {
        const width = Math.max(1, line.end_offset - line.offset);
        const end = same && knownStream(line.stream) ? this.ends[line.stream] : 0;
        const skip = Math.min(line.count, Math.max(0, Math.ceil((end - line.offset) / width)));
        if (skip < line.count)
          lines.push({
            ...line,
            offset: line.offset + skip * width,
            end_offset: line.end_offset + skip * width,
            count: line.count - skip,
          });
      }
    return {
      ...batch,
      lines,
      dropped_lines: obsolete
        ? 0
        : Math.max(0, batch.dropped_lines - (same && batch.snapshot ? this.dropped : 0)),
      skipped_long_lines: obsolete
        ? 0
        : Math.max(0, batch.skipped_long_lines - (same && batch.snapshot ? this.skipped : 0)),
    };
  }

  admit(batch: BashWatchLineBatch): void {
    const pendingID = batch.pending_id ?? "legacy";
    if (this.pendingID !== pendingID) {
      this.pendingID = pendingID;
      this.version = undefined;
      this.ends = { stdout: 0, stderr: 0, pty: 0 };
      this.dropped = 0;
      this.skipped = 0;
    }
    if (
      !batch.snapshot &&
      batch.version !== undefined &&
      this.version !== undefined &&
      batch.version <= this.version
    )
      return;
    for (const line of batch.lines) {
      if (knownStream(line.stream)) {
        const end = line.offset + line.count * Math.max(1, line.end_offset - line.offset);
        this.ends[line.stream] = Math.max(this.ends[line.stream], end);
      }
    }
    this.dropped = batch.snapshot
      ? Math.max(this.dropped, batch.dropped_lines)
      : this.dropped + batch.dropped_lines;
    this.skipped = batch.snapshot
      ? Math.max(this.skipped, batch.skipped_long_lines)
      : this.skipped + batch.skipped_long_lines;
    if (batch.version !== undefined)
      this.version = Math.max(this.version ?? batch.version, batch.version);
  }
}

export function watchBatchHasContent(batch: BashWatchLineBatch): boolean {
  return batch.lines.length > 0 || batch.dropped_lines > 0 || batch.skipped_long_lines > 0;
}
