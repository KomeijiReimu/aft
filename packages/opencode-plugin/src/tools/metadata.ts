import { Effect } from "effect";

type MetadataContext = { metadata?: (update: Record<string, unknown>) => unknown };

/** Serialize live UI updates: OpenCode 1 may return a lazy Effect, while OpenCode 2 returns void. */
export function metadataUpdater(context: MetadataContext) {
  let pending = Promise.resolve();
  return (metadata: Record<string, unknown>): Promise<void> => {
    pending = pending.then(async () => {
      const result = context.metadata?.({ metadata });
      if (Effect.isEffect(result))
        await Effect.runPromise(result as Effect.Effect<unknown, unknown>);
      else await result;
    });
    // Progress callbacks cannot await. Attach a rejection handler now; the next
    // awaited update still reports a host failure without an unhandled rejection.
    void pending.catch(() => {});
    return pending;
  };
}
