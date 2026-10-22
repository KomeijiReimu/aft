//! The published chunked-return vectors from `cortexkit-exec-remote-types`
//! 0.2.10, vendored byte for byte under `fixtures/return-chunked/` (see
//! `fixtures/SOURCE.md`). Each case is checked against its published digest
//! before it is decoded.

use super::types::StreamRecord;
use serde_json::Value;

macro_rules! vectors {
    ($($name:literal),* $(,)?) => {
        /// Every case: name, `.jcs` bytes, `.sha256` text.
        pub(crate) const RETURN_VECTORS: &[(&str, &[u8], &str)] = &[$(
            (
                $name,
                include_bytes!(concat!("fixtures/return-chunked/", $name, ".jcs")),
                include_str!(concat!("fixtures/return-chunked/", $name, ".sha256")),
            ),
        )*];
    };
}

vectors!(
    "two-files-one-empty",
    "three-chunks-short-last",
    "failed-missing",
    "failed-not-regular",
    "failed-escape",
    "failed-over-cap",
    "read-error-after-chunks",
    "replay-retained",
    "replay-expired",
    "unknown-cause-discards-chunks",
    "refuse-offset-gap",
    "refuse-offset-overlap",
    "refuse-interleaved-paths",
    "refuse-chunk-too-large",
    "refuse-empty-chunk",
    "refuse-path-index-out-of-range",
    "refuse-digest-mismatch",
    "refuse-size-mismatch",
    "refuse-path-not-echoed",
    "refuse-chunks-before-over-cap",
    "refuse-total-over-cap",
);

/// One case, after checking its bytes against the published digest.
pub(crate) fn return_vector(name: &str) -> Value {
    use sha2::{Digest, Sha256};
    let (_, bytes, digest) = RETURN_VECTORS
        .iter()
        .find(|(case, _, _)| *case == name)
        .unwrap_or_else(|| panic!("no return-chunked vector {name}"));
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        digest.trim(),
        "{name}.jcs no longer matches its published digest"
    );
    serde_json::from_slice(bytes).unwrap()
}

/// The case's stream records, decoded with the locked crate.
pub(crate) fn return_vector_records(name: &str) -> Vec<StreamRecord> {
    serde_json::from_value(return_vector(name)["records"].clone()).unwrap()
}

/// The case's requested paths.
// Only the Unix returned-file receiver tests read them.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn return_vector_paths(name: &str) -> Vec<String> {
    serde_json::from_value(return_vector(name)["return_paths"].clone()).unwrap()
}

#[test]
fn every_vendored_return_vector_matches_its_digest_and_round_trips() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/exec_remote/fixtures/return-chunked");
    let files = std::fs::read_dir(directory).unwrap().count();
    assert_eq!(
        files,
        RETURN_VECTORS.len() * 2,
        "unchecked vendored vector files"
    );
    for (name, bytes, _) in RETURN_VECTORS {
        let vector = return_vector(name);
        for record in vector["records"].as_array().unwrap() {
            let decoded: StreamRecord = serde_json::from_value(record.clone()).unwrap();
            assert_eq!(
                &serde_json::to_value(&decoded).unwrap(),
                record,
                "{name}: a record changed in a decode and encode round trip"
            );
        }
        assert!(!bytes.is_empty());
    }
}

/// Records what the stream consumer hands a sink, by seq.
#[derive(Default)]
struct ReturnSink {
    chunks: Vec<u64>,
    manifests: Vec<u64>,
    lost: Vec<u64>,
    gaps: usize,
    skipped: Vec<(u64, u64)>,
    verdicts: Vec<super::Verdict>,
}

impl super::OutputSink for ReturnSink {
    fn accepted(&mut self, _: &super::types::Accepted) -> std::io::Result<()> {
        Ok(())
    }
    fn output(&mut self, _: u64, _: super::types::OutputStream, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn truncated(&mut self, before_seq: u64) -> std::io::Result<()> {
        self.lost.push(before_seq);
        Ok(())
    }
    fn gap_recovery(&mut self, _: &super::GapRecovery) -> std::io::Result<()> {
        self.gaps += 1;
        Ok(())
    }
    fn unknown_output(&mut self, _: u64, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn return_chunk(&mut self, chunk: &super::types::ReturnChunk) -> std::io::Result<()> {
        self.chunks.push(chunk.seq);
        Ok(())
    }
    fn return_manifest(&mut self, manifest: &super::types::ReturnManifest) -> std::io::Result<()> {
        self.manifests.push(manifest.seq);
        Ok(())
    }
    fn return_gap_skipped(&mut self, first: u64, last: u64) -> std::io::Result<()> {
        self.skipped.push((first, last));
        Ok(())
    }
    fn terminal(
        &mut self,
        _: &super::types::TerminalRecord,
        verdict: &super::Verdict,
    ) -> std::io::Result<()> {
        self.verdicts.push(verdict.clone());
        Ok(())
    }
}

/// Feed a replay vector's records to a consumer that re-attaches after seq 0,
/// the record before the replayed part. An attach replays sequenced records
/// only, so the vector's acceptance is not fed again.
fn consume(records: Vec<StreamRecord>) -> (Result<(), super::Error>, ReturnSink) {
    let mut consumer = super::StreamConsumer::resume(super::ResumePoint {
        job_id: "0192a64a-1234-7000-8000-000000000001".parse().unwrap(),
        last_seq: Some(0),
        gap_recovery: None,
    });
    let mut sink = ReturnSink::default();
    for record in records {
        if matches!(record, StreamRecord::Accepted(_)) {
            continue;
        }
        let bytes = serde_json::to_vec(&record).unwrap();
        if let Err(error) = consumer.consume_bytes(&bytes, &mut sink) {
            return (Err(error), sink);
        }
    }
    (consumer.finish().map(|_| ()), sink)
}

#[test]
fn expired_replay_accepts_the_chunk_gap_before_its_manifest() {
    // Output at seq 2, then the manifest at its original seq 6: the chunks
    // the runner no longer keeps were at seqs 3 to 5.
    let (result, sink) = consume(return_vector_records("replay-expired"));
    result.expect("the expired replay completes without re-attaching");
    assert_eq!(sink.manifests, [6]);
    assert!(sink.chunks.is_empty());
    assert_eq!(sink.gaps, 0, "the chunk gap is not an output gap");
    assert!(sink.lost.is_empty(), "no output is reported lost");
    assert_eq!(sink.skipped, [(3, 5)], "the skipped seqs are disclosed");
    assert_eq!(sink.verdicts, [super::Verdict::Exited { code: 0 }]);
}

#[test]
fn retained_replay_delivers_chunks_then_manifest_in_seq_order() {
    let (result, sink) = consume(return_vector_records("replay-retained"));
    result.unwrap();
    assert_eq!(sink.chunks, [3, 4, 5]);
    assert_eq!(sink.manifests, [6]);
    assert_eq!(sink.gaps, 0);
    assert!(sink.skipped.is_empty());
}

#[test]
fn missing_chunks_before_a_manifest_that_returns_bytes_need_recovery() {
    // The same retained replay with its chunks lost in transit: those seqs
    // held returned bytes, so the gap is recovered by attaching again, never
    // skipped like an expired replay's.
    let records = return_vector_records("replay-retained")
        .into_iter()
        .filter(|record| !matches!(record, StreamRecord::ReturnChunk(_)))
        .collect();
    let (result, sink) = consume(records);
    assert!(
        matches!(result, Err(super::Error::RecoveryRequired { .. })),
        "{result:?}"
    );
    assert!(sink.manifests.is_empty());
    assert_eq!(sink.gaps, 1);
}

/// A fresh run's records: acceptance, output at seq 0, then `rest`.
fn live_stream(rest: Vec<StreamRecord>) -> (Result<(), super::Error>, ReturnSink) {
    use super::types::{Accepted, BytePayload, Output, OutputStream};
    let mut consumer = super::StreamConsumer::new();
    let mut sink = ReturnSink::default();
    let job_id = "0192a64a-1234-7000-8000-000000000001".parse().unwrap();
    let head = [
        StreamRecord::Accepted(Accepted::new(job_id, 1)),
        StreamRecord::Output(Output::new(
            0,
            OutputStream::Stdout,
            BytePayload(b"a".to_vec()),
        )),
    ];
    for record in head.into_iter().chain(rest) {
        let bytes = serde_json::to_vec(&record).unwrap();
        if let Err(error) = consumer.consume_bytes(&bytes, &mut sink) {
            return (Err(error), sink);
        }
    }
    (consumer.finish().map(|_| ()), sink)
}

/// A manifest at `seq` whose only path expired, and the terminal after it.
fn expired_manifest_and_terminal(seq: u64) -> Vec<StreamRecord> {
    use super::types::*;
    let job_id = "0192a64a-1234-7000-8000-000000000001".parse().unwrap();
    let entry =
        ReturnManifestEntry::failed("dist/app.bin", ReturnPathsFailureCause::Expired).with_size(10);
    vec![
        StreamRecord::ReturnManifest(ReturnManifest::new(
            job_id,
            seq,
            vec![entry],
            0,
            RETURN_CHUNKED_MAX_BYTES_CAP,
        )),
        StreamRecord::Terminal(TerminalRecord::new(
            job_id,
            Outcome::Exit { code: 0 },
            1,
            0,
            0,
        )),
    ]
}

#[test]
fn output_lost_inside_the_skipped_gap_is_disclosed_not_hidden() {
    // Seq 1 was output and seqs 2 and 3 were chunks; none arrived. Nothing
    // received tells them apart, so the gap is skipped and reported.
    let (result, sink) = live_stream(expired_manifest_and_terminal(4));
    result.unwrap();
    assert_eq!(sink.skipped, [(1, 3)]);
    assert_eq!(sink.manifests, [4]);
}

#[test]
fn output_received_inside_the_gap_keeps_ordinary_gap_recovery() {
    // Seq 2 arrived but seq 1 did not: the hole is before output, not
    // directly before the manifest, so it is never skipped.
    use super::types::{BytePayload, Output, OutputStream};
    let mut rest = vec![StreamRecord::Output(Output::new(
        2,
        OutputStream::Stdout,
        BytePayload(b"c".to_vec()),
    ))];
    rest.extend(expired_manifest_and_terminal(4));
    let (result, sink) = live_stream(rest);
    assert!(
        matches!(result, Err(super::Error::RecoveryRequired { .. })),
        "{result:?}"
    );
    assert!(sink.skipped.is_empty());
    assert!(sink.manifests.is_empty());
}
