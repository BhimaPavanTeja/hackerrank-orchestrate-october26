# Evaluation report

## Evaluation protocol

Only participant-facing files were used. The 32 public cases in `dataset/sample_deletion_requests.csv` were compared with `dataset/sample_output.csv`; the public answers were used as an evaluation reference, not as prediction-time labels. The hidden 518-case gold output is not available in the repository, so hidden-gold accuracy is not claimed.

## Public sample results

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | 32 / 32 (100.00%) |
| Step-level positional exact accuracy | 115 / 193 (59.59%) |
| Field-level positional accuracy (7 step fields) | 1,072 / 1,351 (79.35%) |
| Exact ordered step-sequence accuracy | 14 / 32 (43.75%) |
| Output schema validation | Passed (one row per sample case; valid JSON arrays and consecutive step numbers) |

Field accuracy counts `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id` at each aligned array position; absent positions count as incorrect. Sequence accuracy requires the complete ordered `steps_json` array to match exactly. These results show correct public-sample status decisions but remaining gaps in precise resource/evidence selection and complete step lists.

## Additional evaluation cases created by the participant

`test_solver.py` covers the following deterministic and AI-integration behaviors, all of which pass:

1. A marketing-only unsubscribe/removal request is `NOT_APPLICABLE` rather than a deletion authorization.
2. A Japanese-language account deletion request is recognized as authorized.
3. A newer participant-visible absence check supersedes an older present observation for the same resource.
4. An active connector produces `REPORT_ACTIVE_DATA_FLOW`, `DISABLE_DATA_FLOW`, and `VERIFY_DATA_FLOW_DISABLED` operations.
5. A retained account tombstone with an exposed email produces a redaction finding and redaction/verification plan.
6. The opt-in AI client sends redacted request text and accepts only a boolean structured decision.
7. AI configuration fails explicitly when the required API key/model settings are missing.

Run them with `python -m unittest discover -s code\evaluation -p "test_*.py" -v`.

The AI assist path was not used to generate the checked-in predictions because no provider credentials/model configuration were supplied. Its request classification is therefore integration-tested with a mocked API response, not benchmarked against the public sample.

## Failures found and improvements made

- Initial evidence matching missed nested JSON payloads and SQL rows whose data was stored in a `record_json` column. SQL payloads are now decoded before identifier matching.
- Point-in-time state initially treated old present copies as current after a later `404`. Linked resources now inherit later explicit absence observations, respecting `audit_at`.
- Structured logs separate lookup-start events from resource readbacks. Trace/correlation keys now connect lookup keys and subject references to completed resource checks.
- PDFs use compressed text streams; a standard-library fallback now decodes common Flate/ASCII85 text streams, with optional local `pdftotext`/`tesseract` support.
- Request-intent handling was tightened to distinguish deletion from marketing opt-out, correction, and access/export requests, and includes common multilingual deletion terms.
- The public sample still exposes incomplete step-level recall and exact evidence/resource mismatches. The run report makes that limitation explicit; no hidden-label performance is inferred.
- A configurable AI intent reviewer was added for requests that deterministic intent rules do not classify. The reviewer cannot mutate evidence findings or policy-derived steps, and all identifying aliases are redacted from request text before transmission.

## Full-dataset run

The generated root `output.csv` contains one sorted row for each of the 518 evaluation requests. Its schema and JSON serialization were validated after generation. Because hidden answers are unavailable, accuracy on those 518 cases is not measurable locally.
