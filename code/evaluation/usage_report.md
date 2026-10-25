# Model and token usage report

## Full-dataset prediction run

The checked-in `output.csv` was generated in deterministic mode using `python code/main.py`. AI assist is opt-in (`--ai-assist`) and was not enabled during that run.

| Provider/model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---:|---:|---:|---:|---:|
| Runtime model API: none | 0 | 0 | 0 | 0 | $0.00 |
| **Overall prediction run** | **0** | **0** | **0** | **0** | **$0.00** |

- Requests processed: 518
- Average model tokens per request: 0
- Estimated model cost per request: $0.00
- Token and cost totals refer only to calls made by the submitted solver; there were no such calls.

If a later full-dataset run uses AI assist, replace this section with the actual provider/model, request count, token usage, and cost reported by the provider. Do not estimate or invent unavailable telemetry.

The optional runtime model is selected through `OPENAI_MODEL` (or `--ai-model`) and is not hardcoded because supported model identifiers depend on the configured API provider/account. The coding-session model is not called by `code/main.py`.
