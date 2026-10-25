# Ghost Data Still Exists — hybrid Python and AI agent

This folder contains a hybrid deletion-audit agent. Python performs identity resolution, evidence extraction, point-in-time state reconstruction, policy enforcement, step ordering, and output validation deterministically. An optional AI intent reviewer handles requests that the deterministic intent rules do not classify; it cannot alter evidence findings or policy-derived remediation. OpenAI-compatible OpenAI and NVIDIA endpoints are supported.

## Requirements

- Python 3.10 or newer
- No required third-party packages
- Optional: `pdftotext` for richer PDF extraction and `tesseract` for OCR of screenshots; the solver also has a standard-library PDF text fallback
- Optional AI assist: an OpenAI-compatible API endpoint, API key, and model name supported by that endpoint

## Run

From the repository root:

```powershell
python code\main.py
```

This runs the deterministic mode without making any network calls. It defaults to `dataset\deletion_requests.csv`, reads identities, audit history, deletion policy, and evidence from `dataset\`, and writes `output.csv` at the repository root.

To use NVIDIA NIM for unresolved deletion intent, set the provider/model/endpoint in the untracked `code\.env` file and provide the key in the `NVIDIA_API_KEY` environment variable:

```powershell
$env:AI_PROVIDER = "nvidia"
$env:NVIDIA_MODEL = "openai/gpt-oss-20b"
$env:NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
$env:NVIDIA_API_KEY = Read-Host "Enter your NVIDIA API key"
python code\main.py --ai-assist --ai-provider nvidia
```

Alternatively, add only the non-secret settings below to `code\.env` (never put the API key in that file):

```text
AI_PROVIDER=nvidia
NVIDIA_MODEL=openai/gpt-oss-20b
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
```

Process environment values take precedence over `.env` values. The client targets `/chat/completions`, as shown in the provider's OpenAI-compatible API example, and does not require the optional structured `response_format` parameter. You may override the model or base URL with `--ai-model` and `--ai-base-url`; select only a model exposed to your NVIDIA account. The AI receives only ambiguous request text, with emails, phone numbers, and known identity aliases redacted. Do not put credentials in source files or commits. API/network/response errors stop the run explicitly; they do not silently fall back to a different result.

HTTP 401/403 responses include a short provider error and targeted setup checks. A 403 generally means the key is not authorized for the requested model or the model identifier is not enabled for the account.

The AI reviewer can only classify deletion intent. It does not create, remove, or rewrite evidence-backed steps. Python remains authoritative for resource matching, policy application, time cutoffs, allowed operations, ordering, and CSV/JSON serialization.

Optional paths support the public sample or another participant-facing dataset:

```powershell
python code\main.py --input dataset\sample_deletion_requests.csv --output sample_output.csv
python code\main.py --input path\to\requests.csv --dataset path\to\dataset --output path\to\output.csv
```

## Tests

```powershell
python -m unittest discover -s code\evaluation -p "test_*.py" -v
```

## Approach and limitations

The rule-based intent classifier handles clear cases locally; AI assist is limited to unresolved intent and must be explicitly enabled. The deterministic engine resolves current and historical identifiers, extracts participant evidence from JSON, SQLite-compatible SQL, structured text/logs, and PDFs, applies cutoff-aware resource state selection and the supplied policy, then emits ordered findings/remediation/verification steps. Image OCR is attempted only when a local `tesseract` executable is available.

The recorded full-dataset output was generated in deterministic mode, so it used zero model tokens and zero model cost. Update `evaluation/usage_report.md` with actual provider telemetry whenever generating predictions with AI assist enabled.
