from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class AIIntentReviewer:
    def __init__(self, model: str | None = None, base_url: str | None = None,
                 provider: str | None = None, timeout: float = 45):
        load_env_file(Path(__file__).resolve().with_name(".env"))
        self.provider = (provider or os.environ.get("AI_PROVIDER", "openai")).strip().casefold()
        if self.provider == "nvidia":
            key_name, model_name, base_url_name = "NVIDIA_API_KEY", "NVIDIA_MODEL", "NVIDIA_BASE_URL"
            default_base_url = "https://integrate.api.nvidia.com/v1"
        elif self.provider == "openai":
            key_name, model_name, base_url_name = "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL"
            default_base_url = "https://api.openai.com/v1"
        else:
            raise ValueError("AI_PROVIDER must be either 'openai' or 'nvidia'.")
        self.key_name = key_name
        self.model_name = model_name
        self.base_url_name = base_url_name
        self.api_key = os.environ.get(key_name, "").strip()
        self.model = (model or os.environ.get(model_name, "")).strip()
        self.base_url = (base_url or os.environ.get(base_url_name, default_base_url)).rstrip("/")
        self.timeout = timeout
        if not self.api_key:
            raise ValueError(f"AI assist with provider '{self.provider}' requires {key_name}.")
        if not self.model:
            raise ValueError(f"AI assist with provider '{self.provider}' requires {model_name}.")

    def classify_deletion_intent(self, request_text: str, identifiers: set[str]) -> bool:
        safe_text = redact_identifiers(request_text, identifiers)
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Classify whether the user explicitly authorizes deletion or erasure of their account "
                        "or personal data. A request only for access, export, correction, marketing opt-out, "
                        "or help is not authorization. Distinguish negation and quoted/hypothetical requests. "
                        'Return only JSON: {"deletion_authorized": boolean}.'
                    ),
                },
                {"role": "user", "content": safe_text},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result: Any = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = read_error_detail(error, self.api_key)
            if error.code in {401, 403}:
                hint = (
                    f" Verify that {self.key_name} is active and authorized for this model, and that the model "
                    f"identifier is enabled for your {self.provider} account."
                )
            elif error.code == 404:
                hint = f" Verify {self.base_url_name} and that the requested model is available."
            else:
                hint = ""
            suffix = f" Provider response: {detail}" if detail else ""
            raise RuntimeError(
                f"AI intent review failed with HTTP {error.code}.{hint}{suffix}"
            ) from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RuntimeError(f"AI intent review failed: {error}") from error
        try:
            content = result["choices"][0]["message"]["content"]
            decision = json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            raise RuntimeError("AI intent review returned an invalid JSON response.") from error
        authorized = decision.get("deletion_authorized")
        if not isinstance(authorized, bool):
            raise RuntimeError("AI intent review omitted the boolean deletion_authorized field.")
        return authorized


def read_error_detail(error: urllib.error.HTTPError, secret: str) -> str:
    try:
        body = error.read(2048).decode("utf-8", "replace").strip()
    except OSError:
        return ""
    if not body:
        return ""
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            error_value = parsed.get("error", parsed)
            if isinstance(error_value, dict):
                body = str(error_value.get("message") or error_value.get("detail") or error_value)
            else:
                body = str(error_value)
    except json.JSONDecodeError:
        pass
    if secret:
        body = body.replace(secret, "[REDACTED]")
    return re.sub(r"\s+", " ", body)[:500]


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        if candidate.startswith("export "):
            candidate = candidate[7:].lstrip()
        name, separator, value = candidate.partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(name, value)


def redact_identifiers(text: str, identifiers: set[str]) -> str:
    redacted = re.sub(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "[REDACTED_IDENTIFIER]",
        text,
    )
    redacted = re.sub(r"(?<!\w)\+?\d[\d ().-]{6,}\d(?!\w)", "[REDACTED_IDENTIFIER]", redacted)
    for identifier in sorted(identifiers, key=len, reverse=True):
        if len(identifier) >= 4:
            redacted = re.sub(re.escape(identifier), "[REDACTED_IDENTIFIER]", redacted, flags=re.IGNORECASE)
    return redacted
