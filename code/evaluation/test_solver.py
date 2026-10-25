from __future__ import annotations

import sys
import unittest
import os
import json
import tempfile
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main
from ai_agent import AIIntentReviewer, load_env_file


class SolverBehaviorTests(unittest.TestCase):
    def test_marketing_opt_out_is_not_deletion(self):
        self.assertFalse(main.is_authorized("Please remove me from marketing lists only. I still want receipts."))
        self.assertTrue(main.is_explicitly_non_deletion(
            "Please remove me from marketing lists only. I still want receipts."
        ))

    def test_japanese_account_deletion_is_authorized(self):
        self.assertTrue(main.is_authorized("このアカウントを削除してください"))

    def test_ai_intent_reviewer_sends_redacted_text_and_parses_boolean(self):
        response = BytesIO(
            b'{"choices":[{"message":{"content":"{\\"deletion_authorized\\":true}"}}]}'
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key", "OPENAI_MODEL": "test-model"}), \
             patch("ai_agent.load_env_file"), \
             patch("urllib.request.urlopen", return_value=response) as open_url:
            reviewer = AIIntentReviewer()
            self.assertTrue(reviewer.classify_deletion_intent(
                "Please erase my account at user@example.test",
                {"user@example.test"},
            ))
        request = open_url.call_args.args[0]
        self.assertNotIn(b"user@example.test", request.data)
        self.assertIn(b"[REDACTED_IDENTIFIER]", request.data)

    def test_nvidia_configuration_uses_nvidia_endpoint_and_model(self):
        response = BytesIO(
            b'{"choices":[{"message":{"content":"{\\"deletion_authorized\\":false}"}}]}'
        )
        with patch.dict(os.environ, {
            "AI_PROVIDER": "nvidia",
            "NVIDIA_API_KEY": "nvidia-test-key",
            "NVIDIA_MODEL": "openai/gpt-oss-20b",
        }, clear=True), patch("ai_agent.load_env_file"), \
             patch("urllib.request.urlopen", return_value=response) as open_url:
            reviewer = AIIntentReviewer()
            self.assertFalse(reviewer.classify_deletion_intent("Please send me a copy.", set()))
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "https://integrate.api.nvidia.com/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer nvidia-test-key")
        payload = json.loads(request.data)
        self.assertEqual(payload["model"], "openai/gpt-oss-20b")
        self.assertNotIn("response_format", payload)

    def test_ai_intent_reviewer_requires_model_and_api_key(self):
        with patch.dict(os.environ, {}, clear=True), patch("ai_agent.load_env_file"):
            with self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"):
                AIIntentReviewer()
            with self.assertRaisesRegex(ValueError, "NVIDIA_API_KEY"):
                AIIntentReviewer(provider="nvidia")

    def test_dotenv_loader_preserves_environment_and_reads_local_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            env_path.write_text(
                "OPENAI_API_KEY=local-secret\n"
                "OPENAI_MODEL='gpt-test'\n"
                "OPENAI_BASE_URL=https://cleanapis.com/v1\n"
                "NOT_A_VALID_LINE\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"OPENAI_API_KEY": "process-secret"}, clear=True):
                load_env_file(env_path)
                self.assertEqual(os.environ["OPENAI_API_KEY"], "process-secret")
                self.assertEqual(os.environ["OPENAI_MODEL"], "gpt-test")
                self.assertEqual(os.environ["OPENAI_BASE_URL"], "https://cleanapis.com/v1")

    def test_forbidden_provider_response_explains_model_and_key_checks(self):
        error = HTTPError(
            "https://cleanapis.com/v1/chat/completions",
            403,
            "Forbidden",
            {},
            BytesIO(b'{"error":{"message":"model access denied"}}'),
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-secret", "OPENAI_MODEL": "test-model"}), \
             patch("ai_agent.load_env_file"), \
             patch("urllib.request.urlopen", side_effect=error):
            reviewer = AIIntentReviewer()
            with self.assertRaisesRegex(RuntimeError, "HTTP 403") as caught:
                reviewer.classify_deletion_intent("Delete my account.", set())
        message = str(caught.exception)
        self.assertIn("model identifier is enabled", message)
        self.assertIn("model access denied", message)
        self.assertNotIn("test-secret", message)

    def test_latest_absence_supersedes_older_present_record(self):
        old = main.Observation("evidence_a", datetime(2026, 9, 1, tzinfo=timezone.utc), "account_service",
                              "account_100", "USER_PROFILE", {"email": "a@example.test"}, "", "json")
        newer = main.Observation("evidence_b", datetime(2026, 9, 2, tzinfo=timezone.utc), "account_service",
                                "account_100", "USER_PROFILE", {"status_code": 404}, "", "absence")
        self.assertEqual(main.effective_observations([old], [newer]), [])

    def test_active_connector_gets_disable_and_verification_plan(self):
        active = main.Observation("evidence_flow", datetime(2026, 9, 2, tzinfo=timezone.utc), "integration_service",
                                  "data_flow_42", "DATA_FLOW", {"enabled": True}, "", "json")
        findings, plan = main.violation_plan([active], {"user_42"}, set(), "user_42")
        self.assertEqual([step["operation"] for step in findings], ["REPORT_ACTIVE_DATA_FLOW"])
        self.assertEqual({step["operation"] for step in plan}, {"DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"})

    def test_tombstone_direct_identifiers_require_redaction(self):
        tombstone = main.Observation("evidence_tombstone", datetime(2026, 9, 2, tzinfo=timezone.utc), "account_service",
                                     "account_42", "ACCOUNT_TOMBSTONE",
                                     {"user_id": "user_42", "email": "person@example.test"}, "", "json")
        findings, plan = main.violation_plan([tombstone], {"user_42", "person@example.test"}, set(), "user_42")
        self.assertEqual([step["operation"] for step in findings], ["REPORT_EXPOSED_PII"])
        self.assertIn("REDACT_RECORD", {step["operation"] for step in plan})
        self.assertIn("VERIFY_RECORD_REDACTED", {step["operation"] for step in plan})


if __name__ == "__main__":
    unittest.main()
