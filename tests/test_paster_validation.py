import asyncio
import tempfile
import unittest
from pathlib import Path

from database import Database, KeyStatus
from scanner import ScanResult
from validator import AsyncValidator, ValidationResult


class PasterValidationTests(unittest.TestCase):
    def test_relay_result_uses_base_url_models_and_becomes_confirmed(self):
        async def run_test():
            with tempfile.TemporaryDirectory() as folder:
                db = Database(str(Path(folder) / "test.db"))
                validator = AsyncValidator(db)
                calls = {}

                async def validate_openai(api_key, base_url):
                    calls["validate"] = (api_key, base_url)
                    return ValidationResult(
                        KeyStatus.VALID,
                        "models ok",
                        models=["model-a", "model-b"],
                    )

                async def confirm_key(api_key, base_url, models, platform=""):
                    calls["confirm"] = (api_key, base_url, models, platform)
                    return ValidationResult(
                        KeyStatus.VALID,
                        "Подтверждён: model-b",
                        models=["model-b"],
                    )

                async def no_gpt4(*args):
                    return False

                async def no_balance(*args):
                    return {"balance": 0}

                async def has_quota(*args):
                    return {"has_quota": True}

                async def no_metadata(*args):
                    return None

                validator.validate_openai = validate_openai
                validator.confirm_key = confirm_key
                validator.probe_gpt4 = no_gpt4
                validator.probe_billing = no_balance
                validator.probe_quota_by_request = has_quota
                validator._save_key_metadata = no_metadata

                key = "sk-relay-test-validation-key-1234567890"
                base_url = "https://relay.example.com/v1"
                result = ScanResult(
                    platform="relay",
                    api_key=key,
                    base_url=base_url,
                    source_url="https://paster.sh/ABC123",
                    is_relay=True,
                )

                try:
                    await validator.process_result(result)
                    self.assertEqual(
                        db.get_key_status(key), KeyStatus.CONFIRMED.value
                    )
                    self.assertEqual(calls["validate"], (key, base_url))
                    self.assertEqual(
                        calls["confirm"],
                        (key, base_url, ["model-a", "model-b"], "relay"),
                    )
                finally:
                    await validator.close()
                    db.close()

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
