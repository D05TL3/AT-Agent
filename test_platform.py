from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from harness.blackboard import Blackboard
from harness.controller import Controller, Evidence, FlagResult
from harness.platform import Platform, TaskSpec


class StubPlatform(Platform):
    def __init__(self, responses: list[object] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[str, str, dict | None]] = []
        super().__init__()

    def _request(self, method: str, path: str, body: dict | None = None):
        self.calls.append((method, path, body))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class PlatformTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "BENCHMARK_BASE_URL": "https://benchmark.example",
                "BENCHMARK_TOKEN": "not-a-real-token",
                "OUTPUT_DIR": self.tempdir.name,
            },
        )
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()
        self.tempdir.cleanup()

    def test_load_tasks_maps_benchmark_fields(self) -> None:
        platform = StubPlatform(
            [
                [
                    {
                        "unique_code": "web_injection_01",
                        "description": "test task",
                        "total_score": 100,
                        "flag_count": 2,
                        "correct_flag_count": 1,
                        "is_completed": False,
                        "container_status": "stopped",
                        "container_addr": [],
                    }
                ]
            ]
        )

        tasks = platform.load_tasks()

        self.assertEqual(tasks[0].id, "web_injection_01")
        self.assertEqual(tasks[0].category, "web")
        self.assertEqual(tasks[0].points, 100)
        self.assertEqual(tasks[0].flag_count, 2)
        self.assertEqual(tasks[0].correct_flag_count, 1)
        self.assertEqual(platform.calls[0], ("GET", "/openapi/v1/challenges", None))

    def test_start_and_close_use_unique_code_contract(self) -> None:
        platform = StubPlatform(
            [
                {"unique_code": "web_injection_01", "container_addr": ["10.1.0.2:8080"]},
                {"unique_code": "web_injection_01", "closed": True},
            ]
        )
        platform._tasks["web_injection_01"] = TaskSpec(id="web_injection_01")

        addresses = platform.start_task("web_injection_01")
        self.assertEqual(addresses, ["10.1.0.2:8080"])
        self.assertEqual(platform._tasks["web_injection_01"].target, "10.1.0.2:8080")
        self.assertTrue(platform.close_task("web_injection_01"))
        self.assertEqual(platform.calls[0][0:2], (
            "POST", "/openapi/v1/challenges/start?unique_code=web_injection_01"
        ))
        self.assertEqual(platform.calls[1][0:2], (
            "POST", "/openapi/v1/challenges/close?unique_code=web_injection_01"
        ))
        self.assertFalse(platform._active)

    def test_submit_uses_unique_code_and_tracks_multiple_flags(self) -> None:
        platform = StubPlatform(
            [
                {
                    "correct": True,
                    "awarded": 25,
                    "correct_flag_count": 1,
                    "total_flag_count": 2,
                },
                {
                    "correct": True,
                    "awarded": 25,
                    "correct_flag_count": 2,
                    "total_flag_count": 2,
                },
            ]
        )
        platform._tasks["web_injection_01"] = TaskSpec(id="web_injection_01", flag_count=2)

        first = platform.submit_flag("web_injection_01", "flag{first_value}")
        second = platform.submit_flag("web_injection_01", "flag{second_value}")

        self.assertTrue(first.accepted)
        self.assertFalse(first.completed)
        self.assertTrue(second.accepted)
        self.assertTrue(second.completed)
        self.assertEqual(platform.calls[0][2], {
            "unique_code": "web_injection_01", "flag": "flag{first_value}"
        })

    def test_api_request_sends_benchmark_token_without_bearer(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"[]"

        platform = Platform()
        with patch("harness.platform.urllib.request.urlopen", return_value=Response()) as urlopen:
            self.assertEqual(platform._request("GET", "/openapi/v1/challenges"), [])

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Benchmark_token"), "not-a-real-token")
        self.assertIsNone(request.get_header("Authorization"))

    def test_controller_waits_for_all_flags(self) -> None:
        bb = Blackboard()
        bb.add_task("web_injection_01", "web")
        bb.set_task("web_injection_01", stage=3, status="active")
        results = iter(
            [
                FlagResult(True, False, 1, 2, "flag 正确"),
                FlagResult(True, True, 2, 2, "flag 正确"),
            ]
        )
        controller = Controller(bb, verifier=lambda _task, _flag: next(results))

        first = controller.judge(
            "web_injection_01",
            Evidence("flag", "verifier", flag="flag{first_value}"),
        )
        self.assertTrue(first.accepted)
        self.assertFalse(first.solved)
        self.assertEqual(bb.task("web_injection_01").status, "active")

        second = controller.judge(
            "web_injection_01",
            Evidence("flag", "verifier", flag="flag{second_value}"),
        )
        self.assertTrue(second.solved)
        self.assertEqual(bb.task("web_injection_01").status, "solved")
        bb.db.close()


if __name__ == "__main__":
    unittest.main()
