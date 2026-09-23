import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from evaluate import parse_prediction, score_predictions
from prepare import read_cases, split_cases


def sample(case_id, group_id, verdict="likely_true_positive"):
    return {"case_id": case_id, "group_id": group_id,
            "alert": {"alert_type": "credential_stuffing", "severity": "high",
                      "entity": "198.51.100.1", "title": "Failed logins",
                      "window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:10:00Z",
                      "evidence": {"counts": {"failed_logins": 35}}},
            "answer": {"verdict": verdict, "confidence": 0.9,
                       "reasoning": "35 failures in ten minutes", "next_steps": ["Review source"]}}


class WorkflowTests(unittest.TestCase):
    def test_prepare_cli_writes_compatible_splits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reviewed.jsonl"
            out = Path(tmp) / "splits"
            path.write_text("\n".join(json.dumps(sample(str(i), f"incident-{i}")) for i in range(3)),
                            encoding="utf-8")
            subprocess.run([sys.executable, str(Path(__file__).with_name("prepare.py")),
                            "--input", str(path), "--out", str(out)], check=True, capture_output=True)
            train = [json.loads(line) for line in (out / "train.jsonl").read_text().splitlines()]
            test = [json.loads(line) for line in (out / "test.jsonl").read_text().splitlines()]
            self.assertEqual(len(train) + len(test), 3)
            self.assertEqual(train[0]["completion"][0]["role"], "assistant")
            self.assertIn("answer", test[0])

    def test_split_keeps_incidents_together_and_hides_labels(self):
        examples = [sample("a", "incident-1"), sample("b", "incident-1"),
                    sample("c", "incident-2", "needs_review")]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reviewed.jsonl"
            path.write_text("\n".join(json.dumps(e) for e in examples), encoding="utf-8")
            cases = read_cases(path)
        train, test = split_cases(cases, 0.5, 42)
        self.assertFalse({c["group_id"] for c in train} & {c["group_id"] for c in test})
        self.assertEqual(len(train) + len(test), 3)
        self.assertNotIn("incident-", cases[0]["prompt"][0]["content"])
        self.assertIn("35", cases[0]["prompt"][0]["content"])

    def test_rejects_ground_truth_in_input(self):
        example = sample("a", "incident-1")
        example["alert"]["evidence"]["attack_id"] = "answer-leak"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reviewed.jsonl"
            path.write_text(json.dumps(example), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ground-truth key"):
                read_cases(path)

    def test_invalid_output_is_counted_as_missed(self):
        answer = sample("a", "one")["answer"]
        self.assertIsNone(parse_prediction("not JSON"))
        self.assertIsNone(parse_prediction('{"verdict":"fake","confidence":1}'))
        rows = [{"expected": answer, "prediction": None, "latency_seconds": 1.0}]
        self.assertEqual(score_predictions(rows)["true_positive_missed"], 1)


if __name__ == "__main__":
    unittest.main()
