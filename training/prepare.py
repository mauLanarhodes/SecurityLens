"""Validate reviewed triage cases and split by incident group without leakage."""

import argparse
import json
import random
from collections import Counter
from datetime import datetime
from pathlib import Path

VERDICTS = {"likely_true_positive", "likely_false_positive", "needs_review"}
ALERT_FIELDS = ("alert_type", "severity", "entity", "title", "window_start", "window_end", "evidence")
FORBIDDEN_KEYS = {"attack_id", "attack_type", "ground_truth", "is_attack", "label"}


def validate_answer(answer):
    if not isinstance(answer, dict):
        raise ValueError("answer must be an object")
    if answer.get("verdict") not in VERDICTS:
        raise ValueError("answer.verdict must match SecurityLens's triage enum")
    confidence = answer.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError("answer.confidence must be a number in [0, 1]")
    if not isinstance(answer.get("reasoning"), str) or not answer["reasoning"].strip():
        raise ValueError("answer.reasoning must be nonempty")
    steps = answer.get("next_steps")
    if not isinstance(steps, list) or not steps or any(not isinstance(s, str) or not s.strip() for s in steps):
        raise ValueError("answer.next_steps must contain nonempty strings")
    return {key: answer[key] for key in ("verdict", "confidence", "reasoning", "next_steps")}


def check_no_labels(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise ValueError(f"ground-truth key {key!r} is forbidden in alert input")
            check_no_labels(child)
    elif isinstance(value, list):
        for child in value:
            check_no_labels(child)


def render_prompt(alert):
    if not isinstance(alert, dict) or any(field not in alert for field in ALERT_FIELDS):
        raise ValueError(f"alert needs fields: {', '.join(ALERT_FIELDS)}")
    for field in ALERT_FIELDS[:-1]:
        if not isinstance(alert[field], str) or not alert[field].strip():
            raise ValueError(f"alert.{field} must be nonempty text")
    window = {}
    for field in ("window_start", "window_end"):
        parsed = datetime.fromisoformat(alert[field].replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError(f"alert.{field} needs a timezone")
        # Go's time.RFC3339 rendering omits fractional seconds.
        window[field] = parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
    check_no_labels(alert)
    evidence = json.dumps(alert["evidence"], ensure_ascii=False, separators=(",", ":"))
    # Keep this synchronized with internal/llm/service.go Triage's prompt.
    return ("TASK: triage\n\n"
            "You are a senior SOC analyst triaging one alert. Assess whether it is a true\n"
            "positive and what to do next.\n\n"
            "ALERT:\n"
            f"  type: {alert['alert_type']}\n"
            f"  severity: {alert['severity']}\n"
            f"  entity: {alert['entity']}\n"
            f"  title: {alert['title']}\n"
            f"  window: {window['window_start']} .. {window['window_end']}\n"
            f"  evidence: {evidence}\n\n"
            "Respond with ONLY a JSON object:\n"
            '{"verdict": "likely_true_positive"|"likely_false_positive"|"needs_review",\n'
            ' "confidence": 0.0-1.0,\n'
            ' "reasoning": "...",\n'
            ' "next_steps": ["...", "..."]}')


def read_cases(path):
    cases, ids = [], set()
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                case = json.loads(line)
                for key in ("case_id", "group_id"):
                    if not isinstance(case.get(key), str) or not case[key].strip():
                        raise ValueError(f"{key} must be nonempty text")
                if case["case_id"] in ids:
                    raise ValueError("duplicate case_id")
                ids.add(case["case_id"])
                prompt = render_prompt(case["alert"])
                answer = validate_answer(case["answer"])
                cases.append({"case_id": case["case_id"], "group_id": case["group_id"],
                              "prompt": [{"role": "user", "content": prompt}], "answer": answer})
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    if len({c["group_id"] for c in cases}) < 2:
        raise ValueError("at least two incident groups are needed for a held-out split")
    return cases


def split_cases(cases, fraction, seed):
    if not 0 < fraction < 1:
        raise ValueError("test fraction must be between 0 and 1")
    groups = sorted({c["group_id"] for c in cases})
    random.Random(seed).shuffle(groups)
    n_test = max(1, min(len(groups) - 1, round(len(groups) * fraction)))
    test_groups = set(groups[:n_test])
    return ([c for c in cases if c["group_id"] not in test_groups],
            [c for c in cases if c["group_id"] in test_groups])


def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="analyst-reviewed JSONL")
    parser.add_argument("--out", type=Path, default=Path("training/data/splits"))
    parser.add_argument("--test-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    cases = read_cases(args.input)
    train, test = split_cases(cases, args.test_fraction, args.seed)
    args.out.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out / "train.jsonl", [
        {"prompt": c["prompt"], "completion": [{"role": "assistant", "content": json.dumps(c["answer"], ensure_ascii=False)}]}
        for c in train])
    write_jsonl(args.out / "test.jsonl", test)
    print(f"train: {len(train)} cases; test: {len(test)} cases; "
          f"groups: {len(set(c['group_id'] for c in train))}/{len(set(c['group_id'] for c in test))}")
    print("test verdicts:", dict(Counter(c["answer"]["verdict"] for c in test)))


if __name__ == "__main__":
    main()
