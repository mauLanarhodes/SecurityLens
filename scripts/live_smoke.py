#!/usr/bin/env python3
"""Exercise the running SecurityLens stack and all three live OpenAI features.

Run after `docker compose up --build -d` with OPENAI_API_KEY set in .env.
The key is never read by this script: it is sent only by the backend.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def request(base_url, path, body=None):
    url = base_url.rstrip("/") + path
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=190) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc).get("error", exc.reason)
        except (ValueError, AttributeError):
            detail = exc.reason
        raise RuntimeError(f"{path}: HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"{path}: {exc}") from exc


def wait_until_ready(base_url, deadline, path, key, predicate):
    last_error = "service has not responded yet"
    while time.monotonic() < deadline:
        try:
            data = request(base_url, path)
            value = data.get(key)
            if predicate(value):
                return data
            last_error = f"{path} returned no {key} yet"
        except RuntimeError as exc:
            last_error = str(exc)
        time.sleep(3)
    raise RuntimeError(f"Timed out waiting for {path}: {last_error}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--model", default="gpt-6.1-sol")
    parser.add_argument("--wait-seconds", type=int, default=300)
    args = parser.parse_args()

    deadline = time.monotonic() + args.wait_seconds
    print("Waiting for the backend and a detected alert...", flush=True)
    health = wait_until_ready(args.base_url, deadline, "/api/health", "ok", bool)
    require(health.get("llm_mode") == "live", "Backend is in mock mode; set LLM_MODE=live and OPENAI_API_KEY in .env, then rebuild")
    require(health.get("llm_model") == args.model, f"Expected model {args.model}, got {health.get('llm_model')}")
    print(f"Backend ready: live {args.model}", flush=True)

    alerts = wait_until_ready(args.base_url, deadline, "/api/alerts?limit=100", "alerts", bool)["alerts"]
    alert = next((item for item in alerts if not item.get("triage")), alerts[0])
    alert_id = alert["id"]
    print(f"Using detected {alert['alert_type']} alert {alert_id}", flush=True)

    result = request(args.base_url, f"/api/alerts/{alert_id}/triage", {})["triage"]
    require(result.get("mock") is False and result.get("model") == args.model, "Triage did not use the selected live model")
    require(result.get("verdict") in {"likely_true_positive", "likely_false_positive", "needs_review"}, "Triage verdict is missing or invalid")
    require(isinstance(result.get("next_steps"), list) and result["next_steps"], "Triage next steps are empty")
    print(f"Triage OK: {result['verdict']} (cached={result.get('cached', False)})", flush=True)

    investigation = request(args.base_url, f"/api/alerts/{alert_id}/investigate", {})["investigation"]
    require(investigation.get("mock") is False and investigation.get("model") == args.model, "Investigation did not use the selected live model")
    require(investigation.get("hypothesis") and investigation.get("pivot_queries"), "Investigation is missing hypothesis or pivot queries")
    print("Investigation OK: hypothesis and pivot queries returned", flush=True)

    rule = request(args.base_url, "/api/rules/generate", {
        "description": "Flag users with more than five denied API calls within the event window."
    })
    require(rule.get("mock") is False and rule.get("model") == args.model, "Rule generation did not use the selected live model")
    require(rule.get("compile_ok") is True, f"Generated rule did not compile: {rule.get('compiler_output', '')}")
    print("Rule generation OK: live Go code passed isolated compilation", flush=True)
    print("Live OpenAI smoke check passed.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyError, TypeError, ValueError) as exc:
        print(f"Live smoke check failed: {exc}", file=sys.stderr)
        sys.exit(1)
