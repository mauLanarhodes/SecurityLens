"""Score base or adapted triage model on the held-out cases."""

import argparse
import json
import time
from pathlib import Path

from prepare import validate_answer


def parse_prediction(text):
    decoder = json.JSONDecoder()
    try:
        parsed, _ = decoder.raw_decode(text[text.index("{"):])
        return validate_answer(parsed)
    except (ValueError, TypeError):
        return None


def score_predictions(rows):
    total = len(rows)
    valid = [r for r in rows if r["prediction"] is not None]
    correct = sum(r["prediction"]["verdict"] == r["expected"]["verdict"] for r in valid)
    positives = [r for r in rows if r["expected"]["verdict"] == "likely_true_positive"]
    missed = sum(r["prediction"] is None or r["prediction"]["verdict"] != "likely_true_positive"
                 for r in positives)
    return {"cases": total, "schema_valid": len(valid), "verdict_correct": correct,
            "true_positive_cases": len(positives), "true_positive_missed": missed,
            "mean_latency_seconds": round(sum(r["latency_seconds"] for r in rows) / total, 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", type=Path, default=Path("training/data/splits/test.jsonl"))
    parser.add_argument("--model", default="Qwen/Qwen2.5-0.5B-Instruct")
    parser.add_argument("--adapter", type=Path, help="omit for the untuned baseline")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-new-tokens", type=int, default=256)
    args = parser.parse_args()

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    if not torch.cuda.is_available():
        raise SystemExit("Evaluation requires an NVIDIA GPU and a CUDA-enabled PyTorch install.")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForCausalLM.from_pretrained(
        args.model, device_map={"": 0}, torch_dtype=torch.float16,
        quantization_config=BitsAndBytesConfig(load_in_4bit=True,
            bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16))
    if args.adapter:
        model = PeftModel.from_pretrained(model, str(args.adapter))
    model.eval()

    results = []
    with args.test.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            case = json.loads(line)
            inputs = tokenizer.apply_chat_template(case["prompt"], tokenize=True,
                add_generation_prompt=True, return_tensors="pt").to("cuda")
            start = time.perf_counter()
            with torch.inference_mode():
                output = model.generate(inputs, max_new_tokens=args.max_new_tokens,
                    do_sample=False, pad_token_id=tokenizer.eos_token_id)
            seconds = time.perf_counter() - start
            text = tokenizer.decode(output[0, inputs.shape[-1]:], skip_special_tokens=True)
            results.append({"case_id": case["case_id"], "group_id": case["group_id"],
                            "expected": case["answer"], "prediction": parse_prediction(text),
                            "raw_output": text, "latency_seconds": round(seconds, 3)})
    if not results:
        raise SystemExit("No held-out cases found")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        for row in results:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps(score_predictions(results), indent=2))
    print(f"Review every prediction and unsupported claim in {args.output}")


if __name__ == "__main__":
    main()
