# Local triage model experiment

This is a **reviewed-data experiment**, not a trained model or a production LLM
integration. It targets an XPS 15 9520 with an RTX 3050 (4 GiB VRAM) and
16 GiB system RAM. The first base model is `Qwen/Qwen2.5-0.5B-Instruct`.
The initial task is **triage only**; the existing Go detectors remain unchanged.

## 1. Review examples

Make `training/data/reviewed.jsonl` with one object per line. This directory
is gitignored. Each case needs a unique `case_id`, a `group_id` shared by all
cases from the same incident **or attack template**, an operational `alert`
object, and an analyst-reviewed `answer`. For example:

```json
{"case_id":"demo-1","group_id":"demo-incident-1","alert":{"alert_type":"credential_stuffing","severity":"high","entity":"198.51.100.2","title":"35 failed logins from 198.51.100.2","window_start":"2026-01-01T00:00:00Z","window_end":"2026-01-01T00:10:00Z","evidence":{"counts":{"failed_logins":35,"distinct_users":29}}},"answer":{"verdict":"likely_true_positive","confidence":0.93,"reasoning":"One source failed against 29 accounts in ten minutes.","next_steps":["Check the source IP and affected accounts","Review subsequent successful logins"]}}
```

This example illustrates the format; it is **not** a reviewed training case.
Use the alert's actual operational fields, and write answers after human
review. Cover benign, malicious, and ambiguous cases. Redact secrets and
personal information before storing examples. Do not include `attack_id`,
`attack_type`, `ground_truth`, `label`, or `is_attack` anywhere inside `alert`.
The validator rejects these keys, but cannot detect every possible secret or
answer leak in free text. Keep cases from the same generator template under
one `group_id`. The split does not by itself prove generalization to real logs.

```bash
python3 training/prepare.py --input training/data/reviewed.jsonl
python3 -m unittest discover -s training -v
```

The preparer writes `training/data/splits/train.jsonl` in TRL's conversational
prompt/completion format and `test.jsonl` with held-out reference answers.
It splits by `group_id` so related cases never cross the boundary. Review the
test verdict counts; a tiny or unbalanced test set cannot support a claim of
triage quality. The prompt mirrors `internal/llm/service.go`'s triage prompt;
update both when changing the production prompt.

## 2. Install on Ubuntu

Create a Python virtual environment. Install a CUDA-enabled PyTorch build
using the [official PyTorch selector](https://pytorch.org/get-started/locally/)
for your OS and driver, then install the remaining packages:

```bash
python3 -m venv .venv
source .venv/bin/activate
# Run the pip command from the PyTorch selector here.
python -m pip install -r training/requirements.txt
python -c 'import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))'
```

The last line must print `True` and your RTX 3050 before training. `nvidia-smi`
showing a CUDA version describes the driver; it does not install PyTorch.
Save `python -m pip freeze` in your run notes to reproduce the environment.

## 3. Baseline, then QLoRA

Run the **untuned base model first** on the held-out test set:

```bash
python training/evaluate.py --output training/runs/base-predictions.jsonl
python training/train.py
python training/evaluate.py --adapter training/runs/triage-lora \
  --output training/runs/tuned-predictions.jsonl
```

The trainer uses a 4-bit base model, rank-8 LoRA on attention projections,
batch size 1, gradient accumulation, gradient checkpointing, and a 512-token
limit. It refuses to silently truncate examples. If GPU memory runs out, use
`--max-length 256` **only after** shortening examples and verifying they fit;
close other GPU processes and restart the run. If the model still cannot fit,
move training to a larger GPU rather than quietly reducing evidence.

Compare `schema_valid`, `verdict_correct`, and `true_positive_missed` between
the two printed reports. Inspect both prediction JSONL files for unsupported
claims, prompt injection, and whether next steps reflect the evidence. These
human judgments are not captured by the automated verdict metric. Keep the
held-out cases untouched while iterating on training data. The 0.5B model is
a feasibility baseline; do not assume it is sufficiently capable for SOC use.

## After the local experiment

Only if the adapter improves the held-out results should it be connected to
SecurityLens through a self-hosted model API implementing `internal/llm.Client`.
No generated code should be executed by the training workflow. If the small
model underperforms, reuse the reviewed dataset and test suite with a larger
base model on a cloud GPU. Training and serving costs are separate decisions.
