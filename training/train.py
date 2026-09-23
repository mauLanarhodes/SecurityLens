"""Train a small triage LoRA adapter; defaults target a 4 GB NVIDIA GPU."""

import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, default=Path("training/data/splits/train.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("training/runs/triage-lora"))
    parser.add_argument("--model", default="Qwen/Qwen2.5-0.5B-Instruct")
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--epochs", type=float, default=2)
    args = parser.parse_args()

    import torch
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from trl import SFTConfig, SFTTrainer

    if not torch.cuda.is_available():
        raise SystemExit("This QLoRA run requires an NVIDIA GPU. Check nvidia-smi and the PyTorch CUDA install.")
    if args.max_length < 128:
        raise SystemExit("--max-length must be at least 128")
    dataset = load_dataset("json", data_files=str(args.train), split="train")
    if len(dataset) == 0:
        raise SystemExit("The training split is empty. Run prepare.py first.")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    # Never silently truncate an analyst's verdict or the attack evidence.
    too_long = [i for i, row in enumerate(dataset) if len(tokenizer.apply_chat_template(
        row["prompt"] + row["completion"], tokenize=True)) > args.max_length]
    if too_long:
        raise SystemExit(f"{len(too_long)} examples exceed {args.max_length} tokens "
                         f"(first row {too_long[0]}). Shorten them or increase --max-length if VRAM allows.")

    model = AutoModelForCausalLM.from_pretrained(
        args.model, device_map={"": 0}, torch_dtype=torch.float16,
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True))
    model.config.use_cache = False
    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset,
        peft_config=LoraConfig(
            r=8, lora_alpha=16, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
            target_modules=["q_proj", "v_proj"]),
        args=SFTConfig(
            output_dir=str(args.output), max_length=args.max_length,
            completion_only_loss=True, per_device_train_batch_size=1,
            gradient_accumulation_steps=8, gradient_checkpointing=True,
            gradient_checkpointing_kwargs={"use_reentrant": False},
            learning_rate=1e-4, num_train_epochs=args.epochs,
            fp16=True, bf16=False, packing=False, report_to="none",
            save_strategy="epoch", logging_steps=10, seed=42,
            optim="paged_adamw_8bit"))
    trainer.train()
    trainer.save_model(str(args.output))
    tokenizer.save_pretrained(str(args.output))
    print(f"Saved adapter to {args.output}; run evaluate.py on the held-out split.")


if __name__ == "__main__":
    main()
