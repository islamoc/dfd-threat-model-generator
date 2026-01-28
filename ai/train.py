import argparse
from pathlib import Path

from ai.loader import load_training_corpus, build_instruction_examples


def main(limit: int, out: str) -> None:
    print(f"Loading up to {limit} threat models from OWASP Threat Model Library...")
    corpus = load_training_corpus(limit=limit)
    print(f"Loaded {len(corpus)} raw models")

    print("Building instruction-style training pairs...")
    pairs = build_instruction_examples(corpus)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        for ex in pairs:
            f.write(ex["input"].replace("\n", " ") + "\t" + ex["output"].replace("\n", " ") + "\n")

    print(f"Wrote {len(pairs)} pairs to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare OWASP threat model data for AI training")
    parser.add_argument("--limit", type=int, default=50, help="Max number of threat models to load")
    parser.add_argument("--out", type=str, default="ai/out/pairs.tsv", help="Output TSV file path")

    args = parser.parse_args()
    main(limit=args.limit, out=args.out)
