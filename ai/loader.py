import os
import json
import logging
from typing import List, Dict, Any

import requests

OWASP_REPO_RAW = "https://raw.githubusercontent.com/OWASP/www-project-threat-model-library/main"


def list_example_models() -> List[str]:
    """Return a static list of example JSON threat models in the OWASP library.

    NOTE: The real repo may evolve; for production, you would hit the GitHub API
    to dynamically list files under `threat-models/`.
    """
    # Minimal hard-coded examples to avoid relying on GitHub API rate limits here.
    examples = [
        "threat-models/husky-ai-threat-model.json",
        "threat-models/sample-threat-model.json",
    ]
    return examples


def fetch_model(path: str) -> Dict[str, Any]:
    """Download and parse a threat model JSON from the OWASP repo.

    :param path: Relative path under the OWASP Threat Model Library repo
    :return: Parsed JSON as dict
    """
    url = f"{OWASP_REPO_RAW}/{path.lstrip('/')}"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    return resp.json()


def load_training_corpus(limit: int = 50) -> List[Dict[str, Any]]:
    """Load a small corpus of threat models for experimentation.

    This function is intentionally conservative and does not try to mirror the
    whole dataset. It gives you a starting point to build prompts or training
    examples from real-world models.
    """
    corpus: List[Dict[str, Any]] = []
    for i, rel_path in enumerate(list_example_models()):
        if i >= limit:
            break
        try:
            model = fetch_model(rel_path)
            corpus.append(model)
        except Exception as exc:  # pragma: no cover - network failures
            logging.warning("Failed to fetch %s: %s", rel_path, exc)
    return corpus


def build_instruction_examples(corpus: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Transform OWASP threat models into simple instruction-style pairs.

    Each entry roughly follows an instruction-tuning pattern:
    - input: textual description of the system, elements, and dataflows
    - output: textual summary of threats and mitigations
    """
    examples: List[Dict[str, str]] = []

    for model in corpus:
        meta = model.get("metadata", {})
        title = meta.get("title") or model.get("name", "Unnamed System")
        desc = meta.get("description") or model.get("description", "")
        elements = model.get("elements", [])
        dataflows = model.get("dataflows", [])
        threats = model.get("threats", model.get("threatModel", {}).get("threats", []))

        # Build a compact system description
        elem_summary = "; ".join(
            f"{e.get('name', 'elem')}({e.get('type', 'unknown')})" for e in elements
        )
        df_summary = "; ".join(
            f"{df.get('name', 'flow')}:{df.get('from')}->{df.get('to')}" for df in dataflows
        )

        input_text = (
            f"System: {title}\n\n"
            f"Description: {desc}\n\n"
            f"Elements: {elem_summary}\n\n"
            f"Dataflows: {df_summary}"
        )

        # Build an output text summarising threats
        threat_lines = []
        for t in threats:
            title_t = t.get("title") or t.get("name", "Threat")
            sev = t.get("severity", "Unknown")
            mitigations = t.get("mitigations") or t.get("mitigation") or []
            if isinstance(mitigations, str):
                mitigations = [mitigations]
            mit_text = "; ".join(mitigations)
            threat_lines.append(f"- [{sev}] {title_t}: {mit_text}")

        output_text = (
            "Threat analysis based on OWASP Threat Model Library data:\n" +
            "\n".join(threat_lines)
        )

        examples.append({"input": input_text, "output": output_text})

    return examples


if __name__ == "__main__":
    corpus = load_training_corpus(limit=10)
    pairs = build_instruction_examples(corpus)
    out_path = os.path.join(os.path.dirname(__file__), "training_pairs.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for ex in pairs:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Wrote {len(pairs)} training pairs to {out_path}")
