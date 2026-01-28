import os
from typing import List, Dict, Any

import requests


PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY")
PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"


SYSTEM_PROMPT = """You are a security architect helping to enrich application threat models.
You receive a list of threats (with titles, severity, STRIDE, and mitigations) and an
optional short description of the system / DFD.

Your job is to:
1. Summarize the overall risk picture in 3-5 concise bullet points.
2. Highlight the top 3-5 threats that deserve immediate attention and explain why.
3. Suggest any additional mitigations or architectural changes that are often missed.

Be concrete, security-focused, and avoid generic advice.
"""


def _build_user_prompt(threats: List[Dict[str, Any]], context: str | None = None) -> str:
    lines: List[str] = []

    if context:
        lines.append("System / DFD summary:")
        lines.append(context.strip())
        lines.append("")

    lines.append("Threats:")
    for t in threats:
        title = t.get("title", "Threat")
        sev = t.get("severity", "Unknown")
        stride = ",".join(t.get("stride") or [])
        element = t.get("elementName") or t.get("dataflowName") or "n/a"
        lines.append(f"- [{sev}] {title} | STRIDE={stride} | target={element}")

    return "\n".join(lines)


def enrich_threats(threats: List[Dict[str, Any]], context: str | None = None) -> str:
    """Call Perplexity to enrich a threat model with narrative guidance.

    :param threats: List of threat dicts as produced by src/threatGenerator.js
    :param context: Optional free-text summary of the system / DFD
    :return: Markdown text with summary + recommendations
    """
    if not PERPLEXITY_API_KEY:
        raise RuntimeError("PERPLEXITY_API_KEY environment variable is not set")

    if not threats:
        return "No threats provided. Nothing to enrich."

    headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "sonar-pro",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(threats, context)},
        ],
        "temperature": 0.2,
    }

    resp = requests.post(PERPLEXITY_API_URL, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    # Standard OpenAI-like shape: choices[0].message.content
    try:
        return data["choices"][0]["message"]["content"]
    except Exception:  # pragma: no cover - defensive
        return str(data)


if __name__ == "__main__":  # Manual quick test
    demo_threats = [
        {
            "title": "Man-in-the-Middle Attack",
            "severity": "Critical",
            "stride": ["Tampering", "Information Disclosure"],
            "elementName": "Public API",
        },
        {
            "title": "SQL Injection",
            "severity": "Critical",
            "stride": ["Tampering"],
            "elementName": "Orders Database",
        },
    ]
    print(enrich_threats(demo_threats, context="Multi-tenant SaaS platform handling payment data."))
