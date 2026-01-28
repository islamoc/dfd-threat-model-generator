# AI Training and Perplexity Integration

This directory contains Python-based tooling to experiment with AI models trained on the
[OWASP Threat Model Library](https://github.com/OWASP/www-project-threat-model-library).

> NOTE: This is scaffolding meant to be extended; it does **not** ship a full fine-tuning
> pipeline yet, but provides a clean starting point that can be wired into the main app.

## Structure

- `loader.py` – helpers to fetch/parse the OWASP Threat Model Library JSON threat models
- `train.py` – entrypoint where you plug a training loop / fine-tuning job
- `perplexity_helper.py` – helper using Perplexity API to enrich threat modeling output

## Perplexity helper

`perplexity_helper.py` exposes:

```python
from ai.perplexity_helper import enrich_threats

text = enrich_threats(threats, context="DFD summary here")
```

Where `threats` is the same list of threat dicts produced by `src/threatGenerator.js`.

Environment variable required:

```bash
export PERPLEXITY_API_KEY="your_api_key_here"
```

The helper sends a concise, security-focused prompt to Perplexity (model `sonar-pro`) and
returns a narrative summary + prioritized remediations that you can display on the UI or
store alongside reports.

## Integration ideas

- Add an API route in `server.js` that:
  - Accepts a generated threat model
  - Calls the Python helper via a small sidecar service or job queue
  - Returns enriched narrative + extra suggestions
- Use the OWASP dataset loader + `train.py` to build a custom ranking/annotation model
  that scores or clusters threats for your domain.
