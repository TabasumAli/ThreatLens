# ThreatLens 🔎

**ThreatLens** is an AI-powered threat-intelligence assistant. Give it an IP
address, domain, or URL, and it enriches the indicator via the
[VirusTotal](https://www.virustotal.com/) API, then generates a
plain-language risk explanation using the [Groq](https://groq.com/) LLM API —
tailored to your stated knowledge level (Beginner / Intermediate / Expert).

## Features

- Look up **IP addresses, domains, or URLs** against VirusTotal's v3 API
- Get a structured summary: verdict, malicious/suspicious/harmless/undetected
  vote counts, and key metadata
- Get an **AI-generated explanation** of the risk, written at your chosen
  complexity level
- Graceful error handling — missing/invalid keys, indicator not found, rate
  limits, and LLM failures are all handled without crashing the app
- Built around an extensible **registry pattern** — new intel sources or LLM
  providers can be added with minimal changes to existing code (see
  `sources.py` for details)

## How it works

1. Enter your **Groq API key** and **VirusTotal API key** in the sidebar
   (both are required, and are used only for the duration of your session —
   never stored, logged, or sent anywhere but the respective official APIs).
2. Choose the indicator type (IP / Domain / URL) and your knowledge level.
3. Enter the indicator value and click **Analyze**.
4. ThreatLens queries VirusTotal, normalizes the response, and asks Groq to
   explain the result in plain language matched to your knowledge level.

## Getting API keys

- **VirusTotal**: sign up free at [virustotal.com](https://www.virustotal.com/)
  and grab your API key from your account settings.
- **Groq**: sign up free at [console.groq.com](https://console.groq.com/) and
  create an API key.

## Project structure

```
threatlens/
├── app.py            # Streamlit UI + orchestration only — no business logic
├── sources.py         # All external integrations + extensibility framework
├── requirements.txt   # Pinned dependencies
├── .gitignore         # Excludes caches, venvs, and local secrets
└── README.md          # This file
```

- `app.py` owns the Streamlit UI and never talks to an external API directly.
- `sources.py` owns all external integrations (VirusTotal, Groq) behind a
  common `IntelSource` interface and a `SOURCE_REGISTRY`, so a new source
  (e.g. AbuseIPDB, Shodan) can be dropped in with one registration line and
  zero changes to existing code.

## Running locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL Streamlit prints (usually `http://localhost:8501`).

## Deploying

This app is deployable as-is on [Streamlit Community Cloud](https://share.streamlit.io/):
point it at this repo, set the main file path to `app.py`, and deploy.
No secrets need to be configured — users supply their own API keys in the
sidebar at runtime.

### Known deployment issue (blank page)

Streamlit Community Cloud currently defaults some environments to Python
3.14.x, which has a confirmed platform-level incompatibility with newer
Streamlit/Starlette releases — the app fails to start (blank white page)
before any of your code even runs. If you hit this, pin Streamlit to a
pre-Starlette-migration release in `requirements.txt`:

```
streamlit==1.56.0
requests>=2.32.3
```

Then push the change and reboot the app (**Manage app → ⋮ → Reboot app**).

## Notes

- API keys are never hardcoded or logged; they live only in the Streamlit
  session for the duration of use.
- All external API calls are wrapped with timeouts and structured error
  handling (`SourceError`, `AuthError`, `NotFoundError`, `RateLimitError`,
  `LLMError`).