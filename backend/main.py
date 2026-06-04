from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from openai import AzureOpenAI
from dotenv import load_dotenv
import os
import json
from pathlib import Path
from backend.database import init_db, save_scan, get_recent_scans

load_dotenv()

client = AzureOpenAI(
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_version="2024-02-01"
)

app = FastAPI()

init_db()

# Resolve path relative to this file so it works regardless of cwd
RULES_PATH = Path(__file__).parent.parent / "rules" / "owasp_rules.json"


def load_rules() -> list[dict]:
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["rules"]
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Rules file not found at {RULES_PATH}")
    except (KeyError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse rules file: {e}")


def format_rules_for_prompt(rules: list[dict]) -> str:
    lines = []
    for r in rules:
        lines.append(
            f"- [{r['rule_id']}] {r['owasp_category']} | {r['name']} "
            f"(Severity: {r['severity']})\n"
            f"  Description: {r['description']}\n"
            f"  Remediation: {r['remediation_summary']}"
        )
    return "\n\n".join(lines)


def build_prompt(code: str, rules_text: str) -> str:
    return f"""You are an expert application security engineer performing a thorough code review.

Analyze the code below against the OWASP security rules provided and return your findings as a
JSON object with exactly this structure:

{{
  "vulnerabilities": [
    {{
      "rule_id": "<rule_id from the list, e.g. A03-001>",
      "owasp_category": "<full category string>",
      "name": "<vulnerability name>",
      "severity": "<CRITICAL | HIGH | MEDIUM | LOW>",
      "explanation": "<plain English explanation of the specific issue in this code, 2-4 sentences>",
      "vulnerable_snippet": "<the exact lines or expression from the submitted code that are vulnerable>"
    }}
  ],
  "fixed_code": "<complete rewritten version of the code with all vulnerabilities remediated>",
  "summary": "<2-3 sentence plain English overview of the overall security posture of the submitted code>"
}}

Rules:
If no vulnerabilities are found for a rule, do not include it. Only report issues you can concretely
identify in the submitted code. Do not invent problems.

═══════════════════════ OWASP RULES ═══════════════════════
{rules_text}

═══════════════════════ CODE TO REVIEW ═══════════════════════
{code}

Return only the JSON object. No markdown fences, no commentary outside the JSON."""


# ── Response models ──────────────────────────────────────────────────────────

class VulnerabilityFinding(BaseModel):
    rule_id: str
    owasp_category: str
    name: str
    severity: str
    explanation: str
    vulnerable_snippet: str


class ScanResult(BaseModel):
    vulnerabilities: list[VulnerabilityFinding]
    fixed_code: str
    summary: str


class ScanRecord(BaseModel):
    id: int
    timestamp: str
    code_snippet: str
    vulnerabilities_found: list[dict]
    fixed_code: str
    summary: str


# ── Endpoints ────────────────────────────────────────────────────────────────

class CodeInput(BaseModel):
    code: str


@app.get("/")
def read_root():
    return {"message": "Hello from Security Review Tool!"}


@app.get("/history", response_model=list[ScanRecord])
def get_history():
    return get_recent_scans(limit=10)


@app.post("/scan", response_model=ScanResult)
def scan_code(input: CodeInput):
    rules = load_rules()
    rules_text = format_rules_for_prompt(rules)
    prompt = build_prompt(input.code, rules_text)

    response = client.chat.completions.create(
        model=os.getenv("AZURE_DEPLOYMENT_NAME"),
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a security code reviewer. "
                    "You always respond with a single valid JSON object and nothing else."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    )

    raw = response.choices[0].message.content
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"LLM returned invalid JSON: {e}\n\nRaw response:\n{raw}")

    # Normalise: ensure required keys exist so Pydantic validation gives a clear error
    parsed.setdefault("vulnerabilities", [])
    parsed.setdefault("fixed_code", "")
    parsed.setdefault("summary", "")

    save_scan(
        code_snippet=input.code,
        vulnerabilities_found=parsed["vulnerabilities"],
        fixed_code=parsed["fixed_code"],
        summary=parsed["summary"],
    )

    return ScanResult(**parsed)
