from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import json
from pathlib import Path
from typing import TypedDict, List, Dict, Any

from langgraph.graph import StateGraph, START, END
from langchain_openai import AzureChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from backend.database import init_db, save_scan, get_recent_scans

load_dotenv()

app = FastAPI()
init_db()

RULES_PATH = Path(__file__).parent.parent / "rules" / "owasp_rules.json"

llm = AzureChatOpenAI(
    azure_deployment=os.getenv("AZURE_DEPLOYMENT_NAME"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    api_version="2024-02-01",
    temperature=0,
)


# ── LangGraph State ──────────────────────────────────────────────────────────

class ScanState(TypedDict):
    code: str
    rules: List[Dict[str, Any]]
    rules_text: str
    vulnerabilities: List[Dict[str, Any]]
    fixed_code: str
    summary: str


# ── Agent Nodes ──────────────────────────────────────────────────────────────

def load_rules(state: ScanState) -> dict:
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data["rules"]
    except FileNotFoundError:
        raise RuntimeError(f"Rules file not found at {RULES_PATH}")
    except (KeyError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Failed to parse rules file: {e}")

    lines = []
    for r in rules:
        lines.append(
            f"- [{r['rule_id']}] {r['owasp_category']} | {r['name']} "
            f"(Severity: {r['severity']})\n"
            f"  Description: {r['description']}\n"
            f"  Remediation: {r['remediation_summary']}"
        )
    return {"rules": rules, "rules_text": "\n\n".join(lines)}


def analyze_code(state: ScanState) -> dict:
    prompt = f"""You are an expert application security engineer.

Analyze the code below against the OWASP security rules and return a JSON array of vulnerabilities found.

Return ONLY a raw JSON array (no markdown fences, no extra text):
[
  {{
    "rule_id": "<rule_id from the list, e.g. A03-001>",
    "owasp_category": "<full category string>",
    "name": "<vulnerability name>",
    "severity": "<CRITICAL | HIGH | MEDIUM | LOW>",
    "explanation": "<2-4 sentence plain English explanation of the specific issue in this code>",
    "vulnerable_snippet": "<exact lines or expression from the submitted code that are vulnerable>"
  }}
]

If no vulnerabilities are found, return an empty array: []
Only report issues you can concretely identify. Do not invent problems.

═══════════════════════ OWASP RULES ═══════════════════════
{state["rules_text"]}

═══════════════════════ CODE TO REVIEW ═══════════════════════
{state["code"]}"""

    response = llm.invoke([
        SystemMessage(content="You are a security code reviewer. Respond with a valid JSON array only."),
        HumanMessage(content=prompt),
    ])

    raw = response.content.strip()
    # Strip markdown fences if the model wraps output despite instructions
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json\n"):
            raw = raw[5:]
        raw = raw.strip()

    return {"vulnerabilities": json.loads(raw)}


def generate_fix(state: ScanState) -> dict:
    prompt = f"""You are an expert application security engineer.

The following vulnerabilities were found in the code:
{json.dumps(state["vulnerabilities"], indent=2)}

Rewrite the code below to remediate every identified vulnerability.
Return ONLY the fixed code — no explanation, no markdown fences, no commentary.

═══════════════════════ ORIGINAL CODE ═══════════════════════
{state["code"]}"""

    response = llm.invoke([
        SystemMessage(content="You are a security code reviewer. Return only the fixed code, nothing else."),
        HumanMessage(content=prompt),
    ])

    fixed_code = response.content.strip()
    if fixed_code.startswith("```"):
        lines = fixed_code.split("\n")
        fixed_code = "\n".join(lines[1:-1]).strip()

    return {"fixed_code": fixed_code}


def explain(state: ScanState) -> dict:
    vuln_count = len(state["vulnerabilities"])
    prompt = f"""You are an expert application security engineer writing for a developer audience.

{vuln_count} vulnerabilities were found. Based on the findings below, write a 2-3 sentence plain English
summary of the overall security posture of the reviewed code.

Findings:
{json.dumps(state["vulnerabilities"], indent=2)}

Be concise. Return only the summary paragraph — no JSON, no headers, no bullet points."""

    response = llm.invoke([
        SystemMessage(content="You are a security code reviewer writing clear summaries for developers."),
        HumanMessage(content=prompt),
    ])

    return {"summary": response.content.strip()}


# ── Build LangGraph agent ────────────────────────────────────────────────────

def _build_scan_agent():
    g = StateGraph(ScanState)
    g.add_node("load_rules", load_rules)
    g.add_node("analyze_code", analyze_code)
    g.add_node("generate_fix", generate_fix)
    g.add_node("explain", explain)
    g.add_edge(START, "load_rules")
    g.add_edge("load_rules", "analyze_code")
    g.add_edge("analyze_code", "generate_fix")
    g.add_edge("generate_fix", "explain")
    g.add_edge("explain", END)
    return g.compile()


scan_agent = _build_scan_agent()


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
    initial: ScanState = {
        "code": input.code,
        "rules": [],
        "rules_text": "",
        "vulnerabilities": [],
        "fixed_code": "",
        "summary": "",
    }

    try:
        result = scan_agent.invoke(initial)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"LLM returned invalid JSON: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {e}")

    save_scan(
        code_snippet=input.code,
        vulnerabilities_found=result["vulnerabilities"],
        fixed_code=result["fixed_code"],
        summary=result["summary"],
    )

    return ScanResult(
        vulnerabilities=result["vulnerabilities"],
        fixed_code=result["fixed_code"],
        summary=result["summary"],
    )
