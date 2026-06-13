from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from pydantic import BaseModel, field_validator
from enum import Enum
from dotenv import load_dotenv
import os
import json
from pathlib import Path
from typing import Annotated, TypedDict, List, Dict, Any
import hashlib
import openai
import re
import traceback

from langgraph.graph import StateGraph, START, END
from langchain_openai import AzureChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from backend.database import init_db, save_scan, get_recent_scans

load_dotenv()

limiter = Limiter(key_func=lambda request: request.client.host, default_limits=["20/hour"])

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
init_db()

RULES_PATH = Path(__file__).parent.parent / "rules" / "owasp_rules.json"

llm = AzureChatOpenAI(
    azure_deployment=os.getenv("AZURE_DEPLOYMENT_NAME"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    api_version="2024-02-01",
    temperature=0,
)


# ── Auth dependency ──────────────────────────────────────────────────────────

def verify_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    provided_hash = hashlib.sha256(x_api_key.encode()).hexdigest() if x_api_key else None
    if provided_hash != os.getenv("API_KEY_HASH"):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ── LangGraph State ──────────────────────────────────────────────────────────

class ScanState(TypedDict):
    code: str
    language: str
    rules: List[Dict[str, Any]]
    rules_text: str
    imports: List[str]
    flagged_comments: List[str]
    injection_findings: List[Dict[str, Any]]
    auth_findings: List[Dict[str, Any]]
    secrets_findings: List[Dict[str, Any]]
    dependency_findings: List[Dict[str, Any]]
    llm_findings: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    fixed_code: str
    checker_warnings: List[str]
    summary: str


# ── Agent Nodes ──────────────────────────────────────────────────────────────

_INJECTION_TRIGGERS = {"ignore", "bypass", "override", "previous instructions"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_IMPORT_RE = re.compile(
    r"^\s*(import\s+\S.*|from\s+\S+\s+import\s+.*|require\s*\(.*\)|#include\s+.*|using\s+\S.*|use\s+\S.*)",
    re.IGNORECASE,
)
_COMMENT_RE = re.compile(
    r'(""".*?"""|\'\'\'.*?\'\'\'|/\*.*?\*/|#[^\n]*|//[^\n]*|--[^\n]*)',
    re.DOTALL,
)


def _format_rules(rules: List[Dict[str, Any]]) -> str:
    return "\n\n".join(
        f"- [{r['rule_id']}] {r['owasp_category']} | {r['name']} "
        f"(Severity: {r['severity']})\n"
        f"  Description: {r['description']}\n"
        f"  Remediation: {r['remediation_summary']}"
        for r in rules
    )


def _call_llm_for_findings(
    code: str, language: str, rules: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    if not rules:
        return []
    prompt = f"""You are an expert application security engineer.

Analyze the {language} code below against the OWASP security rules and return a JSON array of vulnerabilities found.

Return ONLY a raw JSON array (no markdown fences, no extra text):
[
  {{
    "rule_id": "<rule_id from the list, e.g. A03-001>",
    "owasp_category": "<full category string>",
    "name": "<vulnerability name>",
    "severity": "<CRITICAL | HIGH | MEDIUM | LOW>",
    "confidence": "<HIGH | MEDIUM | LOW>",
    "explanation": "<2-4 sentence plain English explanation of the specific issue in this code>",
    "vulnerable_snippet": "<exact lines or expression from the submitted code that are vulnerable>"
  }}
]

Set confidence to HIGH when the vulnerability is unambiguous from the code alone, MEDIUM when context outside this snippet is needed to confirm, LOW when it is a heuristic match that requires human review.
If no vulnerabilities are found, return an empty array: []
Only report issues you can concretely identify. Do not invent problems.

═══════════════════════ OWASP RULES ═══════════════════════
{_format_rules(rules)}

═══════════════════════ CODE TO REVIEW ═══════════════════════
{code}"""

    response = llm.invoke([
        SystemMessage(content="You are a security code reviewer. Respond with a valid JSON array only."),
        HumanMessage(content=prompt),
    ])

    raw = response.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json\n"):
            raw = raw[5:]
        raw = raw.strip()

    return json.loads(raw)


def preprocess_input(state: ScanState) -> dict:
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data["rules"]
    except FileNotFoundError:
        raise RuntimeError(f"Rules file not found at {RULES_PATH}")
    except (KeyError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Failed to parse rules file: {e}")

    code = state["code"]

    imports = [
        line.strip()
        for line in code.splitlines()
        if _IMPORT_RE.match(line)
    ]

    flagged_comments = []
    for match in _COMMENT_RE.finditer(code):
        text = match.group().lower()
        if any(trigger in text for trigger in _INJECTION_TRIGGERS):
            flagged_comments.append(match.group().strip())

    stripped = _COMMENT_RE.sub("", code)
    stripped = "\n".join(line for line in stripped.splitlines() if line.strip())

    return {
        "rules": rules,
        "imports": imports,
        "flagged_comments": flagged_comments,
        "code": stripped,
    }


def injection_analyzer(state: ScanState) -> dict:
    rules = [r for r in state["rules"] if r["rule_id"].startswith("A03")]
    return {"injection_findings": _call_llm_for_findings(state["code"], state["language"], rules)}


def auth_analyzer(state: ScanState) -> dict:
    rules = [r for r in state["rules"] if r["rule_id"].startswith(("A01", "A07"))]
    return {"auth_findings": _call_llm_for_findings(state["code"], state["language"], rules)}


def secrets_analyzer(state: ScanState) -> dict:
    rules = [r for r in state["rules"] if r["rule_id"].startswith("A02")]
    return {"secrets_findings": _call_llm_for_findings(state["code"], state["language"], rules)}


def dependency_analyzer(state: ScanState) -> dict:
    rules = [r for r in state["rules"] if r["rule_id"].startswith("A09")]
    import_text = "\n".join(state["imports"]) if state["imports"] else "(no imports detected)"
    return {"dependency_findings": _call_llm_for_findings(import_text, state["language"], rules)}


def llm_analyzer(state: ScanState) -> dict:
    rules = [r for r in state["rules"] if r["rule_id"].startswith("LLM")]
    if not rules:
        return {"llm_findings": []}

    code = state["code"]
    language = state["language"]

    prompt = f"""You are an expert in LLM application security (OWASP LLM Top 10).

Analyze the {language} code below for LLM-specific security vulnerabilities. Focus exclusively on these four attack surfaces:

1. PROMPT INJECTION (LLM01): User-controlled input concatenated or f-string interpolated directly into prompt strings, system messages, or message arrays sent to an LLM API — without sanitization or a structured template boundary separating instructions from data.

2. INSECURE OUTPUT HANDLING (LLM02): LLM response content (.content, .text, .choices[]) rendered into HTML via innerHTML / dangerouslySetInnerHTML / render_template_string, or passed to eval() / exec() / subprocess without sanitization or schema validation first.

3. SENSITIVE INFORMATION DISCLOSURE (LLM06): Secrets (API keys, tokens, passwords), PII (SSN, email, DOB, credit card), or environment variables containing credentials included in the prompt payload sent to an external LLM API call (openai, anthropic, bedrock, gemini, azure openai).

4. INSECURE PLUGIN / TOOL DESIGN (LLM07): LLM-generated tool call arguments passed directly to os.system(), subprocess, cursor.execute(), file operations, or shell commands without allowlist validation, schema enforcement, or sandboxing.

Apply the following rules when reporting findings:
{_format_rules(rules)}

Return ONLY a raw JSON array (no markdown fences, no extra text):
[
  {{
    "rule_id": "<LLM01-001 | LLM02-001 | LLM06-001 | LLM07-001 | LLM08-001 | LLM09-001>",
    "owasp_category": "<full category string from the rule>",
    "name": "<vulnerability name>",
    "severity": "<CRITICAL | HIGH | MEDIUM | LOW>",
    "confidence": "<HIGH | MEDIUM | LOW>",
    "explanation": "<2-4 sentences describing the specific issue in this code and why it is exploitable>",
    "vulnerable_snippet": "<exact lines or expression from the submitted code that are vulnerable>"
  }}
]

Set confidence to HIGH when the vulnerability is unambiguous from the code alone, MEDIUM when context outside this snippet is needed to confirm, LOW when it is a heuristic match that requires human review.
If none of the four attack surfaces are present, return an empty array: []
Only report issues you can concretely identify in the code. Do not invent problems.

═══════════════════════ CODE TO REVIEW ═══════════════════════
{code}"""

    response = llm.invoke([
        SystemMessage(content="You are an LLM application security expert. Respond with a valid JSON array only."),
        HumanMessage(content=prompt),
    ])

    raw = response.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json\n"):
            raw = raw[5:]
        raw = raw.strip()

    return {"llm_findings": json.loads(raw)}


def synthesizer(state: ScanState) -> dict:
    all_findings = (
        state.get("injection_findings", [])
        + state.get("auth_findings", [])
        + state.get("secrets_findings", [])
        + state.get("dependency_findings", [])
        + state.get("llm_findings", [])
    )

    seen: set = set()
    unique = []
    for f in all_findings:
        key = (f.get("rule_id", ""), f.get("vulnerable_snippet", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity", "LOW"), 4))
    return {"vulnerabilities": unique}


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


def checker(state: ScanState) -> dict:
    vulns = state.get("vulnerabilities", [])
    if not vulns:
        return {"checker_warnings": []}

    vuln_list = "\n".join(
        f"{i+1}. [{v.get('rule_id', '?')}] {v.get('name', '?')} — {v.get('vulnerable_snippet', '')[:120]}"
        for i, v in enumerate(vulns)
    )

    prompt = f"""You are a security code reviewer verifying that a set of fixes actually remediate identified vulnerabilities.

Original code:
{state["code"]}

Vulnerabilities found:
{vuln_list}

Fixed code:
{state["fixed_code"]}

For each numbered vulnerability, answer YES if the fixed code addresses it, or NO if it does not or you cannot confirm it.
Return ONLY a raw JSON array (no markdown fences, no extra text):
[
  {{"number": 1, "rule_id": "<rule_id>", "addressed": true, "reason": "<one-line reason>"}}
]"""

    response = llm.invoke([
        SystemMessage(content="You are a security code reviewer. Respond with a valid JSON array only."),
        HumanMessage(content=prompt),
    ])

    raw = response.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json\n"):
            raw = raw[5:]
        raw = raw.strip()

    try:
        checks = json.loads(raw)
    except json.JSONDecodeError:
        return {"checker_warnings": ["⚠️ Could not verify fixes — human review recommended."]}

    warnings = [
        f"[{c.get('rule_id', '?')}] Not addressed: {c.get('reason', '')}"
        for c in checks
        if not c.get("addressed", True)
    ]
    return {"checker_warnings": warnings}


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

    summary = response.content.strip()
    if state.get("checker_warnings"):
        summary += "\n\n⚠️ Some fixes may be incomplete - human review recommended."
    return {"summary": summary}


# ── Build LangGraph agent ────────────────────────────────────────────────────

def _build_scan_agent():
    g = StateGraph(ScanState)
    g.add_node("preprocess_input", preprocess_input)
    g.add_node("injection_analyzer", injection_analyzer)
    g.add_node("auth_analyzer", auth_analyzer)
    g.add_node("secrets_analyzer", secrets_analyzer)
    g.add_node("dependency_analyzer", dependency_analyzer)
    g.add_node("llm_analyzer", llm_analyzer)
    g.add_node("synthesizer", synthesizer)
    g.add_node("generate_fix", generate_fix)
    g.add_node("checker", checker)
    g.add_node("explain", explain)
    g.add_edge(START, "preprocess_input")
    g.add_edge("preprocess_input", "injection_analyzer")
    g.add_edge("injection_analyzer", "auth_analyzer")
    g.add_edge("auth_analyzer", "secrets_analyzer")
    g.add_edge("secrets_analyzer", "dependency_analyzer")
    g.add_edge("dependency_analyzer", "llm_analyzer")
    g.add_edge("llm_analyzer", "synthesizer")
    g.add_edge("synthesizer", "generate_fix")
    g.add_edge("generate_fix", "checker")
    g.add_edge("checker", "explain")
    g.add_edge("explain", END)
    return g.compile()


scan_agent = _build_scan_agent()


# ── Response models ──────────────────────────────────────────────────────────

class VulnerabilityFinding(BaseModel):
    rule_id: str
    owasp_category: str
    name: str
    severity: str
    confidence: str = "HIGH"
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


# ── Input models ─────────────────────────────────────────────────────────────

class Language(str, Enum):
    python = "python"
    javascript = "javascript"
    java = "java"
    typescript = "typescript"
    go = "go"
    ruby = "ruby"
    php = "php"
    csharp = "csharp"
    cpp = "cpp"
    other = "other"


class CodeInput(BaseModel):
    code: str
    language: Language = Language.python

    @field_validator("code")
    @classmethod
    def validate_code(cls, v):
        if not v or not v.strip():
            raise ValueError("Code cannot be empty")
        if len(v) > 10000:
            raise ValueError("Code exceeds maximum allowed size of 10,000 characters")
        if "\x00" in v:
            raise ValueError("Code contains invalid characters")
        return v


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/")
def read_root():
    return {"message": "Hello from Security Review Tool!"}


@app.get("/history", response_model=list[ScanRecord], dependencies=[Depends(verify_api_key)])
@limiter.limit("20/hour")
def get_history(request: Request):
    return get_recent_scans(limit=10)


@app.post("/scan", response_model=ScanResult, dependencies=[Depends(verify_api_key)])
@limiter.limit("20/hour")
def scan_code(request: Request, input: CodeInput):
    initial: ScanState = {
        "code": input.code,
        "language": input.language.value,
        "rules": [],
        "rules_text": "",
        "imports": [],
        "flagged_comments": [],
        "injection_findings": [],
        "auth_findings": [],
        "secrets_findings": [],
        "dependency_findings": [],
        "llm_findings": [],
        "vulnerabilities": [],
        "fixed_code": "",
        "checker_warnings": [],
        "summary": "",
    }

    try:
        result = scan_agent.invoke(initial)
    except openai.BadRequestError:
        raise HTTPException(status_code=400, detail="Code was flagged by content safety filter")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"LLM returned invalid JSON: {e}")
    except Exception:
        import logging
        logging.exception("Agent error")
        raise HTTPException(status_code=500, detail="Internal server error")

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