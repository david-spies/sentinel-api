"""
ai/core/llm.py

LLM inference layer — wraps llama-cpp-python with:
  - Lazy model loading (singleton, load-on-first-use)
  - Structured prompts per OWASP category with backend-specific code snippets
  - Tenacity retry with exponential backoff
  - Template fallback when the model is unavailable or times out
  - Token budget enforcement (never exceeds model_max_tokens)
"""

from __future__ import annotations

import time
import threading
from functools import lru_cache
from typing import Optional

import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .config import get_settings
from .models import Finding, OWASPCategory, Severity

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Singleton model handle
# ---------------------------------------------------------------------------

_llm = None
_llm_lock = threading.Lock()
_load_start: float = 0.0
_load_done: bool = False


def get_llm():
    """
    Return the singleton Llama model instance.
    Thread-safe lazy initialisation — loads on first call.
    Raises RuntimeError if model file does not exist.
    """
    global _llm, _load_done, _load_start
    if _llm is not None:
        return _llm

    with _llm_lock:
        if _llm is not None:
            return _llm

        cfg = get_settings()
        if not cfg.model_path.exists():
            raise RuntimeError(
                f"Model not found: {cfg.model_path}. "
                "Download Mistral-7B-Instruct-v0.2-Q4_K_M.gguf and place it at that path."
            )

        logger.info("loading_llm", model=str(cfg.model_path))
        _load_start = time.monotonic()

        try:
            from llama_cpp import Llama  # type: ignore
            _llm = Llama(
                model_path=str(cfg.model_path),
                n_ctx=cfg.model_context_length,
                n_gpu_layers=cfg.model_n_gpu_layers,
                n_threads=cfg.model_n_threads,
                verbose=cfg.model_verbose,
                chat_format="mistral-instruct",
            )
            elapsed = time.monotonic() - _load_start
            _load_done = True
            logger.info("llm_loaded", elapsed_s=round(elapsed, 2), model=cfg.model_path.name)
        except Exception as exc:
            logger.error("llm_load_failed", error=str(exc))
            raise

    return _llm


def is_model_loaded() -> bool:
    return _load_done


def model_name() -> str:
    cfg = get_settings()
    return cfg.model_path.stem


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

# Per-OWASP-category system context injected into the prompt.
# Instructs the model to generate backend-specific, actionable code.
OWASP_SYSTEM_CONTEXTS: dict[OWASPCategory, str] = {
    OWASPCategory.API1: (
        "You are a senior API security engineer specialising in Broken Object Level Authorization (BOLA/IDOR). "
        "Generate a concise, production-ready fix that adds server-side ownership validation. "
        "Prefer FastAPI/Python examples unless the finding evidence indicates another stack."
    ),
    OWASPCategory.API2: (
        "You are a senior API security engineer specialising in authentication hardening. "
        "Generate a fix that enforces strong token validation, including algorithm pinning "
        "and proper JWT library usage. Include rate-limiting guidance for auth endpoints."
    ),
    OWASPCategory.API3: (
        "You are a senior API security engineer specialising in mass assignment vulnerabilities. "
        "Generate a fix using allowlist field validation — show how to use Pydantic response models "
        "or framework-specific serialisers to prevent privileged field acceptance."
    ),
    OWASPCategory.API4: (
        "You are a senior API security engineer specialising in rate limiting and resource protection. "
        "Generate both Nginx upstream config and application-level middleware (slowapi for FastAPI, "
        "express-rate-limit for Node.js) appropriate to the stack."
    ),
    OWASPCategory.API5: (
        "You are a senior API security engineer specialising in function-level access control. "
        "Generate a role-based guard that prevents regular users from accessing admin endpoints. "
        "Include both middleware and decorator patterns."
    ),
    OWASPCategory.API7: (
        "You are a senior API security engineer specialising in SSRF prevention. "
        "Generate an allowlist-based URL validator that blocks internal RFC-1918 ranges, "
        "cloud metadata endpoints (169.254.x.x, 100.100.x.x), and localhost variants."
    ),
    OWASPCategory.API8: (
        "You are a senior API security engineer specialising in security misconfiguration. "
        "Generate specific server and application config fixes: CORS policy tightening, "
        "security header injection, and dangerous HTTP method disabling."
    ),
    OWASPCategory.API9: (
        "You are a senior API security engineer specialising in API inventory management. "
        "Generate a decommissioning plan for zombie endpoints (410 Gone + Sunset header) "
        "and API gateway routing rules to block undocumented internal paths."
    ),
}

DEFAULT_SYSTEM_CONTEXT = (
    "You are a senior API security engineer. "
    "Generate a concise, production-ready remediation for the described vulnerability. "
    "Always include a code example. Be specific and actionable."
)


def build_prompt(finding: Finding) -> str:
    """
    Build a structured chat prompt for a finding.
    Uses Mistral instruction format: [INST] ... [/INST]
    """
    system = OWASP_SYSTEM_CONTEXTS.get(finding.owasp_category, DEFAULT_SYSTEM_CONTEXT)

    endpoint_ctx = ""
    if finding.endpoint:
        endpoint_ctx = (
            f"\nAffected endpoint: {finding.endpoint.method} {finding.endpoint.path}"
            f"\nAuth required: {finding.endpoint.auth_required} ({finding.endpoint.auth_type or 'None'})"
            f"\nRate limited: {finding.endpoint.has_rate_limit}"
        )

    user_message = (
        f"Vulnerability: {finding.title}\n"
        f"OWASP category: {finding.owasp_category}\n"
        f"Severity: {finding.severity} (CVSS {finding.cvss_score:.1f})\n"
        f"Description: {finding.description}"
        f"{endpoint_ctx}\n"
        f"Evidence: {finding.evidence or 'See description'}\n\n"
        "Provide:\n"
        "1. A one-paragraph explanation of why this is dangerous\n"
        "2. A specific code fix (include the language/framework)\n"
        "3. A verification step to confirm the fix works\n"
        "Format the code block with ``` fences."
    )

    # Mistral instruction format
    return f"<s>[INST] {system}\n\n{user_message} [/INST]"


# ---------------------------------------------------------------------------
# Inference with retry
# ---------------------------------------------------------------------------

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception),
    reraise=False,
)
def _run_inference(prompt: str) -> Optional[str]:
    """Execute a single inference call with retry."""
    cfg = get_settings()
    llm = get_llm()

    result = llm(
        prompt,
        max_tokens=cfg.model_max_tokens,
        temperature=cfg.model_temperature,
        top_p=cfg.model_top_p,
        stop=["</s>", "[INST]"],
        echo=False,
    )

    choices = result.get("choices", [])
    if not choices:
        return None
    return choices[0].get("text", "").strip()


# ---------------------------------------------------------------------------
# Fallback templates
# ---------------------------------------------------------------------------

FALLBACK_TEMPLATES: dict[OWASPCategory, str] = {
    OWASPCategory.API1: (
        "**Fix:** Add server-side ownership validation before returning any user-scoped resource.\n\n"
        "```python\n"
        "# FastAPI + SQLAlchemy\n"
        "@app.get('/v1/users/{user_id}/orders')\n"
        "async def get_orders(user_id: int, current_user=Depends(get_current_user)):\n"
        "    if current_user.id != user_id:\n"
        "        raise HTTPException(status_code=403, detail='Forbidden')\n"
        "    return db.query(Order).filter(Order.owner_id == current_user.id).all()\n"
        "```\n\n"
        "**Verify:** Attempt to access another user's resource with a valid but different JWT — expect HTTP 403."
    ),
    OWASPCategory.API2: (
        "**Fix:** Enforce JWT algorithm pinning and validate all claims.\n\n"
        "```python\n"
        "import jwt\n"
        "def verify_token(token: str) -> dict:\n"
        "    return jwt.decode(\n"
        "        token,\n"
        "        SECRET_KEY,\n"
        "        algorithms=['RS256'],  # pin — never allow 'none'\n"
        "        options={'require': ['exp', 'iat', 'sub']},\n"
        "    )\n"
        "```\n\n"
        "**Verify:** Submit a token with alg:none — expect HTTP 401."
    ),
    OWASPCategory.API4: (
        "**Fix:** Add rate limiting at both the Nginx and application layers.\n\n"
        "```nginx\n"
        "limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;\n"
        "location /v1/auth/token {\n"
        "    limit_req zone=api burst=5 nodelay;\n"
        "    limit_req_status 429;\n"
        "}\n"
        "```\n\n"
        "**Verify:** Send 50 rapid requests — expect HTTP 429 after the burst allowance."
    ),
    OWASPCategory.API5: (
        "**Fix:** Add a role guard dependency on all admin endpoints.\n\n"
        "```python\n"
        "def require_admin(current_user=Depends(get_current_user)):\n"
        "    if current_user.role != 'admin':\n"
        "        raise HTTPException(status_code=403)\n"
        "    return current_user\n\n"
        "@app.get('/v1/admin/users', dependencies=[Depends(require_admin)])\n"
        "async def list_users(): ...\n"
        "```\n\n"
        "**Verify:** Call the endpoint with a non-admin JWT — expect HTTP 403."
    ),
}

DEFAULT_FALLBACK = (
    "**Fix:** Review the vulnerability description and apply the principle of least privilege. "
    "Consult the OWASP API Security Top 10 (2023) guidance for this category.\n\n"
    "**Verify:** Re-run the Sentinel-API scan after applying the fix to confirm the finding is resolved."
)


def get_fallback(finding: Finding) -> str:
    """Return a deterministic template when the LLM is unavailable."""
    return FALLBACK_TEMPLATES.get(finding.owasp_category, DEFAULT_FALLBACK)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_remediation(finding: Finding) -> tuple[str, str]:
    """
    Generate LLM remediation for a single finding.

    Returns:
        (full_text, code_snippet) — code_snippet is extracted from the first ``` block.
    """
    cfg = get_settings()
    log = logger.bind(finding_id=finding.id, owasp=str(finding.owasp_category))

    # Fast-path: if model is not loaded and fallback is enabled, skip inference.
    if not is_model_loaded() and cfg.llm_fallback_enabled:
        log.warning("llm_not_loaded_using_fallback")
        text = get_fallback(finding)
        return text, _extract_code(text)

    try:
        prompt = build_prompt(finding)
        log.debug("running_inference", prompt_chars=len(prompt))
        t0 = time.monotonic()
        text = _run_inference(prompt)
        elapsed = time.monotonic() - t0
        log.info("inference_complete", elapsed_ms=round(elapsed * 1000), tokens=len((text or "").split()))

        if not text:
            raise ValueError("Empty LLM response")

        return text, _extract_code(text)

    except Exception as exc:
        log.warning("llm_inference_failed", error=str(exc), fallback=cfg.llm_fallback_enabled)
        if cfg.llm_fallback_enabled:
            text = get_fallback(finding)
            return text, _extract_code(text)
        raise


def _extract_code(text: str) -> str:
    """Extract the first fenced code block from LLM output."""
    import re
    match = re.search(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return match.group(1).strip() if match else ""
