"""Fusion AI Orchestrator /invokeAsync test client.

This CLI:
  1) Fetches an OAuth2 access token (client credentials) from IDCS
  2) Calls /invokeAsync for a workflow
  3) Optionally polls /status/{jobId} until terminal state

Secrets are read from environment variables (optionally via a local .env file).
Do not commit real credentials.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests


TERMINAL_STATUSES = {
    "COMPLETE",
    "COMPLETED",  # just in case
    "FAILED",
    "ERROR",
    "CANCELLED",
    "CANCELED",
    "REJECTED",
    "TIMEOUT",
}


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (no external dependency).

    Supports KEY=VALUE lines; ignores blanks and comments.
    Does not override already-set environment variables.
    """

    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _require_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise SystemExit(
            f"Missing required environment variable: {name}. "
            f"Set it in your shell or in .env (see .env.example)."
        )
    return v


def _join_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


@dataclass(frozen=True)
class Config:
    token_url: str
    client_id: str
    client_secret: str
    scope: str
    fusion_base_url: str
    workflow_code: str
    invocation_mode: str
    conversational: bool
    verify_ssl: bool


def load_config() -> Config:
    _load_dotenv()

    # Common copy/paste issue: double slash before oauth2 path
    token_url = _require_env("TOKEN_URL").replace("//oauth2/", "/oauth2/")

    return Config(
        token_url=token_url,
        client_id=_require_env("CLIENT_ID"),
        client_secret=_require_env("CLIENT_SECRET"),
        scope=_require_env("SCOPE"),
        fusion_base_url=_require_env("FUSION_BASE_URL"),
        workflow_code=_require_env("WORKFLOW_CODE"),
        invocation_mode=os.getenv("INVOCATION_MODE", "ADMIN"),
        conversational=_bool_env("CONVERSATIONAL", True),
        verify_ssl=_bool_env("VERIFY_SSL", True),
    )


def get_token(cfg: Config, timeout_s: int = 30) -> Tuple[str, Dict[str, Any]]:
    """Fetch OAuth2 token using client_credentials grant."""

    basic = base64.b64encode(
        f"{cfg.client_id}:{cfg.client_secret}".encode("utf-8")
    ).decode("ascii")

    headers = {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {"grant_type": "client_credentials", "scope": cfg.scope}

    resp = requests.post(
        cfg.token_url,
        headers=headers,
        data=data,
        timeout=timeout_s,
        verify=cfg.verify_ssl,
    )

    if resp.status_code >= 400:
        raise SystemExit(
            "Token request failed. "
            f"HTTP {resp.status_code}: {resp.text.strip()}"
        )
    payload = resp.json()
    token = payload.get("access_token")
    if not token:
        raise SystemExit(f"Token response missing access_token: {payload}")
    return token, payload


def invoke_async(
    cfg: Config,
    token: str,
    message: str,
    conversation_id: Optional[str] = None,
    timeout_s: int = 60,
) -> Dict[str, Any]:
    """Call the invokeAsync endpoint for the configured workflow."""

    # Observed pattern from your the doc:
    # /api/fusion-ai/orchestrator/agent/v2/{workflowCode}/invokeAsync
    url = _join_url(
        cfg.fusion_base_url,
        f"/api/fusion-ai/orchestrator/agent/v2/{cfg.workflow_code}/invokeAsync",
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    body: Dict[str, Any] = {
        "workflowCode": cfg.workflow_code,
        "invocationMode": cfg.invocation_mode,
        "conversational": cfg.conversational,
        "message": message,
    }
    if conversation_id:
        body["conversationId"] = conversation_id

    resp = requests.post(
        url,
        headers=headers,
        json=body,
        timeout=timeout_s,
        verify=cfg.verify_ssl,
    )

    if resp.status_code >= 400:
        raise SystemExit(
            "invokeAsync failed. "
            f"HTTP {resp.status_code}: {resp.text.strip()}"
        )
    return resp.json()


def get_status(
    cfg: Config,
    token: str,
    job_id: str,
    timeout_s: int = 30,
) -> Dict[str, Any]:
    # Status endpoint varies by deployment.
    # We implement the most likely workflow-scoped path first.
    candidates = [
        f"/api/fusion-ai/orchestrator/agent/v2/{cfg.workflow_code}/status/{job_id}",
        f"/api/fusion-ai/orchestrator/agent/v2/status/{job_id}",
    ]

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    last_error: Optional[str] = None

    for path in candidates:
        url = _join_url(cfg.fusion_base_url, path)
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout_s,
            verify=cfg.verify_ssl,
        )
        if resp.status_code < 400:
            return resp.json()
        last_error = f"GET {path} -> HTTP {resp.status_code}: {resp.text.strip()}"

    raise SystemExit(f"Status request failed. Last error: {last_error}")


def poll_status(
    cfg: Config,
    token: str,
    job_id: str,
    interval_s: float = 2.0,
    timeout_s: float = 120.0,
    quiet: bool = False,
) -> Dict[str, Any]:
    """Poll status until terminal status or timeout."""

    deadline = time.time() + timeout_s
    last: Optional[Dict[str, Any]] = None

    while time.time() < deadline:
        last = get_status(cfg, token, job_id)
        status = str(last.get("status", "")).upper()
        if not quiet:
            print(f"status={status}")
        if status in TERMINAL_STATUSES:
            return last
        time.sleep(interval_s)

    raise SystemExit(
        f"Timed out after {timeout_s}s waiting for job {job_id}. "
        f"Last status payload: {json.dumps(last or {}, indent=2)}"
    )


def _extract_job_and_conversation(resp: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    # Your sample response had top-level jobId and conversationId.
    job_id = resp.get("jobId")
    conversation_id = resp.get("conversationId")
    return job_id, conversation_id


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Test client for /invokeAsync")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_token = sub.add_parser("token", help="Fetch and print token metadata (not the secret)")
    p_token.add_argument("--show-token", action="store_true", help="Print access_token too")

    p_invoke = sub.add_parser("invoke", help="Call invokeAsync")
    p_invoke.add_argument("--message", required=True, help="Message to send")
    p_invoke.add_argument("--conversation-id", help="Existing conversationId")
    p_invoke.add_argument("--poll", action="store_true", help="Poll status until terminal")
    p_invoke.add_argument("--interval", type=float, default=2.0, help="Poll interval seconds")
    p_invoke.add_argument("--timeout", type=float, default=180.0, help="Poll timeout seconds")
    p_invoke.add_argument("--quiet", action="store_true", help="Less polling output")

    args = parser.parse_args(argv)
    cfg = load_config()

    token, token_payload = get_token(cfg)

    if args.cmd == "token":
        if args.show_token:
            _print_json(token_payload)
        else:
            redacted = dict(token_payload)
            if "access_token" in redacted:
                redacted["access_token"] = "<redacted>"
            _print_json(redacted)
        return 0

    if args.cmd == "invoke":
        invoke_resp = invoke_async(
            cfg,
            token=token,
            message=args.message,
            conversation_id=args.conversation_id,
        )
        job_id, conv_id = _extract_job_and_conversation(invoke_resp)
        print("invokeAsync response:")
        _print_json(invoke_resp)
        if conv_id:
            print(f"conversationId={conv_id}")
        if not job_id:
            print("WARNING: jobId not found in response; cannot poll.", file=sys.stderr)
            return 0
        print(f"jobId={job_id}")

        if args.poll:
            print("Polling status...")
            final = poll_status(
                cfg,
                token=token,
                job_id=job_id,
                interval_s=args.interval,
                timeout_s=args.timeout,
                quiet=args.quiet,
            )
            print("Final status payload:")
            _print_json(final)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
