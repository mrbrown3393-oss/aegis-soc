#!/usr/bin/env python3
"""Local repro of the CI smoke test (issue #74, item 1).

Mirrors .github/workflows/ci.yml: boot assumptions, health check,
login -> MFA setup -> TOTP verify -> metrics/overview.

Usage (from backend/ with a working .env):
    python scripts/local_smoke_repro.py

Notes:
- Sets MONGO_TLS=false for this process only (does not write .env).
  Local default MONGO_TLS=true will fail handshake without certs.
- Expects uvicorn already running on 127.0.0.1:8001, or starts it
  if --start is passed (requires MongoDB listening on MONGO_URL).
- Admin credentials come from ADMIN_EMAIL / ADMIN_PASSWORD env.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import struct
import subprocess
import sys
import time

import httpx

BASE = "http://127.0.0.1:8001"


def step(name: str):
    print(f"\n==> {name}")


def fail(msg: str, resp: httpx.Response | None = None) -> None:
    print(f"FAIL: {msg}")
    if resp is not None:
        print(f"  status: {resp.status_code}")
        print(f"  body:   {resp.text[:800]}")
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", action="store_true", help="start uvicorn for this run")
    args = parser.parse_args()

    # Mirror CI: TLS off locally unless explicitly set.
    os.environ.setdefault("MONGO_TLS", "false")
    os.environ.setdefault("AEGIS_ENV", "development")

    proc = None
    if args.start:
        step("starting uvicorn")
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server:app",
             "--host", "127.0.0.1", "--port", "8001"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                r = httpx.get(f"{BASE}/api/", timeout=1)
                if r.status_code == 200:
                    break
            except httpx.TransportError:
                time.sleep(0.5)
        else:
            fail("API did not become ready within 30s")

    s = httpx.Client(base_url=BASE, timeout=10)

    step("health check GET /api/")
    r = s.get("/api/")
    if r.status_code != 200 or r.json().get("status") != "ok":
        fail("health check", r)
    print("  ok")

    email = os.environ.get("ADMIN_EMAIL", "")
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not email or not password:
        fail("ADMIN_EMAIL and ADMIN_PASSWORD must be set in the environment")

    step(f"login as {email}")
    r = s.post("/api/auth/login", json={"email": email, "password": password})
    if r.status_code != 200:
        fail("login", r)
    body = r.json()
    print(f"  mfaRequired: {body.get('mfaRequired')}")
    if not body.get("mfaRequired"):
        # MFA disabled in this env — skip to metrics.
        step("metrics/overview?tenant=all (no MFA)")
        r = s.get("/api/metrics/overview?tenant=all")
        if r.status_code != 200 or "total_threats" not in r.json():
            fail("metrics", r)
        print("  ok —", {k: r.json()[k] for k in r.json() if k != "trend"})
        print("\nSMOKE PASSED (MFA not required in this environment)")
        return

    step("MFA setup GET /api/auth/mfa/setup")
    r = s.get("/api/auth/mfa/setup")
    if r.status_code != 200:
        fail("mfa setup", r)
    secret = r.json().get("secret", "")
    if not secret:
        fail("mfa setup returned no secret", r)
    print(f"  secret: {secret[:4]}...")

    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    counter = int(time.time() // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"

    step(f"MFA verify code {code}")
    r = s.post("/api/auth/mfa/verify", json={"code": code})
    if r.status_code != 200:
        fail("mfa verify", r)
    print("  ok")

    step("metrics/overview?tenant=all")
    r = s.get("/api/metrics/overview?tenant=all")
    if r.status_code != 200 or "total_threats" not in r.json():
        fail("metrics", r)
    data = r.json()
    print("  ok —", {k: data[k] for k in data if k != "trend"})

    print("\nSMOKE PASSED")
    if proc is not None:
        proc.terminate()


if __name__ == "__main__":
    main()
