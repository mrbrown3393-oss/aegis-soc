"""Startup indexes and idempotent demo-data seeding."""
from __future__ import annotations

import random
import secrets
from datetime import datetime, timezone, timedelta

from database import db
from auth_helpers import hash_password
from config import settings


async def ensure_indexes() -> None:
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.login_attempts.create_index("key", unique=True)
    await db.auth_rate_limits.create_index("key", unique=True)
    await db.auth_rate_limits.create_index("window", expireAfterSeconds=300)
    await db.auth_sessions.create_index("session_id", unique=True)
    await db.auth_sessions.create_index("expires_at", expireAfterSeconds=0)
    for col in ("threats", "incidents", "vulnerabilities", "assets", "compliance", "audit_logs"):
        await db[col].create_index("tenant")
        await db[col].create_index("id", unique=True)


async def seed_users() -> None:
    if await db.users.count_documents({}) > 0:
        return
    now = datetime.now(timezone.utc).isoformat()
    await db.users.insert_many([
        {
            "id": secrets.token_hex(16),
            "email": settings.ADMIN_EMAIL,
            "name": "William Brown",
            "role": "owner",
            "tenant": "government",
            "password_hash": hash_password(settings.ADMIN_PASSWORD),
            "created_at": now,
            "mfaEnrolledAt": None,
        },
        {
            "id": secrets.token_hex(16),
            "email": settings.ANALYST_EMAIL,
            "name": "Demo Analyst",
            "role": "analyst",
            "tenant": "private",
            "password_hash": hash_password(settings.ANALYST_PASSWORD),
            "created_at": now,
            "mfaEnrolledAt": None,
        },
    ])


async def seed_demo_data() -> None:
    if await db.threats.count_documents({}) > 0:
        return

    now = datetime.now(timezone.utc)
    tenants = ["government", "private", "saas"]
    severities = ["critical", "high", "medium", "low"]
    sources = ["10.0.0.1", "192.168.1.50", "203.0.113.10", "198.51.100.5"]
    geos = ["RU", "CN", "KP", "IR", "US", "DE", "BR", "IN"]

    threats = []
    for i in range(120):
        threats.append({
            "id": secrets.token_hex(8),
            "tenant": tenants[i % 3],
            "severity": secrets.choice(severities),
            "title": f"Simulated threat event {i+1}",
            "description": "Demo telemetry for Aegis SOC operator training.",
            "source_ip": secrets.choice(sources),
            "geo": secrets.choice(geos),
            "confidence": round(random.uniform(0.4, 0.99), 2),
            "affected_asset": f"asset-{(i % 60)+1:03d}",
            "timestamp": (now - timedelta(days=secrets.randbelow(14), hours=secrets.randbelow(24))).isoformat(),
        })
    await db.threats.insert_many(threats)

    cves = [f"CVE-2024-{1000+i}" for i in range(36)]
    vulns = []
    for i, cve in enumerate(cves):
        vulns.append({
            "id": secrets.token_hex(8),
            "tenant": tenants[i % 3],
            "cve": cve,
            "title": f"Demo vulnerability {cve}",
            "cvss": round(random.uniform(4.0, 9.8), 1),
            "status": secrets.choice(["open", "open", "patched"]),
            "asset": f"asset-{(i % 60)+1:03d}",
            "discovered_at": (now - timedelta(days=secrets.randbelow(30))).isoformat(),
        })
    await db.vulnerabilities.insert_many(vulns)

    statuses = ["new", "investigating", "contained", "resolved"]
    phases = ["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "c2", "actions"]
    incidents = []
    for i in range(24):
        incidents.append({
            "id": secrets.token_hex(8),
            "tenant": tenants[i % 3],
            "title": f"Incident ticket {i+1}",
            "status": secrets.choice(statuses),
            "severity": secrets.choice(severities),
            "kill_chain_phase": secrets.choice(phases),
            "assignee": secrets.choice(["Demo Analyst", "Unassigned", "William Brown"]),
            "created_at": (now - timedelta(days=secrets.randbelow(14))).isoformat(),
            "updated_at": now.isoformat(),
        })
    await db.incidents.insert_many(incidents)

    asset_types = ["workstation", "server", "firewall", "router", "database", "endpoint"]
    assets = []
    for i in range(60):
        assets.append({
            "id": secrets.token_hex(8),
            "tenant": tenants[i % 3],
            "name": f"{secrets.choice(asset_types)}-{i+1:03d}",
            "type": secrets.choice(asset_types),
            "ip": f"10.{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}",
            "os": secrets.choice(["Windows 11", "Ubuntu 22.04", "RHEL 9", "macOS Sonoma"]),
            "risk_score": round(random.uniform(1.0, 9.5), 1),
            "last_seen": (now - timedelta(minutes=secrets.randbelow(1440))).isoformat(),
        })
    await db.assets.insert_many(assets)

    frameworks = ["NIST 800-53", "ISO 27001", "SOC 2", "HIPAA", "FedRAMP", "PCI-DSS 4.0", "CMMC L2"]
    compliance = []
    for fw in frameworks:
        for t in tenants:
            compliance.append({
                "id": secrets.token_hex(8),
                "tenant": t,
                "framework": fw,
                "score": round(random.uniform(55.0, 95.0), 1),
                "controls_passing": secrets.randbelow(80) + 20,
                "controls_total": 100,
                "last_assessed": (now - timedelta(days=secrets.randbelow(7))).isoformat(),
            })
    await db.compliance.insert_many(compliance)

    audits = []
    for i in range(80):
        audits.append({
            "actor": secrets.choice([settings.ADMIN_EMAIL, settings.ANALYST_EMAIL, "system"]),
            "action": secrets.choice(["login", "logout", "incident_update", "vuln_patch", "user_invite", "threat_view"]),
            "resource": f"resource-{secrets.randbelow(50)}",
            "ip": secrets.choice(sources),
            "tenant": secrets.choice(tenants),
            "created_at": (now - timedelta(hours=secrets.randbelow(720))).isoformat(),
        })
    await db.audit_logs.insert_many(audits)


async def run_startup() -> None:
    await ensure_indexes()
    await seed_users()
    await seed_demo_data()
