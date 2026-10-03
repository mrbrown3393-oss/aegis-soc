"""
Aegis SOC — automated threat tracing engine.

Purpose: given an indicator (IP, asset, technique, account), build the attack
graph: which threats/incidents/assets/accounts are connected, per tenant.

LOW-OBSERVABILITY MODE (per AEG-IR-001 §9):
- Tracing is READ-ONLY over telemetry the platform already holds
  (threats, incidents, audit_logs, assets).
- It performs NO active probing, scanning, beaconing, or any network call
  toward the suspected adversary — nothing an attacker could detect.
- Optional canary/honeypot collections are passively monitored only.
- Trace runs are themselves audit-logged; results land in db.threat_traces.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}


class ThreatTracer:
    def __init__(self, db):
        self.db = db

    async def trace(self, *, tenant_filter: dict, source_ip: str | None = None,
                    asset_id: str | None = None, technique: str | None = None,
                    account: str | None = None, lookback_hours: int = 336) -> dict:
        """Passive correlation — reads existing telemetry only."""
        trace_id = f"trace-{secrets.token_hex(8)}"
        base = dict(tenant_filter)
        nodes, edges = [], []

        threat_query = dict(base)
        ors = []
        if source_ip:
            ors.append({"source_ip": source_ip})
        if asset_id:
            ors.append({"affected_asset": asset_id})
        if technique:
            ors.append({"mitre_technique": technique})
        if ors:
            threat_query["$or"] = ors

        threats = await self.db.threats.find(threat_query, {"_id": 0}).sort("timestamp", -1).to_list(500)
        related_ips = {t.get("source_ip") for t in threats} - {None}
        related_assets = {t.get("affected_asset") for t in threats} - {None}
        related_techniques = {t.get("mitre_technique") for t in threats} - {None}

        for t in threats:
            nodes.append({"type": "threat", "id": t.get("id"), "severity": t.get("severity"),
                          "timestamp": t.get("timestamp"), "title": t.get("title")})

        # Expand: other threats sharing any related indicator (still passive reads)
        if related_ips or related_assets:
            expand = dict(base)
            expand_ors = ([{"source_ip": ip} for ip in related_ips] +
                          [{"affected_asset": a} for a in related_assets])
            expand["$or"] = expand_ors
            expanded = await self.db.threats.find(expand, {"_id": 0}).sort("timestamp", -1).to_list(500)
            known = {n["id"] for n in nodes}
            for t in expanded:
                if t.get("id") not in known:
                    nodes.append({"type": "threat", "id": t.get("id"), "severity": t.get("severity"),
                                  "timestamp": t.get("timestamp"), "title": t.get("title")})
                    related_assets.add(t.get("affected_asset"))
                    related_techniques.add(t.get("mitre_technique"))

        # Account linkage via audit trail (passive)
        account_activity = []
        if account:
            account_activity = await self.db.audit_logs.find(
                {**base, "actor": account}, {"_id": 0}
            ).sort("created_at", -1).to_list(200)
            nodes.append({"type": "account", "id": account, "events": len(account_activity)})

        # Asset posture
        assets = []
        if related_assets:
            assets = await self.db.assets.find(
                {**base, "name": {"$in": [a for a in related_assets if a]}}, {"_id": 0}
            ).to_list(200)
            for a in assets:
                nodes.append({"type": "asset", "id": a.get("name"), "risk_score": a.get("risk_score"),
                              "ip": a.get("ip")})

        # Edges
        for t in threats:
            if t.get("source_ip"):
                edges.append({"from": t.get("source_ip"), "to": t.get("id"), "kind": "originates"})
            if t.get("affected_asset"):
                edges.append({"from": t.get("id"), "to": t.get("affected_asset"), "kind": "targets"})

        # Blast radius + confidence
        max_sev = max((SEVERITY_WEIGHT.get(t.get("severity"), 0.2) for t in threats), default=0.0)
        avg_conf = (sum(t.get("confidence", 0.5) for t in threats) / len(threats)) if threats else 0.0
        blast_radius = len({a for a in related_assets if a})
        confidence = round(min(0.99, max_sev * 0.6 + avg_conf * 0.4), 2)

        result = {
            "id": trace_id,
            "mode": "low-observability-passive",
            "started_by_indicators": {
                "source_ip": source_ip, "asset": asset_id,
                "technique": technique, "account": account,
            },
            "summary": {
                "threats": len(threats),
                "unique_source_ips": sorted(i for i in related_ips if i),
                "techniques": sorted(t for t in related_techniques if t),
                "blast_radius_assets": blast_radius,
                "confidence": confidence,
                "account_events": len(account_activity),
            },
            "graph": {"nodes": nodes, "edges": edges},
            "assets": assets,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await self.db.threat_traces.insert_one(dict(result))
        result.pop("_id", None)
        return result
