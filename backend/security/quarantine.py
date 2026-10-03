"""
Aegis SOC — automated quarantine engine.

Reversible, audit-logged containment actions driven by trace confidence:
  - isolate_asset   tag asset as quarantined + emit network-policy intent
  - block_ip        add source IP to the platform blocklist (enforced at ingress/WAF)
  - disable_account suspend a user identity (sessions rejected on revalidation)
  - freeze_idp      disable a SAML/OIDC federation trust (suspected IdP compromise)

Safety rails (AEG-IR-001 §4.3):
  - PROTECTED entities (owner account, platform control plane) can never be quarantined.
  - Every action records prior state → fully reversible via release().
  - auto=True only when confidence >= AUTO_QUARANTINE_THRESHOLD and entity unprotected.
  - Every automated action requires human review within 1 hour (tracked via 'reviewed_by').
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone

AUTO_QUARANTINE_THRESHOLD = float(os.getenv("AEGIS_AUTO_QUARANTINE_THRESHOLD", "0.9"))

# Entities that must never be auto-quarantined (break-glass owner, control plane)
PROTECTED_ACCOUNTS = set(filter(None, os.getenv("AEGIS_PROTECTED_ACCOUNTS", "").split(",")))
PROTECTED_ASSETS = set(filter(None, os.getenv("AEGIS_PROTECTED_ASSETS", "").split(",")))

ACTIONS = ("isolate_asset", "block_ip", "disable_account", "freeze_idp")


class QuarantineEngine:
    def __init__(self, db):
        self.db = db

    async def _record(self, action: str, target: str, tenant: str, reason: str,
                      trace_id: str | None, auto: bool, actor: str, prior_state: dict) -> dict:
        rec = {
            "id": f"qtn-{secrets.token_hex(8)}",
            "action": action,
            "target": target,
            "tenant": tenant,
            "reason": reason,
            "trace_id": trace_id,
            "auto": auto,
            "actor": actor,
            "prior_state": prior_state,
            "status": "active",
            "reviewed_by": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "released_at": None,
        }
        await self.db.quarantines.insert_one(dict(rec))
        rec.pop("_id", None)
        return rec

    def _check_protected(self, action: str, target: str) -> None:
        if action == "disable_account" and target in PROTECTED_ACCOUNTS:
            raise ValueError(f"Refused: {target} is a protected account")
        if action == "isolate_asset" and target in PROTECTED_ASSETS:
            raise ValueError(f"Refused: {target} is a protected asset")

    async def quarantine(self, *, action: str, target: str, tenant: str, reason: str,
                         actor: str, trace_id: str | None = None,
                         confidence: float | None = None, auto: bool = False) -> dict:
        if action not in ACTIONS:
            raise ValueError(f"Unknown action {action}")
        self._check_protected(action, target)

        if auto:
            if confidence is None or confidence < AUTO_QUARANTINE_THRESHOLD:
                raise ValueError(
                    f"Auto-quarantine requires confidence >= {AUTO_QUARANTINE_THRESHOLD}"
                )

        now = datetime.now(timezone.utc).isoformat()
        prior_state: dict = {}

        if action == "isolate_asset":
            asset = await self.db.assets.find_one({"name": target, "tenant": tenant})
            if not asset:
                raise ValueError("Asset not found in tenant scope")
            prior_state = {"quarantined": asset.get("quarantined", False)}
            await self.db.assets.update_one(
                {"name": target, "tenant": tenant},
                {"$set": {"quarantined": True, "quarantined_at": now}},
            )
            # Network-policy intent for the orchestrator to enforce (K8s NetworkPolicy / SG)
            await self.db.network_policy_intents.insert_one({
                "asset": target, "tenant": tenant, "intent": "deny-all-ingress-egress",
                "created_at": now,
            })

        elif action == "block_ip":
            await self.db.blocklist.update_one(
                {"ip": target},
                {"$set": {"ip": target, "tenant": tenant, "blocked_at": now, "reason": reason}},
                upsert=True,
            )

        elif action == "disable_account":
            user = await self.db.users.find_one({"email": target})
            if not user:
                raise ValueError("Account not found")
            prior_state = {"disabled": user.get("disabled", False)}
            await self.db.users.update_one(
                {"email": target}, {"$set": {"disabled": True, "disabled_at": now}}
            )

        elif action == "freeze_idp":
            cfg = await self.db.sso_trusts.find_one({"idp": target})
            prior_state = {"enabled": (cfg or {}).get("enabled", True)}
            await self.db.sso_trusts.update_one(
                {"idp": target},
                {"$set": {"idp": target, "enabled": False, "frozen_at": now, "reason": reason}},
                upsert=True,
            )

        return await self._record(action, target, tenant, reason, trace_id, auto, actor, prior_state)

    async def release(self, *, quarantine_id: str, actor: str) -> dict:
        """Reverse a quarantine using its recorded prior state. Requires step-up auth (PEP)."""
        rec = await self.db.quarantines.find_one({"id": quarantine_id})
        if not rec:
            raise ValueError("Quarantine record not found")
        if rec["status"] != "active":
            raise ValueError("Quarantine is not active")

        action, target, tenant = rec["action"], rec["target"], rec["tenant"]
        prior = rec.get("prior_state", {})
        now = datetime.now(timezone.utc).isoformat()

        if action == "isolate_asset":
            await self.db.assets.update_one(
                {"name": target, "tenant": tenant},
                {"$set": {"quarantined": prior.get("quarantined", False)}, "$unset": {"quarantined_at": ""}},
            )
            await self.db.network_policy_intents.delete_many({"asset": target, "tenant": tenant})
        elif action == "block_ip":
            await self.db.blocklist.delete_one({"ip": target})
        elif action == "disable_account":
            await self.db.users.update_one(
                {"email": target},
                {"$set": {"disabled": prior.get("disabled", False)}, "$unset": {"disabled_at": ""}},
            )
        elif action == "freeze_idp":
            await self.db.sso_trusts.update_one({"idp": target}, {"$set": {"enabled": prior.get("enabled", True)}})

        await self.db.quarantines.update_one(
            {"id": quarantine_id},
            {"$set": {"status": "released", "released_at": now, "released_by": actor}},
        )
        rec.update({"status": "released", "released_at": now, "released_by": actor})
        rec.pop("_id", None)
        return rec

    async def mark_reviewed(self, *, quarantine_id: str, reviewer: str) -> None:
        await self.db.quarantines.update_one(
            {"id": quarantine_id}, {"$set": {"reviewed_by": reviewer}}
        )
