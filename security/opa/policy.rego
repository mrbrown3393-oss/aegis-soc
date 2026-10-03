# Aegis SOC — externalized Zero Trust policy (OPA / Rego example).
# Reference PDP for service-mesh or gateway deployments; the in-app PEP
# (backend/zerotrust/pep.py) enforces the same decisions today.
package aegis.authz

default allow := false

# Parse the verified identity attributes injected by the PEP/JWT.
role := input.identity.role
tenant := input.identity.tenant
auth_age_minutes := (time.now_ns() / 1e9 - input.identity.iat) / 60

# 1. Authenticated + valid tenant context is the floor.
authenticated {
  input.identity.sub != ""
  input.identity.tenant != ""
}

# 2. Privileged mutations require step-up (recent authentication).
step_up_ok {
  auth_age_minutes < 15
}

# 3. Device posture required for privileged roles.
posture_ok {
  not privileged
} {
  input.device.posture == "managed;compliant"
}

privileged {
  role == "owner"
} {
  role == "admin"
}

# 4. Session risk below threshold.
risk_ok {
  input.session.risk < 0.85
}

# 5. Tenant scoping: non-privileged users stay in their tenant.
tenant_ok {
  privileged
} {
  input.resource.tenant == tenant
}

allow {
  authenticated
  risk_ok
  posture_ok
  tenant_ok
  not needs_step_up
}

allow {
  authenticated
  risk_ok
  posture_ok
  tenant_ok
  needs_step_up
  step_up_ok
}

needs_step_up {
  startswith(input.resource.path, "/api/users")
  input.request.method != "GET"
} {
  startswith(input.resource.path, "/api/security/quarantine")
  input.request.method != "GET"
}
