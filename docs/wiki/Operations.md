# Operations

## Owner and operator access

The initial account from `ADMIN_EMAIL` is seeded as `owner` in the `government` tenant. It can query all tenants. Other accounts remain scoped to their own tenant, including administrators.

Complete password login and TOTP verification before using protected routes. User creation/removal and incident updates also require a current step-up cookie. User creation currently accepts an initial password directly; it is not an emailed onboarding flow.

## Incident workflow

The backend accepts these incident statuses:

| Status | Operator meaning |
| --- | --- |
| `new` | Awaiting triage |
| `investigating` | Investigation in progress |
| `contained` | Containment recorded |
| `resolved` | Resolution recorded |

Use `PATCH /api/incidents/{incident_id}` with the desired status after step-up authentication. These status changes record workflow state; they do not perform containment themselves.

Likewise, `POST /api/vulnerabilities/{vuln_id}/patch` changes a vulnerability record, and the quarantine API records a requested action. Confirm actual endpoint or network changes through the deployment's enforcement tools.

## Routine review

Review health, authentication failures, active incidents, unresolved vulnerabilities, and recent audit entries. Use tenant-scoped accounts for routine work and reserve owner access for tasks requiring cross-tenant scope.

Retain the commit, environment, observed result, and relevant request/audit identifiers for operational checks. Keep sensitive evidence in the deployment's controlled records.

## Runbooks

| Procedure | Existing project document |
| --- | --- |
| Incident response | [Incident response plan](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/INCIDENT_RESPONSE_PLAN.md) |
| Backup and restoration | [Restore drill runbook](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/RESTORE_DRILL_RUNBOOK.md) |
| Secrets and certificates | [Secret rotation runbook](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/SECRET_ROTATION_RUNBOOK.md) |
| Configuration changes | [Configuration management plan](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/CONFIGURATION_MANAGEMENT_PLAN.md) |
| Offboarding and media | [Sanitization and offboarding](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/MEDIA_SANITIZATION_AND_OFFBOARDING.md) |
| Known remediation work | [POA&M tracker](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/POAM_TRACKER.md) |
| Complete operations index | [Operations pack](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/README.md) |

These documents are procedures and record templates. A blank completion record is not evidence that the work was performed.

## Backups and key changes

Validate restores in an isolated environment with the intended application revision and database configuration. Include access, tenant scope, audit readability, and session revocation in the restore checks.

Preserve access to the MFA encryption key when restoring encrypted per-user MFA secrets. Rotating `MFA_MASTER_SECRET` needs a tested migration or re-enrollment procedure; changing the setting by itself does not re-encrypt stored secrets.

Current JWT helpers support a previous signing key. Choose a documented overlap or forced-relogin strategy, verify token acceptance/rejection, and remove an obsolete previous key after the planned window. The older secret-rotation runbook should be reconciled with this implementation before use.

Changing `ADMIN_PASSWORD` in the environment does not reset an existing owner account. Use a tested account recovery procedure.

## Documentation maintenance

The source pages are in [docs/wiki/](https://github.com/mrbrown3393-oss/aegis-soc/tree/main/docs/wiki). Keep their implementation claims aligned with route definitions, configuration checks, and actual evidence when the code changes.

Repository documentation changes do not automatically update the separate GitHub Wiki. Publish the corresponding pages, sidebar, and footer through wiki editing or the wiki Git repository.
