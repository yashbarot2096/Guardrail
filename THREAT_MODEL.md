# Guardrail — Threat Model

This document identifies what Guardrail protects, who might attack it, and
how each part of the system responds — including what it does **not** yet
cover. See `README.md` for the architecture diagram; this document focuses
on threats and mitigations per component.

## 1. Scope

**In scope:** the AWS account this project runs in, the detection/response
pipeline (CloudTrail → EventBridge → Lambda → SNS), the 50-user IAM lab,
and the GitHub repository.

**Out of scope:** multi-account/AWS Organizations, production traffic,
formal compliance mapping (e.g. CIS Benchmarks), and defending against a
sophisticated attacker already operating inside the account undetected.

## 2. Assets

| Asset | Why it matters |
|---|---|
| CloudTrail logs | The only record of what happened in the account; must be trustworthy |
| IAM credentials (lab users, admin, root) | Account takeover is the worst-case outcome |
| Data in S3 buckets | Public exposure is the primary scenario this project defends against |
| The remediation Lambdas' own IAM roles | If misused, could cause damage or blind the defenses they run |
| Terraform state | Reveals account structure; currently stored locally, not remotely |
| The GitHub repository | Must never leak the above, once public |

## 3. Threat actors considered

- **Opportunistic bots** scanning public GitHub repos for leaked AWS keys — the single most realistic threat to a project like this.
- **A careless but non-malicious user** misconfiguring a resource (the main scenario the S3 remediation defends against).
- **An attacker who already holds one IAM user's leaked credentials** (the scenario the key-quarantine response defends against).
- *Not modeled in depth:* a malicious insider, or an attacker already inside the account with elevated access — both are partially reduced by the permission boundary and deny statements, but not specifically detected.

## 4. Threats, mitigations, and residual risk

### CloudTrail & log bucket
| Threat | Mitigation | Residual risk |
|---|---|---|
| Attacker disables logging to hide tracks | Lab users are denied `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` via the permission boundary | The account admin is *not* restricted by this (by necessity) — if the admin's credentials are compromised, logging could still be disabled |
| Log data read by an unauthorized party | SSE-KMS encryption, bucket policy denies insecure transport, all public access blocked | None identified |
| Log files tampered with after writing | Versioning enabled, lab users denied `DeleteObject`/`DeleteObjectVersion` on the log bucket, CloudTrail log file validation enabled | The account admin can still delete log objects — true of almost any AWS account; mitigated by requiring MFA on that account and minimizing its routine use |

### IAM lab (prevent layer)
| Threat | Mitigation | Residual risk |
|---|---|---|
| A lab user tries to widen their own access | Permission boundary denies `iam:Create*/Attach*/Put*/Update*/Delete*` etc. regardless of what their own policy allows | The boundary must be re-reviewed as AWS adds new IAM actions over time |
| A lab user acts without MFA | A require-MFA policy denies nearly all actions unless `aws:MultiFactorAuthPresent` is true | Programmatic access keys don't carry an interactive MFA context — a leaked access key could still authenticate. This is exactly the gap the key-quarantine response (below) exists to contain |

### S3 public-bucket remediation (respond layer)
| Threat | Mitigation | Residual risk |
|---|---|---|
| A bucket is made public via policy, ACL, or Block Public Access change | EventBridge rule on those 4 CloudTrail events triggers a Lambda that re-enables Block Public Access within minutes | Only reacts to **change events** — a bucket already public before this system existed, or opened through a method outside the 4 watched API calls, isn't caught until a manual Access Analyzer review |
| The remediation Lambda's own role is misused | Role is limited to reading/setting Block Public Access and tags, plus publishing alerts — no `s3:GetObject`, no delete permissions | The role's resource scope is `*` across S3, since future bucket names can't be known in advance — accepted trade-off, documented here |
| Someone misuses the exemption tag to keep a bucket open indefinitely | The tag is plain, visible, and auditable — not a hidden bypass | Nothing currently alerts when a new exemption tag is added; a future improvement |

### Leaked IAM key response (respond layer)
| Threat | Mitigation | Residual risk |
|---|---|---|
| A leaked key is used before it's deactivated | Responds automatically the moment AWS attaches its quarantine policy, with no human in the loop | The time between the actual leak and **AWS's own detection** of it is outside this project's control — Guardrail shortens detection-to-containment, not leak-to-detection |
| The Lambda disables the wrong user (e.g. the real admin) | Defense in depth: a `PROTECTED_USERS` check in the code, **and** a hard `Deny` in the Lambda's IAM role for that exact username — a code bug alone can't override the second control | None identified for the protected user; other usernames are not protected unless added to the list |
| Attacker creates a new key after quarantine to regain access | AWS's own `AWSCompromisedKeyQuarantine` policy denies `iam:CreateAccessKey` for the quarantined user | Relies on AWS's managed policy rather than Guardrail's own code — worth knowing where the responsibility actually sits |

### Terraform state & local credentials
| Threat | Mitigation | Residual risk |
|---|---|---|
| `terraform.tfstate` leaks (laptop theft, backup sync) | Never committed to git — verified against full git history, not just current files | State exists only on one laptop with no backup; losing it would complicate managing this infrastructure. Planned: move to encrypted, locked S3 remote state |
| The AWS CLI credentials on the laptop are stolen | No mitigation beyond OS-level device security | This is the single highest-value target in the whole system — effectively a master key to the account. Mitigated by requiring MFA on the account and rotating this key periodically |

### GitHub repository (public)
| Threat | Mitigation | Residual risk |
|---|---|---|
| A future commit accidentally includes a secret | `.gitignore` has excluded all sensitive file patterns since the first commit; history audited clean before going public | `.gitignore` doesn't stop a secret hardcoded *inside* a normal file by mistake — planned: add automated secret scanning in CI |
| The public repo aids account reconnaissance | All resource names are generic (`guardrail-*`); no account IDs or real ARNs are hardcoded — everything is resolved dynamically via Terraform data sources | Accepted — normal for any public infrastructure-as-code project |

## 5. Known limitations (explicit)

- GuardDuty and IAM Access Analyzer currently produce findings but aren't yet wired into the automated response pipeline.
- No automated response for compromised EC2 instances yet.
- Single AWS account, single region (`us-east-1`) — no AWS Organizations or SCPs.
- No automated secret scanning in CI yet (planned alongside the CI/CD pipeline).
- Terraform state is local only, with no remote backend or state locking yet.
- The S3 threat model assumes a well-meaning but fallible actor (misconfiguration), not a sophisticated attacker already inside the account.

## 6. Assumptions

- The AWS account's root user and admin IAM user have MFA enabled. *(To verify.)*
- This is a personal learning account, not a production environment handling real user data.
- The realistic threats modeled here are common real-world incidents — leaked keys, misconfigured buckets — not nation-state-level AWS exploitation techniques.