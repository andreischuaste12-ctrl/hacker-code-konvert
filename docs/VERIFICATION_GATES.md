# Finding Verification Gates

Every scanner result begins as a `candidate`. A result becomes `validated` only after all applicable gates pass with recorded evidence.

## Gate 1: Authorization and Scope

Confirm that the repository, revision, analysis mode, and performed operations are authorized. Static source access does not authorize requests against deployed systems.

Failure outcome: stop the out-of-scope operation. Do not classify the target behavior.

## Gate 2: Coherent Claim

State the alleged weakness, root cause, trigger, attacker capability, affected component, and expected impact. A vague or internally inconsistent claim remains a candidate.

Failure outcome: `false_positive` only when the claim is disproved; otherwise `candidate` with missing facts.

## Gate 3: Code and Version Applicability

Confirm that the referenced code is active in the analyzed revision or that the dependency ecosystem, package, installed version, and advisory range match exactly. Test fixtures, generated code, unreachable branches, and unused dependencies require explicit treatment.

Failure outcome: `false_positive` when the code or vulnerable version is demonstrably not applicable.

## Gate 4: Attacker Control and Reachability

Trace the relevant data or control flow. Establish whether the stated attacker can reach the code and influence the value or state required to trigger the behavior. Record callers, validation, transformations, and trust-boundary crossings.

Failure outcome: `candidate` when reachability is unknown; `false_positive` when controls provably prevent the path.

## Gate 5: Vulnerability Mechanism

Demonstrate why the operation violates a security property. Pattern similarity alone is insufficient. Use source-to-sink reasoning, version evidence, protocol rules, or mathematical bounds appropriate to the weakness class.

Failure outcome: `false_positive` when the mechanism is disproved; otherwise `candidate`.

## Gate 6: Realistic Impact

Describe the consequence under explicit conditions. Separate confidentiality, integrity, availability, authorization, and downstream-system impacts. Do not inflate impact to fit a desired severity.

Failure outcome: reclassify as informational or keep as a candidate if security impact remains uncertain.

## Gate 7: Environmental and Compensating Controls

Evaluate authentication, authorization, sandboxing, framework guarantees, deployment configuration, upstream validation, and other controls. A control reduces severity only when evidence shows it applies to the analyzed path.

Failure outcome: revise the conditions, severity, or verdict according to the observed control.

## Gate 8: Safe Validation Evidence

Provide the safest evidence sufficient to support the conclusion. Acceptable evidence can include static traces, exact advisory matches, unit tests, pseudocode, isolated fixtures, or authorized demonstrations. Executable exploitation is not required by default.

Failure outcome: `candidate` if the claim is plausible but evidence is insufficient.

## Gate 9: Independent Human Review

A human reviewer confirms the evidence, status, severity, confidence, redaction, and remediation before a finding is called a confirmed vulnerability or communicated externally.

Failure outcome: remain `candidate`.

## Verdict Rules

| Status | Requirement |
| --- | --- |
| `candidate` | A signal exists, but one or more required gates remain unresolved. |
| `validated` | All applicable gates pass and human review is recorded. |
| `false_positive` | Evidence disproves applicability, reachability, mechanism, or security impact. |
| `accepted_risk` | An authorized owner accepts a validated risk and records the rationale and review date. |

Missing evidence is not evidence that a finding is false. A clean scanner result is not evidence that the repository has no vulnerabilities.

## Analysis Profiles

Filtering is profile-specific rather than globally hard-coded:

- `repository`: full static review of the selected revision;
- `differential`: security review of a pull request, commit, or diff with baseline context;
- `dependency`: dependency and supply-chain analysis;
- `ecommerce`: authorized application review using relevant web, API, payment, and platform context;
- `active`: separately authorized interaction with named deployed targets.

Denial of service, rate limiting, open redirects, memory safety, and similar categories may be low priority in one profile and critical in another. They may be filtered only with a documented threat-model reason.

## Differential Review Additions

For the `differential` profile, also record:

- the baseline and head revisions;
- all security-relevant changed files;
- removed validation or authorization logic;
- affected callers and estimated blast radius;
- related tests and untested security paths;
- regressions against historical fixes or security invariants.
