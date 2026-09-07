# Roadmap

The open edition is a **checker**: it tells you, at boot time, whether the agent's
memory and convention layer is intact — and it never crashes doing so.

The full design that emerged from four rounds of 200-round multi-agent adversarial
reviews goes further: a **memory boot-check protocol** with the loop
`detect → re-inject → self-repair → prove`.

Items are split by where they belong. Nothing on this page is claimed as shipped
when it isn't.

## Open edition (this repo)

Planned, zero-dependency-first, driven by real failure scenarios (YAGNI enforced):

| Item | Status | Note |
|---|---|---|
| fingerprint / size / archive / tamper / freshness checks | ✅ shipped (v1.x) | the core checker |
| optional semantic-drift hook | planned | calls an *external* embedding script; core stays stdlib |
| memory change proposal companion tool (diff + approval before core-region edits) | planned | separate CLI, same zero-dep philosophy |
| more red-team corruption scenarios in the test suite | ongoing | each release adds scenarios from real incidents |

## Partnership edition (co-developed / early access)

Designed in depth through the review rounds, implemented with and for partners.
These solve failure modes that single-user setups don't hit yet, but production
agent fleets do:

| Capability | Failure mode it addresses |
|---|---|
| Tiered memory (core-convention / working / long-term / audit-log zones) with per-zone check policy | one flat file = diluted attention and noisy checks |
| Dual fingerprints (verbatim + semantic equivalence) | a rule reworded with identical meaning silently fails a hash check — or worse, passes while corrupted |
| Detect-and-repair loop (re-injection of lost core conventions, idempotent repair IDs) | today the tool reports; tomorrow it fixes, provably exactly once |
| Transactional memory writes (write-ahead log, two-phase commit for the core zone) | a crashed edit half-applied = corrupted memory |
| Multi-tenant isolation & per-tenant baselines | shared memory = cross-tenant leaks |
| HMAC-signed baseline & append-only audit trail | the baseline itself can be tampered with |
| Compliance reporting (audit export, retention policy, data-removal with certificate) | regulated industries need evidence, not console output |
| Dashboard & monitoring adapters (structured logs, metrics, alerting) | a boot check nobody looks at is theater |

## For partners

Design partners get early access to the protocol specifications above, a voice in
how they freeze, and integration support. See the
[Partnership section in the README](README.md#partnership-edition).
