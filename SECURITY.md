# Security Policy

## Using AVCI legally

AVCI is an **offensive** security tool. It is built exclusively for targets
you are authorized to test: your own systems, your lab, pentest engagements
with a signed agreement, and bug-bounty scope. Running it against anything
else may be a crime in your jurisdiction. The authors do not condone and are
not responsible for unauthorized use.

The scope guard is fail-closed and is a safety rail, not a legal opinion.
Authorization remains your responsibility.

## Reporting a vulnerability IN AVCI

If you find a security issue in AVCI itself (e.g. a scope-guard bypass, a
way for a target to inject into the agent loop, evidence-vault tampering):

- **Do not** open a public issue.
- Email the maintainers (or open a private GitHub Security Advisory on the
  repository) with a description, reproduction, and impact.
- We aim to acknowledge within 72 hours and ship a fix or mitigation as
  quickly as the issue allows.

Hardening notes for operators:

- Treat MCP servers and target-controlled content as hostile input. AVCI
  strips invisible characters from MCP results and LLM tool output, but the
  model can still be socially engineered by a page — review runs that
  touched production systems.
- The auth vault encrypts at rest when `cryptography` is installed; protect
  `runs/` and `configs/` like you protect browser profiles.
- `AVCI_ENABLE_SQLMAP=1` enables active SQL exploitation through sqlmap —
  only under explicit rules of engagement.
