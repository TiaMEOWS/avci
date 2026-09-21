"""AVCI — Autonomous Offensive Blackbox Hunter.

Design doctrine (each pillar borrowed from the strongest code audited in the
2026-09-17 landscape review, then rebuilt):

  * phased recon fan-out ......... RedAmon's 28-module pipeline doctrine
  * coverage ledger + lifecycle ... strix's `strix.tools.coverage` accounting
  * generic MCP client ............ strix / GH05TCREW `mcpServers.json` pattern
  * temp-mail + OTP + registration  apex (email adapters) + NeuroSploit (mail.tm)
  * auth session persistence ....... xalgorix go-rod cookie/session vault idea
  * evidence oracle on findings .... PriestsBasilisk oracle + pentest-ai probes
  * fail-closed scope guard ........ H-mmer pentest-agents PreToolUse hook
  * rate limiting + politeness ..... Akamai burst-kill lessons (per-host buckets)
  * context compaction ............. strix long-run transcript pruning
  * evidence SHA-256 vault ......... pentest-ai tamper-evident artifacts
  * OOB blind channel .............. interactsh doctrine, zero-dep webhook.site
  * attack chains + compliance ..... pentest-ai chain discovery + PCI/OWASP map
  * TUI dashboard .................. Textual worker-thread hunt view
"""

__version__ = "1.1.0"
