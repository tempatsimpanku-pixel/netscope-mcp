# Security Policy

## Supported versions

Only the latest released minor version receives security fixes while the project is `0.x`.

| Version | Supported |
|---|---|
| latest `0.x` | yes |
| older | no |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: *Security → Report a vulnerability* (Private Vulnerability
Reporting) on `<repository URL>`, or by email to `<security contact address>`. Please include:

- affected version / commit, RouterOS version if relevant;
- a minimal input (tool call or request) that reproduces the problem;
- the impact you observed (what could be read, written or reached);
- whether you want to be credited.

Do not include real credentials, real customer data or real router addresses in a report.

**What to expect**

- acknowledgement within **72 hours**;
- an initial assessment (accepted / not a vulnerability / need more information) within **7 days**;
- a fix or mitigation for confirmed issues, normally within **90 days**; coordinated disclosure
  after a fix is released or after 90 days, whichever comes first (earlier if the issue is already
  being exploited). We credit reporters unless they ask us not to.

## Scope

In scope:

- **Allowlist bypass** – any input that makes the tool send a RouterOS command other than
  `print`, `monitor … once`, `/<menu> export hide-sensitive`, `ping` or `traceroute`, or that reaches a
  menu/column outside the positive list.
- **Secret disclosure** – credentials, keys, pre-shared secrets, community strings or script bodies
  appearing in tool output, error messages, logs, process arguments or on disk with weak permissions.
- **SSRF / scanning** – `ping`/`traceroute`/SNMP used to reach loopback, link-local, multicast or
  other targets the configuration forbids, or to resolve names.
- **Transport** – authentication or Host/Origin validation bypass of the optional HTTP transport.
- **Resource abuse** – inputs that make a router or the host process consume unbounded resources
  (stream commands, unbounded output, unbounded concurrency).
- **Supply chain** – tampered release artefacts, dependency confusion, leaked secrets in the repository or package.

Out of scope:

- Vulnerabilities in RouterOS itself, in your MCP client, or in the language model provider.
- Attacks that require an attacker who already has the router credentials, root on the MCP host, or
  write access to the configuration files.
- Findings that depend on running the tool with a RouterOS account that has write/sensitive
  policies (see “Limits of the guarantee”).
- Denial of service by flooding the MCP endpoint from a host that already holds a valid token.
- Social-engineering of the operator.

## Threat model (short)

**Assets:** access to production routers; customer data visible through routers (PPP user names,
MAC addresses, DHCP leases, ARP, queue names, logs); router stability.

**Actors:** (1) a language model steered by prompt injection – the main adversary: it can call any
tool with any text; (2) another local process or a web page attempting to reach the HTTP transport;
(3) a machine-in-the-middle on the management network; (4) an operator who misconfigures the tool.

**Controls**

| Layer | Control |
|---|---|
| Input | Deny-by-default command planner: closed character set, positive list of menus and verbs, `where` limited to equality, secret columns refused in `where`/`proplist`, `export` only with `hide-sensitive`, heavy tables require `count-only`/`where`, API words built from validated parts (no free-form sentences). |
| Probes | `ping`/`traceroute` accept literal IP addresses only; loopback, link-local, multicast, broadcast and unspecified addresses (in every textual form) are refused; count/size/hop limits; per-target throttle. |
| SNMP | Read-only GET/GETNEXT/GETBULK on an OID allowlist; row cap. |
| Output | Secret redaction by key name and by pattern, exact scrubbing of the known credentials in errors; optional PII redaction. |
| Transport | stdio by default; HTTP binds to loopback, requires a bearer token, validates `Host` and `Origin`, accepts POST only, bounded body, no CORS headers. |
| Router | **Dedicated read-only RouterOS user** – see [ROUTEROS-READONLY-USER.md](docs/ROUTEROS-READONLY-USER.md). |
| Resources | Global and per-device concurrency limits, timeouts, row limits. |

## Limits of the guarantee

- **The allowlist is not a sandbox.** It lowers the chance that a model can do harm; it does not
  replace RouterOS permissions. The security of a deployment rests on the router-side read-only
  account. Running the tool with a full-access account voids the read-only claim.
- **Redaction is best-effort.** It is key-name and pattern based. Secrets placed in free-text fields
  (for example a router `comment`) or under unusual key names can pass through. The `sensitive`
  policy being denied on the router is the control that actually keeps secrets out of replies.
- **Customer data reaches the model provider.** Tool output is returned to your MCP client and is
  therefore sent to whichever model provider you use. Enable `redact_pii`, review data-protection
  obligations that apply to you (for example GDPR or Indonesia's PDP law) and avoid the log tool
  where logs contain subscriber identifiers.
- **Transport security is your configuration.** Use API-SSL with certificate verification, pin SSH
  host keys, keep credential files at mode `0600`, keep the HTTP transport on loopback.
- **Probing still maps your network.** Private addresses remain valid probe targets unless you set a
  deny list; ICMP only, no port scanning.
- **IPv6 probe targets.** `::`, `::1`, `fe80::/10` and `ff00::/8` are refused; IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) forms are checked against the IPv4 rules. Other IPv6 addresses (including ULA `fc00::/7`) stay valid targets unless you list them in `probe.deny_cidrs`.
- **Error text is scrubbed by keyword.** In error messages the word after `password`, `key`, `token`, `secret`, `community`, `psk` is masked, which can also hide harmless words; that is deliberate.
- **Unknown-section `add` rows.** When redaction sees an `add … name=` row without its `/section` header, a credential-looking `name` (10+ characters mixing digits, lower and upper case) is masked; plain names are kept.
- No guarantee is given for RouterOS versions or policy names that were not tested; run the
  acceptance tests in the read-only user guide on your version.

## Hardening checklist for operators

1. Create the `mcp-readonly` group and user, and run the acceptance tests.
2. Use API-SSL (8729) with a verified certificate; disable plain API.
3. Prefer stdio; if you use HTTP, bind to `127.0.0.1` and keep the token in a `0600` file or environment variable.
4. Leave `redact_pii` on, keep local probing and snapshots off unless you need them.
5. Keep dependencies current (Dependabot / `npm audit`) and verify release provenance.
