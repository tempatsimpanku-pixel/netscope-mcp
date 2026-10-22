# Demo: a 75-second NOC session

A scripted scenario for a screen recording. All outputs below are taken from the real output of this version against the simulated RouterOS used by the test suite (see [RECIPES.md](RECIPES.md)); addresses are RFC 5737 documentation addresses and the customer is `alice@example.net`.

**Setup shown on screen (5 s):** `routers.yaml` with `rtr-core-1` (192.0.2.1) and `rtr-edge-1` (192.0.2.11), the read-only RouterOS user, and `claude mcp add netscope ...` (or the Codex `config.toml` block).

## Transcript

**Scene 1: "Is the core healthy?" (about 25 s)**

> **You:** Run the health recipe on rtr-core-1 and tell me if anything looks wrong.

Tool call:

```json
{ "tool": "mikrotik_recipe", "arguments": { "recipe": "health", "device": "rtr-core-1" } }
```

Tool result:

```text
## rtr-core-1
resource: board-name=CCR2004-1G-12S+2XS version=7.16.1 (stable) uptime=41d3h12m55s cpu-load=12 free-memory=1610612736 total-memory=4294967296
health: temperature=46 voltage=24.1
interface: 4 ethernet, 1 down (sfp-sfpplus3)
sfp sfp-sfpplus1: status=link-ok rate=10Gbps sfp-rx-power=-6.8 sfp-tx-power=-2.1 sfp-temperature=38
sfp sfp-sfpplus2: status=link-ok rate=10Gbps sfp-rx-power=-19.4 sfp-tx-power=-2.3 sfp-temperature=39
(2 ms, read-only)
```

> **Assistant:** rtr-core-1 is fine on CPU (12%), memory (about 1.5 GiB free of 4 GiB) and temperature (46 C). Two things to look at: `sfp-sfpplus2` receives -19.4 dBm, which is weak for a 10G optic (compare `sfp-sfpplus1` at -6.8 dBm), so check the fibre and connectors; and `sfp-sfpplus3` is down.

**Scene 2: "Where is this customer?" (about 20 s)**

> **You:** Which router has alice@example.net connected?

```json
{ "tool": "mikrotik_recipe", "arguments": { "recipe": "pppoe-lookup", "name": "alice@example.net" } }
```

```text
## rtr-edge-1
active: name=alice@example.net service=pppoe caller-id=02:00:5E:00:53:2A address=198.51.100.77 uptime=2h14m9s
secret: name=alice@example.net profile=10M disabled=false last-logged-out=2026-10-21 23:58:41
interface: name=<pppoe-alice@example.net> type=pppoe-in running=true disabled=false
(checked without a hit: -)
```

> **Assistant:** She is online on rtr-edge-1 with 198.51.100.77, profile 10M, session up 2 h 14 min. The password was never requested from the router.

**Scene 3: "Fix it!" is refused (about 15 s)**

> **You:** Reboot rtr-core-1 to clear that optic.

```json
{ "tool": "mikrotik_read", "arguments": { "device": "rtr-core-1", "command": "/system reboot" } }
```

```text
mikrotik_read refused: word "reboot" is refused (read-only: only print / monitor once / <menu> export hide-sensitive (full path, e.g. /ip service export hide-sensitive) / ping / traceroute).
```

> **Assistant:** I can't change the router: this server is read-only by design. I'd suggest cleaning and re-seating the SFP on `sfp-sfpplus2`, then I can re-check the receive level for you.

**Closing card (10 s):** "Read-only by construction. Secrets redacted. Apache-2.0. github.com/tempatsimpanku-pixel/netscope-mcp"

## Recording plan

| Item | Choice |
|---|---|
| Tool | [asciinema](https://asciinema.org) for the terminal client, then `agg` to render a GIF for the README; optional MP4 screen capture for the form/social posts |
| Terminal | 100x28, dark theme, font size 16, no prompt clutter (`PS1='$ '`) |
| Client | Claude Code or Codex CLI, with netscope added as MCP server |
| Backend | Real lab routers or the simulated RouterOS from the test suite; **never** real customer data or real IPs on screen. Re-run with documentation addresses if the lab differs |
| Length | 60-90 s; cut waiting time with `asciinema rec --idle-time-limit 1` |
| Output files | `docs/assets/demo.cast`, `docs/assets/demo.gif` (< 3 MB), embed the GIF at the `<!-- demo -->` marker in the README and upload the cast to asciinema.org for the link |
| Pre-flight | `netscope-mcp --config routers.yaml --check`; run once off-camera; check no hostname/IP/credential appears (gitleaks on the cast: `grep` for real prefixes) |

Steps: 1) `asciinema rec demo.cast`; 2) run the three prompts above; 3) `agg --font-size 16 demo.cast demo.gif`; 4) review frame by frame for leaks; 5) commit under `docs/assets/`.
