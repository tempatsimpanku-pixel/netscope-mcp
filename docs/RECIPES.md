# Recipes

A recipe is one tool call that replaces many raw RouterOS commands and returns a compact result. Recipes use the same read-only guard as every other tool (every command they run is built through the allowlist).

```json
{ "recipe": "health", "device": "rtr-core-1" }
```

All output below is real output of this version, produced by the test suite against a simulated RouterOS (documentation addresses from RFC 5737, `example.net`). Real routers differ by RouterOS version and hardware. Each response ends with the elapsed time.

---

## `health`

**Input:** `device` (one id, or a list of up to 8). **Required.**

One call for "is this router OK?": system resource, health sensors, ethernet link summary and SFP/optical readings for the ports that are up (down ports are only counted and named). Port names with spaces or `+` (e.g. `sfp+ 1`) are handled; if one SFP cannot be read, its line says `ERROR …` and the other sections are still returned.

```text
[mikrotik_recipe] health
## rtr-core-1
resource: board-name=CCR2004-1G-12S+2XS version=7.16.1 (stable) uptime=41d3h12m55s cpu-load=12 free-memory=1610612736 total-memory=4294967296
health: temperature=46 voltage=24.1
interface: 4 ethernet, 1 down (sfp-sfpplus3)
sfp sfp-sfpplus1: status=link-ok rate=10Gbps sfp-rx-power=-6.8 sfp-tx-power=-2.1 sfp-temperature=38
sfp sfp-sfpplus2: status=link-ok rate=10Gbps sfp-rx-power=-19.4 sfp-tx-power=-2.3 sfp-temperature=39
(2 ms, read-only)
```

Raw values are always shown; the recipe does not invent thresholds, so judge `sfp-rx-power` (above: `sfp-sfpplus2` reads -19.4 dBm) against your optics' datasheet. Routers without a sensor omit that line. One failing section never fails the recipe: it prints `ERROR …` for that section only.

---

## `neighbors-map`

**Input:** `device` (1–8). **Required.**

What is attached to a router: neighbor discovery matched against your inventory (`known <id>` vs `not in inventory`), ARP counts per interface, and interfaces that are down.

```text
[mikrotik_recipe] neighbors-map
## rtr-core-1
edge rtr-core-1[sfp-sfpplus1] -> rtr-edge-1 192.0.2.11 MikroTik = known rtr-edge-1
edge rtr-core-1[ether5] -> ap-north-01 (not in inventory)
arp: 2 entries; bridge=2
interface: 3 total, down: ether8, sfp-sfpplus3
(total 2 edges)
(2 ms, read-only)
```

Neighbor discovery (MNDP/CDP/LLDP) must be enabled on the router for a neighbor to appear. ARP counts are a rough indicator, not a client inventory.

---

## `pppoe-lookup`

**Input:** `name` (PPPoE username; letters, digits, `. _ @ -`, max 64). `device` optional (id or list): **without `device`, every RouterOS router in the inventory is searched** (switches are skipped).

Finds the active session, the `/ppp secret` row using **safe columns only** (the password is never requested from the router), and the dynamic interface.

```text
[mikrotik_recipe] pppoe-lookup
## rtr-edge-1
active: name=alice@example.net service=pppoe caller-id=02:00:5E:00:53:2A address=198.51.100.77 uptime=2h14m9s
secret: name=alice@example.net profile=10M disabled=false last-logged-out=2026-10-21 23:58:41
interface: name=<pppoe-alice@example.net> type=pppoe-in running=true disabled=false
(checked without a hit: -)
(1 ms, read-only)
```

When nothing is found the answer says `"<name>" not found on N router(s)` and lists the routers checked. For a fast fleet-wide search without touching routers, see the snapshot in [SNAPSHOT.md](SNAPSHOT.md).

---

## Related single reads

```text
[rtr-core-1] /ip address print
0 address=192.0.2.1/24 interface=ether1 disabled=false
(6 ms, read-only)
```

A refused command:

```text
mikrotik_read refused: word "reboot" is refused (read-only: only print / monitor once / export hide-sensitive / ping / traceroute).
```

## Writing good prompts

- Use the ids from `list_devices`.
- Ask for a decision ("is anything abnormal?") rather than a dump.
- For fleet questions say "all routers" or give a `group`; the model will use `mikrotik_batch` or a multi-device recipe.
- The server cannot change anything. If asked to, the model will be told the command is refused.
