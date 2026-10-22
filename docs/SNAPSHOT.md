# Snapshot and cross-router search

Live reads are accurate but slow when you need to find one thing among many routers. The optional snapshot worker keeps a recent copy of a few operational tables in a local SQLite file, so a search takes milliseconds and touches no router.

## Enable

```bash
netscope-mcp --config ./routers.yaml --snapshot ./state/snap.sqlite
```

Without `--snapshot`, `mikrotik_snapshot` answers that snapshots are disabled; every other tool works normally. The file (and its directory, if new) is created with mode `0600` (`0700`), and so are the SQLite side files.

## What is collected

Every `settings.snapshot.interval_min` minutes (default **10**, minimum 2), per RouterOS/switch device:

- system resource (CPU, uptime, version, board, free memory)
- interfaces (running/disabled, speed of physical ports, comment)
- neighbors
- ARP (totals, failed entries, per-interface counts, gateway state)
- active PPP sessions: **count only**, unless `settings.snapshot.store_customer_data: true`, which also keeps name, address, caller-id and uptime so they become searchable

No passwords, secrets, keys or community strings are collected; free-text values pass through the same masking as live output.

Scheduling: devices with label `role: core` are polled a third as often (every 3 x interval); a failed device is retried after `(1 + consecutive failures, max 6) x interval`; a rejected login waits at least 30 minutes (lock-out protection); a router with CPU at or above 80% is not asked for the big tables (ARP/PPP) that cycle. Polling uses the same per-device queue and session reuse as live tools.

## Tool: `mikrotik_snapshot`

| Input | Effect |
|---|---|
| (none) | Summary of all routers. |
| `device` (+ `section`: `summary`, `resource`, `interface`, `neighbor`, `arp`, `ppp`) | Detail for one router. |
| `search` (2-64 chars) | Substring, IP or MAC (any common format) in interface names/comments, neighbors, ARP and (if stored) PPP, across **all** routers. |
| `limit` | Max rows, 1-200. |

Every answer states the **age of the data**; data older than 30 minutes is marked **STALE**.

## Examples (real output, simulated routers)

```text
[mikrotik_snapshot] 4 router(s); newest data 0 s, oldest 5 s
rtr-core-1: age 5 s · cpu 12% · up 41d3h12m55s · v7.16.1 · if down 2 · neighbors 2 · arp 2/0 failed · ppp 1
rtr-edge-1: age 3 s · cpu 12% · up 41d3h12m55s · v7.16.1 · if down 2 · neighbors 2 · arp 2/0 failed · ppp 1
rtr-edge-2: age 2 s · cpu 12% · up 41d3h12m55s · v7.16.1 · if down 2 · neighbors 2 · arp 2/0 failed · ppp 1
sw-crs-1: age 0 s · cpu 12% · up 41d3h12m55s · v7.16.1 · if down 2 · neighbors 2 · arp 2/0 failed · ppp 1
Snapshot data (not live): to confirm the current state use mikrotik_read / mikrotik_recipe.
(1 ms, from the snapshot — did not touch any router)
```

```text
[mikrotik_snapshot] search "02:00:5E:00:53:2A" in 4 router(s) — 4 match(es); newest data 0 s, oldest 5 s
rtr-core-1 [ppp] name=alice@example.net address=198.51.100.77 caller-id=02:00:5E:00:53:2A uptime=2h14m9s · age 5 s
rtr-edge-1 [ppp] name=alice@example.net address=198.51.100.77 caller-id=02:00:5E:00:53:2A uptime=2h14m9s · age 3 s
rtr-edge-2 [ppp] name=alice@example.net address=198.51.100.77 caller-id=02:00:5E:00:53:2A uptime=2h14m9s · age 2 s
sw-crs-1 [ppp] name=alice@example.net address=198.51.100.77 caller-id=02:00:5E:00:53:2A uptime=2h14m9s · age 0 s
Snapshot data (not live): to confirm the current state use mikrotik_read / mikrotik_recipe.
(1 ms, from the snapshot — did not touch any router)
```

## When to use which

| Question | Use |
|---|---|
| "Where is this MAC / customer?" (approximate, fast) | snapshot `search` (PPP needs `store_customer_data`) |
| "Is the session up this second?" | `mikrotik_recipe pppoe-lookup` (live) |
| "Anything changed before I touch this router?" | live tools; never rely on a STALE snapshot |

## Operational notes

- The database is safe to delete; it is rebuilt on the next cycle.
- A restart keeps the data; the age shown is the age of the last successful poll per router.
- A router that fails keeps its previous rows, which age and become STALE; the failure is reported with the summary.
- Routers removed from `routers.yaml` are pruned from the file.
- With `store_customer_data: true` the file contains customer identifiers: keep it on an encrypted disk and treat it like your RADIUS data.
