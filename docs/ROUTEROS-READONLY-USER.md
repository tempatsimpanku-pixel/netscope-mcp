# Dedicated read-only RouterOS user for netscope-mcp

**This is the primary safety control.** The tool's command allowlist is a second layer: it is
written to refuse anything but `print`, `monitor … once`, `export hide-sensitive`, `ping` and
`traceroute`, but an allowlist is code and code has bugs. If the account the tool logs in with
cannot write, a bug in the allowlist cannot change your router.

> Do **not** use the built-in `read` group. According to MikroTik's documentation it still carries
> the `reboot` and `sensitive` policies ("Even the read group includes the reboot and sensitive
> policies"). Create a purpose-built group instead.
> Sources: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>,
> <https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User>

Tested against: *to be filled in by the maintainers (RouterOS version + CHR lab)*. Policy names can
differ slightly between RouterOS 6.x and 7.x; always run the acceptance tests below on your version.

## 1. Create the group and the user

Run on the router (replace the placeholders; keep the password out of shell history and chat logs).

```routeros
/user group add name=mcp-readonly \
    policy=api,ssh,read,test,!local,!telnet,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api

/user add name=mcp-ro group=mcp-readonly \
    address=<MCP-HOST-IP>/32 \
    password=<long-random-password> \
    comment="netscope-mcp read-only"
```

What each policy is for:

| Policy | State | Why |
|---|---|---|
| `api` | granted | API login (`print`, `monitor`, `ping`, `traceroute`). Required when you use the API. |
| `ssh` | granted | Only needed for `export hide-sensitive`. Remove it if you never use export. |
| `read` | granted | Read configuration and status. Required. |
| `test` | granted | Needed for `ping`/`traceroute` on some versions. **Not verified from documentation** – confirm in your lab and remove it if ping works without it. |
| `sensitive` | **denied** | Without it, password/key columns are not readable and `export` hides them. This is the main defence against secret disclosure. |
| `write`, `policy`, `reboot`, `password` | **denied** | No configuration changes, no user/policy changes, no reboot, no password changes. |
| `ftp`, `sniff`, `romon`, `rest-api`, `local`, `telnet`, `web`, `winbox` | **denied** | Not needed; closes side channels (file transfer, packet capture, other management planes). |

## 2. Restrict where the account can be used

```routeros
# Only the MCP host may reach the API services
/ip service set api-ssl address=<MCP-HOST-IP>/32 disabled=no
/ip service set api disabled=yes          # plain-text API (port 8728): off when TLS is used
/ip service set ssh address=<MCP-HOST-IP>/32   # only if export over SSH is used

# Give api-ssl a certificate you control (never "anonymous DH" / no certificate)
/certificate add name=api-ssl common-name=<router-name> days-valid=825 key-usage=digital-signature,key-encipherment,tls-server
/certificate sign api-ssl
/ip service set api-ssl certificate=api-ssl

# Keep login failures visible
/system logging add topics=system,account action=memory
```

Plain-text API (8728) sends the password in clear on RouterOS ≥ 6.43; use API-SSL (8729) with a
certificate you pin or verify on the client side
(<https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API>). A mode without a certificate is
unauthenticated and must not be used. One RouterOS user per MCP host; rotate the password if the
host is ever shared or re-imaged.

## 3. Acceptance tests (run these before first use)

Log in as `mcp-ro` (API-SSL or SSH) and confirm **each** of the following. Every "must fail" must
fail on the router itself, with the netscope allowlist out of the picture (use WinBox-less SSH, or the
vendor API client directly).

| # | Command as `mcp-ro` | Expected |
|---|---|---|
| 1 | `/system identity set name=x` | **fails** (not enough permissions) |
| 2 | `/system reboot` | **fails** |
| 3 | `/user add name=t group=mcp-readonly password=x` | **fails** |
| 4 | `/ip address add address=192.0.2.250/32 interface=<any>` | **fails** |
| 5 | `/file print` and `/file remove <anything>` | no secrets listed / **fails** |
| 6 | `/tool fetch url=http://192.0.2.1/x` | **fails** |
| 7 | `/system script add name=t source=":put 1"` | **fails** |
| 8 | `/ppp secret print` | rows appear, **no `password` values** |
| 9 | `/snmp community print` | no authentication/encryption keys |
| 10 | `/user print` | no password hashes |
| 11 | `/ip address print`, `/system resource print`, `/ping 192.0.2.1 count=1` | **works** |
| 12 | `/ip address export hide-sensitive` (if `ssh` is granted) | works, no secrets |
| 13 | Login from an IP other than `<MCP-HOST-IP>` | **refused** |
| 14 | Wrong password 5 times | counted in the log (and blocked if you run a brute-force guard) |

If a "must fail" succeeds, the group is too permissive: do not use it with netscope-mcp until fixed.
If #8–#10 show secrets, the `sensitive` policy is still granted on that version.

## 4. Operations

- Treat the credentials file of netscope-mcp like a router password: mode `0600`, never in the
  repository, never in a chat or ticket.
- Review `/log` for `mcp-ro` logins periodically.
- Re-run section 3 after every RouterOS upgrade (policy sets can change between releases).
- Even with this account the tool can read **customer data** (PPP user names, MAC addresses, DHCP
  leases, ARP, queue names). Keep `redact_pii` on when the output goes to a third-party model provider.
