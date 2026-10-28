# L4 XDP configuration — panel (backend / frontend) changes

Guide for updating the Dorian **backend** and **frontend** L4 XDP settings page so they stay in sync with Sparta’s adaptive `firewall.config` and Angelos.

**Edge status (already done):**

- Sparta reads adaptive keys (`prefer_adaptive`, `detection_level`, `alert_hold_windows`, …).
- Angelos `POST /API/L4/l4_firewall_data` accepts optional adaptive camelCase fields and merges without inventing classic-only rows.
- Angelos periodically `POST`s `report_edge_configure` with the full `l4.firewall_config` key→value map.
- `sparta_cli` merge-writes so classic protection updates no longer wipe adaptive keys.

**Reference files on the edge:**

| Path | Role |
|------|------|
| `ebpf_firewall/firewall.config` | Canonical adaptive template |
| `plan/firewall.redesign.config` | Full redesign + panel tiers `[T1]`/`[T2]`/`[T3]` |
| `api_parser/angelos_api.yml` → `L4ConfigPush` | Push schema (classic + adaptive) |
| `api_parser/routes/l4_routes.py` → `_ADAPTIVE_PAYLOAD_MAP` | camelCase → snake_case mapping |
| `api_parser/core/edge_list_sync.py` | Edge → panel snapshot |

---

## 1. Mental model change

| Classic (old panel) | Adaptive (current Sparta) |
|---------------------|---------------------------|
| Host-wide `*Threshold` starts Attack | Shadow EWMA/CUSUM + `detection_level` starts Attack |
| `*ProtectionDuration` | Attack lifecycle: confirm / exit / quiet clear / cooldown |
| `blackIpDuration` | `block_initial_seconds` + `block_max_seconds` (doubling) |
| Single “sensitivity” → classic thresholds | **Detection level 1..10** (main owner knob) |
| Class burst/fixed = always-on flood caps | Class burst/fixed = **mitigation while in Attack** |

When `prefer_adaptive = 1` on a node, do **not** treat `synThreshold` / `ackThreshold` / `*ProtectionDuration` / `blackIpDuration` as source of truth. Adaptive configs often omit those keys; Angelos will **not** append them to disk.

---

## 2. Sync flows

```
┌─────────────┐  report_edge_configure   ┌──────────┐
│ Angelos     │ ───────────────────────► │ Backend  │ ──► store / UI form
│ (edge)      │   l4.firewall_config{}   │ (panel)  │
│             │ ◄─────────────────────── │          │
│ l4_firewall │   L4ConfigPush JSON      └──────────┘
│ _data       │
└──────┬──────┘
       │ merge firewall.config + RELOAD_FW / set_protection
       ▼
   Sparta
```

### Edge → panel (read)

- Endpoint: `POST {API_BASE}/report_edge_configure`
- Payload field: `l4.firewall_config` — flat `Record<string, string>` (snake_case keys, comments already stripped).
- Also: `l4.whitelist`, `l4.blocklist`.

**Backend should:** upsert the **entire** map (or all keys listed below), not only the old classic columns. Use this snapshot to populate the L4 XDP form.

### Panel → edge (write)

- Endpoint: `POST /API/L4/l4_firewall_data` on the agent (path overridable via `agentL4Path`).
- Body: existing classic camelCase fields **plus** optional adaptive fields (see §4).
- Auth: agent token as today.

**Backend should:** when saving, send adaptive fields for adaptive nodes; keep sending classic fields for backward compatibility with older edges, but expect Angelos to **ignore classic keys that are absent** from the edge file.

---

## 3. Frontend — page structure

### 3.1 Primary (owner / T1) — always show

| UI control | JSON field (push) | Config key (report) | Notes |
|------------|-------------------|---------------------|-------|
| NIC / bond | `dev` | `dev` | Restart required |
| Attach mode | `attachMode` | `attach_mode` | `native` / `generic` / … |
| **Detection level** | `detectionLevel` | `detection_level` | Integer **1..10**; default **5**. Replaces old sensitivity as main knob |
| Block initial TTL | `blockInitialSeconds` | `block_initial_seconds` | Suggested range 60–600 |
| Block max TTL | `blockMaxSeconds` | `block_max_seconds` | Suggested range 300–7200 |
| HTTP/3 | `serviceHttp3` | `service_http3` | bool |
| DNS | `serviceDns` | `service_dns` | bool |
| GRE tunnels | `serviceGreTunnels` | `service_gre_tunnels` | bool |
| Geo allow/block | `geoCheck`, `geoAllowCountries`, `geoCountriesBlockMode` | `geo_check`, `geo_countries` | Unchanged |
| Per-src conn limit | `tcpConnectionLimitCheck`, `tcpConnectionLimitCnt` | `tcp_connection_limit_*` | Unchanged |
| TCP segment check | `tcpSegCheck` | `tcp_seg_check` | Unchanged |

**Detection level labels (suggested):**

| Value | Label |
|------:|-------|
| 1 | Minimal |
| 2 | Very low |
| 3 | Low |
| 4 | Moderate low |
| 5 | Normal *(default)* |
| 6 | Moderate high |
| 7 | Elevated |
| 8 | High |
| 9 | Very high |
| 10 | Max |

If the UI still has a 3-way “sensitivity”, map it for display only, e.g. low→3, medium→5, high→8, and persist `detectionLevel`.

### 3.2 Attack mitigation limits (T1) — keep, relabel

Relabel section from “flood thresholds” to **“Limits while under Attack”**.

Per class (SYN / ACK / RST / ICMP / UDP / GRE / STOMP / SOCKET):

| Control | Push field example | Config key |
|---------|--------------------|------------|
| Enable | `synValid` | `syn_valid` |
| Burst packets | `synBurstPkt` | `syn_burst_pkt` |
| Burst count/sec | `synBurstCountPerSec` | `syn_burst_count_per_sec` |
| Fixed threshold | `synFixedThreshold` | `syn_fixed_threshold` |
| Fixed window (s) | `synFixedCheckDuration` | `syn_fixed_check_duration` |
| SYN cookie timeout | `challengeTimeout` | `challenge_timeout` |

Same pattern for `ack*`, `rst*`, `icmp*`, `udp*`, `gre*`, `stomp*`, `socket*` (`socketFinThreshold` instead of burst).

### 3.3 Advanced / admin (T2) — add

| UI control | Push field | Config key | Default (current template) |
|------------|------------|------------|----------------------------|
| Prefer adaptive | `preferAdaptive` | `prefer_adaptive` | `true` / `1` |
| Drop invalid in Attack | `enforceDropInvalid` | `enforce_drop_invalid` | `true` |
| Alert hold (s) | `alertHoldWindows` | `alert_hold_windows` | `5` — defers panel/episode START |
| Quiet clear (s) | `quietClearWindows` | `quiet_clear_windows` | `10` |
| Confirm windows | `confirmWindows` | `confirm_windows` | `3` |
| Exit windows | `exitWindows` | `exit_windows` | `45` |
| Cooldown (s) | `cooldownSeconds` | `cooldown_seconds` | `90` |
| Escalate after (s) | `escalateAfterWindows` | `escalate_after_windows` | `5` |
| Baseline k / m | `baselineK`, `baselineM` | `baseline_k`, `baseline_m` | `6` / `3` |
| Learning days | `learningDays` | `learning_days` | `0` = short warm-up |

### 3.4 Hide or demote when adaptive

When node report has `prefer_adaptive === "1"` (or form `preferAdaptive`):

| Old field | Action |
|-----------|--------|
| `synThreshold`, `ackThreshold`, … | Hide or show read-only “legacy / unused” |
| `synProtectionDuration`, … | Hide |
| `blackIpDuration` | Hide; use block initial/max instead |
| Old sensitivity enum only | Replace with detection level |

Still **accept** these in the push payload for classic edges (`prefer_adaptive` missing or `0`).

---

## 4. Backend — data model & API

### 4.1 Persist from `report_edge_configure`

Recommended storage: JSON/JSONB column or key-value table keyed by edge/node id:

```json
{
  "prefer_adaptive": "1",
  "detection_level": "5",
  "alert_hold_windows": "5",
  "dev": "bond0",
  "attach_mode": "native",
  "syn_valid": "1",
  "syn_fixed_threshold": "300"
}
```

Parse integers/bools in the API layer when serving the frontend; keep raw strings from the edge if useful for round-trip fidelity.

### 4.2 Push body — adaptive fields Angelos accepts

Optional fields on `L4ConfigPush` (camelCase). Types as enforced by Angelos:

```text
preferAdaptive            boolean → 0|1
enforceDropInvalid        boolean → 0|1
detectionLevel            integer 1..10
alertHoldWindows          integer
quietClearWindows         integer
confirmWindows            integer
exitWindows               integer
cooldownSeconds           integer
escalateAfterWindows      integer
blockInitialSeconds       integer
blockMaxSeconds           integer
baselineK                 integer
baselineM                 integer
baselineSeasonal          string   (e.g. hour_of_week | off)
learningDays              integer
cusum                     boolean
invalidFloorPps           integer
invalidRatio              number
flowPpsK                  integer
srcBucketK                integer
serviceHttp3              boolean
serviceDns                boolean
serviceGreTunnels         boolean
quicHeaderCheck           boolean
icmpDropFragments         boolean
synackMatchOutbound       boolean
nicDropTriggerSeconds     integer
softirqTriggerPercent     integer
softirqTriggerSeconds     integer
attackLogDir              string
ipv6                      boolean
statsDetailSampleDivisor  integer
```

Snake_case keys in the same JSON are also accepted as a passthrough for adaptive keys.

### 4.3 Classic fields — keep for compat

Continue sending the existing required classic set when talking to older agents. On adaptive agents, Angelos only updates keys **already present** in `firewall.config` (plus adaptive allow-list). Safe to send `synThreshold: 0` etc.; they will be **skipped** if the adaptive file has no such line.

### 4.4 Validation suggestions (panel)

| Field | Rule |
|-------|------|
| `detectionLevel` | 1–10 |
| `blockInitialSeconds` | 60–600 |
| `blockMaxSeconds` | ≥ `blockInitialSeconds`, ≤ 7200 |
| `alertHoldWindows` | ≥ 1 (recommend 3–10) |
| `geoAllowCountries` | ISO-3166 alpha-2 list |

### 4.5 After save

- Agent merges file; adaptive-only changes trigger `RELOAD_FW`.
- `dev` / `attachMode` changes trigger firewall restart (existing behaviour).
- Next `report_edge_configure` should reflect saved values; refresh UI from that report when possible.

---

## 5. Minimal first ship (recommended)

1. **Backend:** store full `l4.firewall_config` from reports; expose it to the L4 settings API.
2. **Frontend:** add **Detection level**, **Alert hold (s)**, **Block initial / max**.
3. **Frontend:** relabel class burst/fixed section as Attack mitigation.
4. **Backend push:** include `detectionLevel`, `alertHoldWindows`, `blockInitialSeconds`, `blockMaxSeconds` (and `preferAdaptive: true` if you expose the toggle).
5. **Stop** overwriting adaptive nodes with only classic threshold fields as the “real” config.

Defer full advanced lifecycle / baseline / NIC softirq controls to a follow-up if needed.

---

## 6. Example push payload (adaptive-focused)

Illustrative; classic fields still included for older agents:

```json
{
  "token": "<agent-token>",
  "id": 1033,
  "dev": "bond0",
  "attachMode": "native",
  "preferAdaptive": true,
  "enforceDropInvalid": true,
  "detectionLevel": 5,
  "alertHoldWindows": 5,
  "quietClearWindows": 10,
  "confirmWindows": 3,
  "exitWindows": 45,
  "cooldownSeconds": 90,
  "escalateAfterWindows": 5,
  "blockInitialSeconds": 60,
  "blockMaxSeconds": 3600,
  "serviceHttp3": true,
  "serviceDns": false,
  "serviceGreTunnels": false,
  "blackIpDuration": 3600,
  "synValid": true,
  "synThreshold": 0,
  "synBurstPkt": 50,
  "synBurstCountPerSec": 5,
  "synFixedThreshold": 300,
  "synFixedCheckDuration": 3,
  "challengeTimeout": 3,
  "synProtectionDuration": 0,
  "ackValid": true,
  "ackThreshold": 0,
  "ackBurstPkt": 300,
  "ackBurstCountPerSec": 50,
  "ackFixedThreshold": 5000,
  "ackFixedCheckDuration": 15,
  "ackProtectionDuration": 0,
  "rstValid": true,
  "rstThreshold": 0,
  "rstBurstPkt": 10,
  "rstBurstCountPerSec": 5,
  "rstFixedThreshold": 500,
  "rstFixedCheckDuration": 10,
  "rstProtectionDuration": 0,
  "icmpValid": true,
  "icmpThreshold": 0,
  "icmpBurstPkt": 10,
  "icmpBurstCountPerSec": 5,
  "icmpFixedThreshold": 200,
  "icmpFixedCheckDuration": 10,
  "icmpProtectionDuration": 0,
  "udpValid": true,
  "udpThreshold": 0,
  "udpBurstPkt": 50,
  "udpBurstCountPerSec": 10,
  "udpFixedThreshold": 30000,
  "udpFixedCheckDuration": 10,
  "udpProtectionDuration": 0,
  "greValid": true,
  "greThreshold": 0,
  "greBurstPkt": 10,
  "greBurstCountPerSec": 5,
  "greFixedThreshold": 50,
  "greFixedCheckDuration": 10,
  "greProtectionDuration": 0,
  "stompValid": true,
  "stompThreshold": 0,
  "stompBurstPkt": 50,
  "stompBurstCountPerSec": 10,
  "stompFixedThreshold": 5000,
  "stompFixedCheckDuration": 10,
  "stompProtectionDuration": 0,
  "socketValid": true,
  "socketFinThreshold": 100,
  "socketFixedThreshold": 500,
  "socketFixedCheckDuration": 15,
  "tcpSegCheck": true,
  "geoCheck": false,
  "geoDbIpv4Path": "geodb/ipv4.csv",
  "geoDbLocationPath": "geodb/location.csv",
  "geoAllowCountries": [],
  "geoCountriesBlockMode": false,
  "tcpConnectionLimitCheck": true,
  "tcpConnectionLimitCnt": 1000
}
```

---

## 7. Example report snippet (edge → panel)

```json
{
  "command": "report_edge_configure",
  "l4": {
    "firewall_config": {
      "prefer_adaptive": "1",
      "detection_level": "5",
      "alert_hold_windows": "5",
      "quiet_clear_windows": "10",
      "block_initial_seconds": "60",
      "block_max_seconds": "3600",
      "dev": "bond0",
      "attach_mode": "native",
      "syn_valid": "1",
      "syn_fixed_threshold": "300"
    },
    "firewall_config_error": null,
    "whitelist": [],
    "blocklist": []
  }
}
```

Map snake_case → form fields with the inverse of §4.2 (e.g. `detection_level` → `detectionLevel`).

---

## 8. Checklist

### Backend

- [ ] Persist full `l4.firewall_config` from `report_edge_configure`
- [ ] L4 settings GET returns adaptive fields for the UI
- [ ] L4 settings SAVE posts adaptive camelCase fields to the agent
- [ ] Do not fail validation if classic `*Threshold` / `*ProtectionDuration` are 0 / unused on adaptive nodes
- [ ] Optional: feature-flag UI by `prefer_adaptive`

### Frontend

- [ ] Detection level control (1–10)
- [ ] Alert hold + block initial/max
- [ ] Service profile toggles (HTTP/3, DNS, GRE)
- [ ] Relabel class limits as Attack mitigation
- [ ] Hide classic host thresholds when adaptive
- [ ] Load form from last edge report when available

### Verify on a live edge

- [ ] Save from panel → `firewall.config` on edge keeps `prefer_adaptive` / `detection_level` / `alert_hold_windows`
- [ ] Sparta log: `Loaded config: detection_level = …` after save
- [ ] Next `report_edge_configure` shows the saved values on the homepage/settings

---

## 9. Out of scope for this doc

- Changing Sparta detection algorithms
- L7 WAF / temporary blacklist UI
- Hardware offload / upstream FlowSpec / scrubbing (`plan/firewall.redesign.config` Tier 0 / upstream section)
