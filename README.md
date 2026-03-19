# SUP — Systemic Undercover Predator
> Lightweight, real-time Intrusion Detection System for Linux — brute-force detection with Splunk SIEM integration.

![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0-orange?style=flat-square)

---

## What It Does

SUP monitors Linux auth logs in real-time, detects brute-force and privilege escalation patterns using a sliding-window algorithm, and forwards structured JSON alerts to Splunk via HEC.

No agents. No daemons. No bloat.

---

## Detection Rules

| Severity | Trigger | Alert Type |
|----------|---------|------------|
| 🔴 CRITICAL | Root login detected | `ROOT_LOGIN_DETECTED` |
| 🟠 HIGH | 5+ failed SSH logins from same IP in 60s | `BRUTE_FORCE_SSH` |
| 🟠 HIGH | 5+ invalid user attempts from same IP in 60s | `BRUTE_FORCE_SSH` |
| 🟡 MEDIUM | sudo auth failure | `SUDO_ESCALATION_ATTEMPT` |
| 🔵 LOW | PAM auth failure (non-SSH) | `PAM_AUTH_FAILURE` |

---

## Quick Start

**1. Clone & install**
```bash
git clone https://github.com/Mitxh13/SUP.git
cd SUP
pip3 install -r requirements.txt
```

**2. Create log directory**
```bash
sudo mkdir -p /var/log/sup && sudo chown $USER /var/log/sup
```

**3. Configure `config.py`**
```python
SPLUNK_HEC_URL   = "https://localhost:8088/services/collector"
SPLUNK_HEC_TOKEN = "your-hec-token-here"
BRUTE_THRESHOLD  = 5
BRUTE_WINDOW     = 60
```

**4. Run**
```bash
sudo python3 sup_ids.py
```

---

## Project Structure

```
SUP/
├── sup_ids.py          # Main entry point
├── config.py           # All settings
├── log_parser.py       # Regex log parser
├── brute_tracker.py    # Sliding-window tracker
├── alert_engine.py     # JSON alert builder
├── splunk_forwarder.py # Splunk HEC forwarder
├── requirements.txt
└── tests/
```

---

## Alert Schema

```json
{
  "alert_type":    "BRUTE_FORCE_SSH",
  "severity":      "HIGH",
  "src_ip":        "192.168.1.47",
  "username":      "root",
  "attempt_count": 7,
  "hostname":      "kali-lab",
  "source_log":    "/var/log/auth.log",
  "event_hash":    "a3f8c2d1e9b74056...",
  "timestamp":     "2025-06-14T08:42:11Z",
  "message":       "Brute-force threshold exceeded: 7 attempts in 60s"
}
```

---

## Splunk Queries

```spl
# HIGH/CRITICAL alerts — last 24h
index=sup_ids severity IN ("HIGH","CRITICAL")
| table _time src_ip username alert_type attempt_count

# Top attacking IPs
index=sup_ids | stats count by src_ip | sort -count | head 10

# Brute-force timeline
index=sup_ids alert_type="BRUTE_FORCE_SSH"
| timechart span=5m count by src_ip
```

---

## Requirements

- Kali Linux / Debian-based distro
- Python 3.10+
- Splunk Free or Enterprise with HEC enabled
- Read access to `/var/log/auth.log`

---

## Roadmap

- [ ] Multi-host log aggregation
- [ ] GeoIP enrichment (country / ASN)
- [ ] Allowlist support
- [ ] Slack / PagerDuty webhook alerts
- [ ] Web UI dashboard
- [ ] ML anomaly baseline (scikit-learn)

---

## License

Internal use only — confidential. © 2025
