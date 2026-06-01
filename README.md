# ssh-filter

A bash script that restricts incoming SSH connections by country and ISP (ASN), reducing your attack surface without requiring a static IP.

> **Note:** This is a first line of defence, not a replacement for hardening your `sshd` configuration.

## How it works

Connections are filtered in two stages:
1. **Country allowlist** — drops connections from unlisted countries
2. **ASN allowlist** — permits connections from trusted ISPs/networks, useful if you don't have a static IP

## Installation

1. Copy the script to `/usr/local/bin/`:
```bash
   sudo cp ssh-filter.sh /usr/local/bin/ssh-filter.sh
   sudo chmod 755 /usr/local/bin/ssh-filter.sh
```

2. Edit the script and set your allowed countries and ASNs (numbers only):
```bash
   ALLOW_COUNTRIES=("GB" "US")
   ALLOW_ASNS=("12345")
```

3. Configure `hosts.allow` to invoke the filter:
```bash
   sudo nano /etc/hosts.allow
```
   Add:
```bash
   sshd : ALL : aclexec /usr/local/bin/ssh-filter.sh %a
```

## Finding your ASN
Look up the ASN for your IP using [bgp.tools](https://bgp.tools), or run:

```bash
whois -h bgp.tools "[your IP here]"
```

Trust any IP belonging to your ISP's ASN rather than pinning a specific IP.

## Prerequisites

### Operating system
- Linux (any modern distro). The script uses GNU `find -mmin`, `stat -c %Y`,
  and `sha256sum`. macOS/BSD are not supported.

### Runtime packages
- `bash` ≥ 3.0 (for `set -o pipefail`)
- `whois` — any standard client; `-4`/`-6` flags are not required
- `mmdb-bin` — provides `mmdblookup`
- `util-linux` — provides `logger`
- Coreutils: `find`, `stat`, `date`, `cut`, `sha256sum`, `mktemp`, `timeout`
- Standard text tools: `awk` (gawk), `sed`, `grep`, `head`, `tr`

On Debian/Ubuntu: `apt install whois mmdb-bin`

### GeoIP data
- MaxMind `GeoLite2-Country.mmdb`
- A free MaxMind license key (signup at
  [maxmind.com](https://www.maxmind.com/en/geolite2/signup))
- `geoipupdate` running on a schedule (cron / systemd timer) to keep the
  database current — the MMDB ages quickly otherwise
- I am actually doing this from inside Docker, but I won't detail that here.

### Network egress
- **TCP/43** to `bgp.tools` for whois lookups
- **HTTPS** to `download.maxmind.com` if you automate MMDB refreshes

The script fails open if whois is unreachable, but you won't be enforcing
the ASN rule in that state.

### SSH server
- The filter must run as a user that can read the MMDB file.
