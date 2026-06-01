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

2. Edit the script and set your allowed countries and ASNs:
```bash
   ALLOW_COUNTRIES=("GB" "US")
   ALLOW_ASNS=("AS12345")
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
