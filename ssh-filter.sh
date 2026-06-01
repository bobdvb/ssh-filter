#!/bin/bash
# SSH filter.
# Denies login unless the source IP's country (MaxMind GeoLite2) is in
# ALLOW_COUNTRIES and its BGP origin ASN (bgp.tools whois) is in ALLOW_ASNS.
# Whois lookups are fail-open: a transient bgp.tools outage will not lock
# anyone out.

# --- config ----------------------------------------------------------------
ALLOW_COUNTRIES="NO TW ES"
ALLOW_ASNS="1234 5678"
CACHE_DIR="/tmp/bgp-cache"
CACHE_TTL=10800                                  # 3 hours
MMDB="/usr/share/GeoIP/GeoLite2-Country.mmdb"
DEBUG_LOG="${CACHE_DIR}/debug.log"
DEBUG_MAX_LINES=200
LOG_TAG="ssh-filter"
NOTICE="authpriv.notice"
ERR="authpriv.err"

# Fail on unset variables and on broken pipelines.  We deliberately do not
# use `set -e`: the script has many graceful-exit branches and we want
# them to be reached rather than aborting the whole login attempt.
set -u
set -o pipefail

mkdir -p "$CACHE_DIR"

# --- logging ---------------------------------------------------------------
log_notice() { logger -t "$LOG_TAG" -p "$NOTICE" "$*"; }
log_err()    { logger -t "$LOG_TAG" -p "$ERR"    "$*"; }

# --- housekeeping ----------------------------------------------------------
# Prune stale cache/tmp/err files and cap the debug log.  Runs every call
# because SSH-login frequency is low and a tiny `find` is cheaper than
# tracking a separate counter.
cleanup() {
  find "$CACHE_DIR" -maxdepth 1 -type f -name '.tmp.*' -mmin +5  -delete 2>/dev/null
  find "$CACHE_DIR" -maxdepth 1 -type f -name '.err.*' -mmin +1  -delete 2>/dev/null
  find "$CACHE_DIR" -maxdepth 1 -type f ! -name 'debug.log' \
                                          ! -name '.tmp.*' \
                                          ! -name '.err.*' -mmin +180 -delete 2>/dev/null
  if [ -f "$DEBUG_LOG" ]; then
    LINES=$(wc -l < "$DEBUG_LOG" 2>/dev/null || echo 0)
    if [ "$LINES" -gt "$DEBUG_MAX_LINES" ]; then
      TMP=$(mktemp "${CACHE_DIR}/.trim.XXXXXX")
      tail -n $((DEBUG_MAX_LINES - 50)) "$DEBUG_LOG" > "$TMP" 2>/dev/null && mv -f "$TMP" "$DEBUG_LOG"
    fi
  fi
}
cleanup

# --- arg parsing -----------------------------------------------------------
# sshd passes "<remoteIP>[:port]>" as a single argument.
if [ $# -ne 1 ]; then
  echo "Usage: $(basename "$0") <IP[:port]>" 1>&2
  exit 0
fi

IP="${1%%:*}"                                     # strip optional :port
IP_HASH=$(printf '%s' "$IP" | sha256sum | cut -c1-16)
CACHE_FILE="${CACHE_DIR}/${IP_HASH}"
ERR_FILE="${CACHE_DIR}/.err.${IP_HASH}"

# --- private / link-local bypass -------------------------------------------
# Allow these without further checks; they're either loopback, RFC1918
# private space, IPv4 link-local, or their IPv6 equivalents.  These ranges
# are unrouteable on the public internet so any match is by definition
# local traffic (VPN, NAT gateway, cloud metadata service, etc.).
#
#   127.0.0.0/8          IPv4 loopback
#   10.0.0.0/8           RFC1918 class A private
#   172.16.0.0/12        RFC1918 class B private
#   192.168.0.0/16       RFC1918 class C private
#   169.254.0.0/16       IPv4 link-local (incl. 169.254.169.254 cloud metadata)
#   ::1                  IPv6 loopback
#   fe80::/10            IPv6 link-local
#   fc00::/7             IPv6 unique local addresses (ULA)
case "$IP" in
  127.*|10.*|192.168.*|169.254.*|::1|fe80:*|fc00:*|fd[0-9a-fA-F][0-9a-fA-F]:*)
    log_notice "Connection allowed from $1 (private/link-local)"
    exit 0
    ;;
  172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
    log_notice "Connection allowed from $1 (private)"
    exit 0
    ;;
esac

# --- cache lookup ----------------------------------------------------------
# Cache file format: BGP_CC|BGP_ASN|MMDB_CC  (newline-terminated)
# One file per IP, addressed by SHA-256 prefix.  Atomic writes below
# ensure readers never see a torn file.
BGP_CC=""
BGP_ASN=""
MMDB_CC=""

if [ -f "$CACHE_FILE" ]; then
  AGE=$(( $(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0) ))
  if [ "$AGE" -lt "$CACHE_TTL" ]; then
    # Legacy 2-field files leave MMDB_CC empty on a partial read, which
    # transparently triggers a fresh MMDB lookup below; the new write
    # upgrades the file to the 3-field format.
    IFS='|' read -r BGP_CC BGP_ASN MMDB_CC < "$CACHE_FILE" 2>/dev/null || {
      BGP_CC=""; BGP_ASN=""; MMDB_CC=""
    }
  fi
fi

# --- country check (local MMDB lookup) -------------------------------------
if [ -z "$MMDB_CC" ]; then
  # Strict regex: only matches a 2-uppercase-letter ISO code in quotes, so
  # we never accidentally pick up "registered_country" or other metadata
  # records that mmdblookup may emit.
  MMDB_CC=$(mmdblookup -f "$MMDB" -i "$IP" country iso_code 2>/dev/null \
    | sed -n 's/.*"\([A-Z][A-Z]\)".*/\1/p' | head -n1)
  if [ -z "$MMDB_CC" ]; then
    log_err "Connection denied from $1 (mmdblookup failed)"
    exit 1
  fi
fi

COUNTRY_OK=0
for c in $ALLOW_COUNTRIES; do
  [ "$MMDB_CC" = "$c" ] && COUNTRY_OK=1 && break
done
if [ "$COUNTRY_OK" -eq 0 ]; then
  log_notice "Connection denied from $1 country=$MMDB_CC"
  exit 1
fi

# --- ASN lookup (external whois, cached) -----------------------------------
# Only runs for IPs already in an allowed country, and only on cache miss.
# The 2-second timeout is intentionally tight: we'd rather fail-open than
# hold up the login prompt.
if [ -z "$BGP_ASN" ]; then
  # bgp.tools' whois server speaks both v4 and v6; pick the right family
  # flag so we don't get a referral to the wrong RIR.
  case "$IP" in
    *:*) WHOIS_FLAG="-6" ;;
    *)   WHOIS_FLAG="-4" ;;
  esac

  # Stderr is captured separately so we can see DNS failures, connection
  # refused, rate-limit warnings, etc. in the debug log.
  RAW=$(timeout 2 /usr/bin/whois -h bgp.tools "$IP" 2>"$ERR_FILE")
  RC=$?
  ERR=$(cat "$ERR_FILE" 2>/dev/null)
  rm -f "$ERR_FILE"
  printf '%s ip=%s rc=%d raw_len=%d err=[%s]\n' "$(date -Is)" "$IP" "$RC" "${#RAW}" "$ERR" >> "$DEBUG_LOG"

  if [ "$RC" -ne 0 ]; then
    # Fail open: bgp.tools unreachable/errored, allow rather than lock out.
    log_notice "Connection allowed from $1 country=$MMDB_CC (bgp.tools unreachable rc=$RC err=[$ERR])"
    exit 0
  fi

  # bgp.tools data line looks like: "12345 | 192.0.2.0/24 | ... | DE | ..."
  # Pick the first line that contains a pipe and starts with a digit.
  LINE=$(printf '%s' "$RAW" | tr -d '\r' | grep '|' | grep '^[0-9]' | head -n1)
  printf '%s ip=%s line=[%s]\n' "$(date -Is)" "$IP" "$LINE" >> "$DEBUG_LOG"

  if [ -z "$LINE" ]; then
    log_notice "Connection allowed from $1 country=$MMDB_CC (bgp.tools parse failed)"
    exit 0
  fi

  BGP_ASN=$(printf '%s' "$LINE" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $1); print $1}')
  BGP_CC=$(printf '%s' "$LINE" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $4); print $4}')
  printf '%s ip=%s asn=%s cc=%s\n' "$(date -Is)" "$IP" "$BGP_ASN" "$BGP_CC" >> "$DEBUG_LOG"

  if [ -n "$BGP_ASN" ]; then
    # Atomic write: mktemp + mv.  rename(2) is atomic on the same
    # filesystem, so concurrent readers never see a half-written file.
    TMP=$(mktemp "${CACHE_DIR}/.tmp.XXXXXX")
    if printf '%s|%s|%s\n' "$BGP_CC" "$BGP_ASN" "$MMDB_CC" > "$TMP"; then
      mv -f "$TMP" "$CACHE_FILE"
    else
      rm -f "$TMP"
    fi
  else
    log_err "Connection allowed from $1 country=$MMDB_CC (bgp.tools ASN empty)"
    exit 0
  fi
fi

# --- consistency warning ---------------------------------------------------
# MaxMind and the BGP registry can disagree (e.g. a network announcing
# through a foreign upstream).  Log as a warning but don't fail: the
# country allowlist is the source of truth for the gate decision.
if [ -n "$BGP_CC" ] && [ "$MMDB_CC" != "$BGP_CC" ]; then
  log_err "WARNING country mismatch from $1 mmdb=$MMDB_CC bgp=$BGP_CC asn=$BGP_ASN"
fi

# --- ASN allowlist ---------------------------------------------------------
ASN_OK=0
for a in $ALLOW_ASNS; do
  [ "$BGP_ASN" = "$a" ] && ASN_OK=1 && break
done
if [ "$ASN_OK" -eq 0 ]; then
  log_notice "Connection denied from $1 country=$MMDB_CC asn=$BGP_ASN"
  exit 1
fi

log_notice "Connection allowed from $1 country=$MMDB_CC asn=$BGP_ASN"
exit 0
