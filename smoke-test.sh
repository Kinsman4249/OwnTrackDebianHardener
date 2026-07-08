#!/usr/bin/env bash
# cf-owntracks smoke test (v2 — mode-aware)
#
# Local checks (run on the origin, as root):
#   - systemd timer active + enabled; retry timer unit installed
#   - config present; mode banner
#   - last-known-good caches (published + ASN) present
#   - nginx pieces present, nginx -t passes
#   - firewall rules loaded for the configured backend
#   - managed ports have listeners; SSH ports are NOT in the managed set
#   - SSH ports still accept TCP connections (locally verifiable)
#   - test mode: decision log exists and lines parse as NDJSON-ish
#
# Remote checks (run from anywhere; needs --server-name; --origin-ip for the
# direct-to-origin probes):
#   - HTTPS via Cloudflare returns 2xx/3xx
#   - HTTP via Cloudflare returns a 301 redirect
#   - Direct-to-origin behavior matches the mode:
#       deploy+mTLS: TLS handshake/403 failure    deploy no-mTLS: 403
#       test: request SUCCEEDS (observe only — it should be logged instead)
#   - Direct HTTP to origin: deploy = dropped (timeout); test = reachable
#
# Usage:
#   sudo ./smoke-test.sh                          # on origin: local + remote
#   ./smoke-test.sh --server-name x --origin-ip Y --remote-only
#   sudo ./smoke-test.sh --local-only
#
# Exit code: 0 if no FAILs.

set -Eeuo pipefail

SERVER_NAME=""
ORIGIN_IP=""
MODE_FLAG="all"
SKIP_DIRECT=0
EXPECTED_MODE=""
EXPECTED_MTLS=""
TIMEOUT_DIRECT_DROP=6

usage() { sed -n '2,30p' "$0"; }

while (( $# )); do
    case "$1" in
        --server-name)  SERVER_NAME="$2"; shift 2 ;;
        --origin-ip)    ORIGIN_IP="$2"; shift 2 ;;
        --local-only)   MODE_FLAG="local-only"; shift ;;
        --remote-only)  MODE_FLAG="remote-only"; shift ;;
        --skip-direct)  SKIP_DIRECT=1; shift ;;
        --mode)         EXPECTED_MODE="$2"; shift 2 ;;
        --mtls)         EXPECTED_MTLS="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

CFG="/etc/cf-owntracks/config"
if [[ -r "$CFG" ]]; then
    # shellcheck disable=SC1090
    source "$CFG"
    SERVER_NAME="${SERVER_NAME:-${CFO_SERVER_NAME:-}}"
    EXPECTED_MODE="${EXPECTED_MODE:-${CFO_MODE:-}}"
    EXPECTED_MTLS="${EXPECTED_MTLS:-${CFO_MTLS_ENABLED:-}}"
fi
EXPECTED_MODE="${EXPECTED_MODE:-deploy}"
EXPECTED_MTLS="${EXPECTED_MTLS:-1}"

if [[ "$MODE_FLAG" != "local-only" ]] && [[ -z "$SERVER_NAME" ]]; then
    echo "ERROR: --server-name required for remote checks (or run on origin with $CFG readable)" >&2
    exit 2
fi

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
if [[ -t 1 ]]; then
    C_OK=$'\e[32m'; C_FAIL=$'\e[31m'; C_SKIP=$'\e[33m'; C_DIM=$'\e[2m'; C_RST=$'\e[0m'
else
    C_OK=""; C_FAIL=""; C_SKIP=""; C_DIM=""; C_RST=""
fi
pass() { printf '%s  PASS%s  %s\n' "$C_OK" "$C_RST" "$1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '%s  FAIL%s  %s\n%s        %s%s\n' "$C_FAIL" "$C_RST" "$1" "$C_DIM" "${2:-}" "$C_RST"; FAIL_COUNT=$((FAIL_COUNT+1)); }
skip() { printf '%s  SKIP%s  %s\n%s        %s%s\n' "$C_SKIP" "$C_RST" "$1" "$C_DIM" "${2:-}" "$C_RST"; SKIP_COUNT=$((SKIP_COUNT+1)); }
section() { printf '\n%s== %s ==%s\n' "$C_DIM" "$1" "$C_RST"; }

# TCP connect check without nc: bash /dev/tcp with timeout.
tcp_open() {
    local host="$1" port="$2"
    timeout 4 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null
}

run_local_checks() {
    if (( EUID != 0 )); then
        skip "local checks" "need root; rerun with sudo"
        return 0
    fi
    section "Local (on-box) checks — expected mode: ${EXPECTED_MODE^^}"

    if [[ "$EXPECTED_MODE" == "test" ]]; then
        echo "  NOTE: TEST mode — enforcement is OFF by design; this host is observing only."
    fi

    systemctl is-active cf-owntracks.timer >/dev/null 2>&1 \
        && pass "refresh timer active" || fail "refresh timer active" "$(systemctl is-active cf-owntracks.timer 2>&1 || true)"
    systemctl is-enabled cf-owntracks.timer >/dev/null 2>&1 \
        && pass "refresh timer enabled at boot" || fail "refresh timer enabled" ""
    [[ -f /etc/systemd/system/cf-owntracks-retry.timer ]] \
        && pass "failure-retry timer installed" || fail "failure-retry timer installed" "missing unit file"

    [[ -r "$CFG" ]] && pass "config present at $CFG" || fail "config present" "missing"

    local v4f="/var/lib/cf-owntracks/ips-v4.last" v6f="/var/lib/cf-owntracks/ips-v6.last"
    [[ -s "$v4f" ]] && pass "published v4 cache ($(grep -c . "$v4f") ranges)" || fail "published v4 cache" "refresh never succeeded?"
    [[ -s "$v6f" ]] && pass "published v6 cache ($(grep -c . "$v6f") ranges)" || fail "published v6 cache" ""
    if [[ "${CFO_ASN_FAILSAFE:-1}" == "1" ]]; then
        local a4f="/var/lib/cf-owntracks/asn-v4.last"
        [[ -f "$a4f" ]] && pass "ASN failsafe cache present ($(grep -c . "$a4f" 2>/dev/null || echo 0) novel v4)" \
                        || skip "ASN failsafe cache" "not created yet"
    fi

    local f
    for f in /etc/nginx/conf.d/cf-owntracks-maps.conf \
             /etc/nginx/snippets/cloudflare-realip.conf \
             /etc/nginx/snippets/cloudflare-enforce.conf \
             /etc/nginx/snippets/cloudflare-mtls.conf; do
        [[ -s "$f" ]] && pass "nginx piece $f" || fail "nginx piece $f" "missing/empty"
    done
    nginx -t >/dev/null 2>&1 && pass "nginx -t" || fail "nginx -t" "$(nginx -t 2>&1 | tail -3)"

    # Managed ports vs SSH ports.
    local managed="" ssh_ports="" p
    [[ -s /var/lib/cf-owntracks/ports.last ]] && managed="$(tr '\n' ' ' < /var/lib/cf-owntracks/ports.last)"
    ssh_ports="$( { sed -n 's/^[[:space:]]*[Pp]ort[[:space:]]\+\([0-9]\+\).*/\1/p' /etc/ssh/sshd_config 2>/dev/null; echo 22; } | sort -un | tr '\n' ' ')"
    if [[ -n "$managed" ]]; then
        pass "managed ports recorded: ${managed% }"
        local clash=0
        for p in $managed; do grep -qw "$p" <<<"$ssh_ports" && clash=1; done
        (( clash == 0 )) && pass "SSH GUARD: managed set does not include SSH ports (${ssh_ports% })" \
                         || fail "SSH GUARD" "managed set includes an SSH port!"
    else
        fail "managed ports recorded" "/var/lib/cf-owntracks/ports.last missing"
    fi

    # SSH still answers locally (loopback path exercises the fw input hook).
    for p in $ssh_ports; do
        if tcp_open 127.0.0.1 "$p"; then
            pass "SSH port ${p} accepts connections"
        else
            skip "SSH port ${p} connect check" "no local listener (custom setup?)"
        fi
    done

    # Listeners on managed ports.
    for p in $managed; do
        ss -ltn "( sport = :${p} )" 2>/dev/null | grep -q LISTEN \
            && pass "listener on :${p}" || fail "listener on :${p}" "nothing listening"
    done

    # Firewall state.
    case "${CFO_FW_BACKEND:-}" in
        nftables)
            if nft list table inet cf_owntracks >/dev/null 2>&1; then
                pass "nftables table present"
                if [[ "$EXPECTED_MODE" == "deploy" ]]; then
                    nft list table inet cf_owntracks | grep -q ' drop' \
                        && pass "deploy: drop rule present" || fail "deploy: drop rule present" "no drop found"
                else
                    nft list table inet cf_owntracks | grep -q 'log prefix' \
                        && pass "test: would-block log rule present" || fail "test: log rule present" "no log rule"
                    nft list table inet cf_owntracks | grep -q ' drop' \
                        && fail "test: nothing drops" "found a drop rule in TEST mode!" || pass "test: nothing drops"
                fi
            else
                fail "nftables table present" "missing"
            fi
            ;;
        ufw)
            local c; c=$(ufw status numbered 2>/dev/null | grep -cF 'cf-owntracks' || true)
            (( c > 0 )) && pass "ufw tagged rules present (${c})" || fail "ufw tagged rules" "none"
            ;;
        iptables)
            iptables -S CF-OWNTRACKS >/dev/null 2>&1 && ip6tables -S CF-OWNTRACKS6 >/dev/null 2>&1 \
                && pass "iptables chains present" || fail "iptables chains" "missing"
            ;;
    esac

    # Decision log (test mode).
    if [[ "$EXPECTED_MODE" == "test" ]]; then
        local dlog="/var/log/cf-owntracks/decisions.ndjson"
        if [[ -s "$dlog" ]]; then
            local sample; sample="$(tail -1 "$dlog")"
            if grep -q '"would_block":' <<<"$sample" && grep -q '"reason":"' <<<"$sample"; then
                pass "decision log parses — last: $(head -c 140 <<<"$sample")"
            else
                fail "decision log format" "last line lacks would_block/reason: $(head -c 120 <<<"$sample")"
            fi
        else
            skip "decision log entries" "no traffic recorded yet ($dlog)"
        fi
    fi

    journalctl -u cf-owntracks.service --since '1 day ago' 2>/dev/null | grep -q 'refresh complete' \
        && pass "refresh succeeded within 24h" \
        || skip "refresh succeeded within 24h" "run: sudo systemctl start cf-owntracks.service"
}

run_remote_checks() {
    section "Remote (network) checks  [$SERVER_NAME]  expected mode: ${EXPECTED_MODE^^}"

    local code
    code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' "https://${SERVER_NAME}/" 2>/dev/null || echo "000")
    case "$code" in
        2??|3??) pass "https via CF returns $code" ;;
        000)     fail "https via CF reachable" "curl failed (DNS/TLS/connectivity)" ;;
        *)       fail "https via CF returns 2xx/3xx" "got $code" ;;
    esac

    code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' "http://${SERVER_NAME}/" 2>/dev/null || echo "000")
    case "$code" in
        301|302|307|308) pass "http via CF redirects ($code)" ;;
        000)             fail "http via CF reachable" "curl failed" ;;
        *)               fail "http via CF redirects" "got $code (expected 301)" ;;
    esac

    if (( SKIP_DIRECT == 1 )); then
        skip "direct-to-origin checks" "--skip-direct"
        return 0
    fi
    if [[ -z "$ORIGIN_IP" ]]; then
        skip "direct-to-origin checks" "pass --origin-ip <public-IP> to probe the firewall/mTLS directly"
        return 0
    fi

    local errfile body err
    errfile="$(mktemp)"
    body=$(curl -sS --max-time 10 --resolve "${SERVER_NAME}:443:${ORIGIN_IP}" -o /dev/null -w '%{http_code}' "https://${SERVER_NAME}/" 2>"$errfile" || true)
    err="$(<"$errfile")"; rm -f "$errfile"

    if [[ "$EXPECTED_MODE" == "test" ]]; then
        case "$body" in
            2??|3??) pass "TEST: direct https to origin succeeds ($body) — will appear in decision log as would_block" ;;
            *)       fail "TEST: direct https to origin succeeds" "got code=$body err=${err:0:100} (test mode must not block)" ;;
        esac
    else
        if [[ "$EXPECTED_MTLS" == "1" ]]; then
            if [[ "$body" == "000" ]] && grep -qiE 'handshake|certificate|alert' <<<"$err"; then
                pass "DEPLOY+mTLS: direct https fails TLS (${err%%$'\n'*})"
            elif [[ "$body" == "403" ]]; then
                pass "DEPLOY+mTLS: direct https rejected with 403 (no valid edge cert)"
            else
                fail "DEPLOY+mTLS: direct https rejected" "got code=$body err=${err:0:100}"
            fi
        else
            [[ "$body" == "403" ]] \
                && pass "DEPLOY: direct https returns 403 (IP gate working)" \
                || fail "DEPLOY: direct https returns 403" "got code=$body err=${err:0:100}"
        fi
    fi

    errfile="$(mktemp)"
    body=$(curl -sS --max-time "$TIMEOUT_DIRECT_DROP" --resolve "${SERVER_NAME}:80:${ORIGIN_IP}" -o /dev/null -w '%{http_code}' "http://${SERVER_NAME}/" 2>"$errfile" || true)
    err="$(<"$errfile")"; rm -f "$errfile"

    if [[ "$EXPECTED_MODE" == "test" ]]; then
        case "$body" in
            301|302|307|308) pass "TEST: direct http to origin answers with redirect ($body) — logged, not blocked" ;;
            *) fail "TEST: direct http to origin reachable" "got code=$body err=${err:0:100}" ;;
        esac
    else
        if [[ "$body" == "000" ]] && grep -qiE 'timed? ?out|timeout|refused' <<<"$err"; then
            pass "DEPLOY: direct http to origin dropped by firewall"
        elif [[ "$body" == "403" ]]; then
            pass "DEPLOY: direct http to origin rejected by nginx (403)"
        else
            fail "DEPLOY: direct http to origin blocked" "got code=$body err=${err:0:100} — check firewall / test from a non-CF, non-allowlisted IP"
        fi
    fi
}

case "$MODE_FLAG" in
    local-only)  run_local_checks ;;
    remote-only) run_remote_checks ;;
    all)         run_local_checks; run_remote_checks ;;
esac

echo
echo "------------------------------------------------------------"
printf '%s%d PASS%s   %s%d FAIL%s   %s%d SKIP%s\n' \
    "$C_OK" "$PASS_COUNT" "$C_RST" "$C_FAIL" "$FAIL_COUNT" "$C_RST" "$C_SKIP" "$SKIP_COUNT" "$C_RST"

(( FAIL_COUNT == 0 ))
