#!/usr/bin/env bash
# cf-owntracks: iptables backend (v2 — mode-aware).
# Dedicated chains CF-OWNTRACKS (v4) / CF-OWNTRACKS6 (v6), jumped from INPUT
# for the managed ports only. Chains rebuilt via iptables-restore --noflush.
#
# v1 bug fixed: loopback traffic to managed ports was dropped — the chain now
# opens with `-i lo -j RETURN` plus localhost source returns.
#
# Test mode:   would-blocked traffic hits a rate-limited LOG rule, then falls
#              through (implicit RETURN) — nothing dropped.
# Deploy mode: would-blocked traffic is dropped.

CFO_IPT_CHAIN="CF-OWNTRACKS"
CFO_IPT_CHAIN6="CF-OWNTRACKS6"

# _iptables_render <family> <mode> <ports-csv> <ssh-ports-csv> <files...>
# family: 4|6. Emits iptables-restore input for *filter.
_iptables_render() {
    local family="$1" mode="$2" ports="$3" ssh_ports="$4"
    local list_file="$5" asn_file="$6" allow_file="$7"
    local chain local_src
    if [[ "$family" == "4" ]]; then
        chain="$CFO_IPT_CHAIN";  local_src="127.0.0.0/8"
    else
        chain="$CFO_IPT_CHAIN6"; local_src="::1/128"
    fi

    echo "*filter"
    echo ":${chain} - [0:0]"
    echo "-F ${chain}"
    # Loopback + SSH insurance first.
    echo "-A ${chain} -i lo -j RETURN"
    if [[ -n "$ssh_ports" ]]; then
        echo "-A ${chain} -p tcp -m multiport --dports ${ssh_ports} -j RETURN"
    fi
    echo "-A ${chain} -s ${local_src} -j RETURN"
    local f cidr tmp
    tmp="$(mktemp)"
    for f in "$allow_file" "$list_file" "$asn_file"; do
        [[ -s "$f" ]] || continue
        read_cidr_file "$f" > "$tmp" || true
        while IFS= read -r cidr; do
            [[ -z "$cidr" ]] && continue
            printf -- '-A %s -s %s -j RETURN\n' "$chain" "$cidr"
        done < "$tmp"
    done
    rm -f "$tmp"
    if [[ "$mode" == "deploy" ]]; then
        echo "-A ${chain} -j DROP"
    else
        echo "-A ${chain} -m limit --limit 10/second --limit-burst 20 -j LOG --log-prefix \"cfo-wouldblock \""
        # implicit fall-through back to INPUT: nothing dropped in test mode
    fi
    echo "COMMIT"
}

iptables_render_v4() {
    # <mode> <ports> <ssh_ports> <v4> <asn4> <allow4>
    _iptables_render 4 "$1" "$2" "$3" "$4" "$5" "$6"
}

iptables_render_v6() {
    # <mode> <ports> <ssh_ports> <v6> <asn6> <allow6>
    _iptables_render 6 "$1" "$2" "$3" "$4" "$5" "$6"
}

iptables_check() {
    local v4_file="$1" v6_file="$2"
    iptables-restore --test < "$v4_file" 2>&1 || return 1
    ip6tables-restore --test < "$v6_file" 2>&1 || return 1
    return 0
}

# Remove any INPUT jumps referencing our chains (both families).
_iptables_clear_jumps() {
    local spec
    while IFS= read -r spec; do
        [[ -z "$spec" ]] && continue
        # shellcheck disable=SC2086
        iptables -D ${spec#-A } 2>/dev/null || true
    done < <(iptables -S INPUT 2>/dev/null | grep -F "$CFO_IPT_CHAIN" || true)
    while IFS= read -r spec; do
        [[ -z "$spec" ]] && continue
        # shellcheck disable=SC2086
        ip6tables -D ${spec#-A } 2>/dev/null || true
    done < <(ip6tables -S INPUT 2>/dev/null | grep -F "$CFO_IPT_CHAIN6" || true)
}

# iptables_apply <v4-ruleset> <v6-ruleset> <ports-csv>
iptables_apply() {
    local v4_file="$1" v6_file="$2" ports="$3"
    log_info "applying iptables ruleset"

    iptables-restore --noflush < "$v4_file" || return 1
    ip6tables-restore --noflush < "$v6_file" || return 1

    # Refresh INPUT jumps so the port match always reflects the managed set.
    _iptables_clear_jumps
    iptables  -I INPUT 1 -p tcp -m multiport --dports "$ports" -j ${CFO_IPT_CHAIN}  || return 1
    ip6tables -I INPUT 1 -p tcp -m multiport --dports "$ports" -j ${CFO_IPT_CHAIN6} || return 1

    return 0
}

iptables_snapshot() {
    local out="$1"
    {
        echo "## iptables CF-OWNTRACKS chain (v4) ##"
        iptables -S ${CFO_IPT_CHAIN} 2>/dev/null || echo "## (chain absent) ##"
        echo "## ip6tables CF-OWNTRACKS6 chain (v6) ##"
        ip6tables -S ${CFO_IPT_CHAIN6} 2>/dev/null || echo "## (chain absent) ##"
        echo "## INPUT jumps ##"
        iptables -S INPUT 2>/dev/null | grep -F "${CFO_IPT_CHAIN}" || true
        ip6tables -S INPUT 2>/dev/null | grep -F "${CFO_IPT_CHAIN6}" || true
    } > "$out"
}

iptables_restore() {
    local snap="$1"; : "$snap"
    log_warn "iptables_restore: removing CF chains; next refresh will rebuild"
    _iptables_clear_jumps
    iptables -F ${CFO_IPT_CHAIN} 2>/dev/null || true
    iptables -X ${CFO_IPT_CHAIN} 2>/dev/null || true
    ip6tables -F ${CFO_IPT_CHAIN6} 2>/dev/null || true
    ip6tables -X ${CFO_IPT_CHAIN6} 2>/dev/null || true
}

iptables_persist() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || \
            log_warn "netfilter-persistent save failed; rules will not survive reboot"
    else
        log_warn "netfilter-persistent not installed; iptables rules will not survive reboot"
        log_warn "  install with: apt-get install iptables-persistent"
    fi
}
