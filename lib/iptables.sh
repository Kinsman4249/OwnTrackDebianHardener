#!/usr/bin/env bash
# =============================================================================
# cf-owntracks: iptables backend (v2 — mode-aware).
#
# (New to the bash idioms used here? See the guide at the top of common.sh.)
#
# How this backend works:
#   - We keep our rules in DEDICATED chains — CF-OWNTRACKS for IPv4 and
#     CF-OWNTRACKS6 for IPv6 — instead of scattering them through INPUT.
#     The only thing we add to INPUT itself is one "jump" rule per family:
#     "packets for the managed TCP ports -> go run our chain".
#   - The chains are rebuilt by feeding a rules file to `iptables-restore
#     --noflush`: atomic for the chains defined in the file, and --noflush
#     leaves every OTHER chain on the system alone.
#   - iptables and ip6tables are entirely separate commands/tables, hence the
#     twin functions for v4 and v6 throughout.
#
# v1 bug fixed: loopback traffic to managed ports was dropped — the chain now
# opens with `-i lo -j RETURN` plus localhost source returns.
#
# Test mode:   would-blocked traffic hits a rate-limited LOG rule, then falls
#              through (implicit RETURN) — nothing dropped.
# Deploy mode: would-blocked traffic is dropped.
# =============================================================================

CFO_IPT_CHAIN="CF-OWNTRACKS"      # IPv4 chain name
CFO_IPT_CHAIN6="CF-OWNTRACKS6"    # IPv6 chain name

# _iptables_render <family> <mode> <ports-csv> <ssh-ports-csv> <files...>
# family: 4|6. Emits iptables-restore input for the *filter table.
#
# iptables-restore file format quick guide:
#   *filter            start of the filter table section
#   :NAME - [0:0]      declare chain NAME (creates it if missing)
#   -F NAME            flush (empty) the chain
#   -A NAME ...        append a rule to the chain
#   COMMIT             apply everything above atomically
#
# Rule verdicts (-j = "jump to"):
#   RETURN = leave this chain, continue wherever INPUT left off
#   DROP   = discard the packet
#   LOG    = write a kernel log line, then CONTINUE to the next rule
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
    # Loopback + SSH insurance first: these RETURN before any verdict logic,
    # so local traffic and SSH can never be caught by the rules below.
    echo "-A ${chain} -i lo -j RETURN"
    if [[ -n "$ssh_ports" ]]; then
        # multiport lets one rule match a comma-separated list of ports.
        echo "-A ${chain} -p tcp -m multiport --dports ${ssh_ports} -j RETURN"
    fi
    echo "-A ${chain} -s ${local_src} -j RETURN"
    # One RETURN rule per allowed CIDR (allowlist first, then the published
    # Cloudflare ranges, then the ASN failsafe ranges).
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
    # Anything reaching this point is on a managed port and not allowed by
    # any rule above.
    if [[ "$mode" == "deploy" ]]; then
        echo "-A ${chain} -j DROP"
    else
        # Test mode: log (rate-limited so a flood can't spam the journal) and
        # fall off the end of the chain — an implicit RETURN, nothing dropped.
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

# Validate both rendered rulesets without applying (--test parses only).
iptables_check() {
    local v4_file="$1" v6_file="$2"
    iptables-restore --test < "$v4_file" 2>&1 || return 1
    ip6tables-restore --test < "$v6_file" 2>&1 || return 1
    return 0
}

# Remove any INPUT jump rules referencing our chains (both families).
# `iptables -S INPUT` prints rules in "-A INPUT ..." form; stripping the
# leading "-A " gives the exact spec `iptables -D` (delete) expects. This is
# how we clear STALE jumps when the managed port list changes between runs.
_iptables_clear_jumps() {
    local spec
    while IFS= read -r spec; do
        [[ -z "$spec" ]] && continue
        # The spec must be word-split back into separate arguments here, so
        # it is deliberately unquoted.
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

    # Rebuild our chains atomically (--noflush = leave everything else alone).
    iptables-restore --noflush < "$v4_file" || return 1
    ip6tables-restore --noflush < "$v6_file" || return 1

    # Refresh the INPUT jumps so the port match always reflects the CURRENT
    # managed set. "-I INPUT 1" inserts at the very top of INPUT so our chain
    # runs before any pre-existing DROP rules.
    _iptables_clear_jumps
    iptables  -I INPUT 1 -p tcp -m multiport --dports "$ports" -j ${CFO_IPT_CHAIN}  || return 1
    ip6tables -I INPUT 1 -p tcp -m multiport --dports "$ports" -j ${CFO_IPT_CHAIN6} || return 1

    return 0
}

# Record our chains + jumps (informational snapshot for the logs).
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

# "Restore" for iptables = fail open, like the ufw backend: rebuilding from a
# textual snapshot is fragile, so we remove our chains and jumps entirely
# (-F = flush the chain, -X = delete it) and let the next refresh rebuild.
iptables_restore() {
    local snap="$1"; : "$snap"     # accepted for API symmetry; intentionally unused
    log_warn "iptables_restore: removing CF chains; next refresh will rebuild"
    _iptables_clear_jumps
    iptables -F ${CFO_IPT_CHAIN} 2>/dev/null || true
    iptables -X ${CFO_IPT_CHAIN} 2>/dev/null || true
    ip6tables -F ${CFO_IPT_CHAIN6} 2>/dev/null || true
    ip6tables -X ${CFO_IPT_CHAIN6} 2>/dev/null || true
}

# Plain iptables rules vanish at reboot. Debian's answer is the
# iptables-persistent package (netfilter-persistent), which saves the current
# rules and replays them at boot — use it if it's there, warn if it isn't.
iptables_persist() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || \
            log_warn "netfilter-persistent save failed; rules will not survive reboot"
    else
        log_warn "netfilter-persistent not installed; iptables rules will not survive reboot"
        log_warn "  install with: apt-get install iptables-persistent"
    fi
}
