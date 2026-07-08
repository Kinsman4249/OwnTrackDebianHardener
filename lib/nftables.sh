#!/usr/bin/env bash
# cf-owntracks: nftables backend (v2 — mode-aware).
# Strategy: dedicated `inet cf_owntracks` table with named interval sets.
# One `nft -f` swaps the whole table atomically.
#
# Test mode:   non-matched traffic on managed ports is LOGGED + COUNTED, never dropped.
# Deploy mode: non-matched traffic on managed ports is dropped.
#
# SSH guarantee: managed ports never include SSH ports (enforced upstream), AND
# the chain opens with `iif lo return` + explicit return for SSH ports as insurance.

CFO_NFT_TABLE="inet cf_owntracks"

# Emit a named set definition when the source file has entries; nothing otherwise.
# _nft_emit_set <name> <type> <cidr-file>
_nft_emit_set() {
    local name="$1" type="$2" file="$3"
    local elements
    elements=$(read_cidr_file "$file" 2>/dev/null | paste -sd, -)
    [[ -z "$elements" ]] && return 0
    cat <<EOF
    set ${name} {
        type ${type}
        flags interval
        elements = { ${elements} }
    }
EOF
}

# nftables_render <mode> <ports-csv> <ssh-ports-csv> <v4> <v6> <asn4> <asn6> <allow4> <allow6>
# Files may be empty/missing; sets and rules are emitted conditionally.
nftables_render() {
    local mode="$1" ports="$2" ssh_ports="$3"
    local v4="$4" v6="$5" asn4="$6" asn6="$7" allow4="$8" allow6="$9"

    echo "# cf-owntracks managed table — generated $(date -u +%FT%TZ), mode=${mode}"
    echo "# DO NOT EDIT — regenerated on every refresh"
    echo "add table ${CFO_NFT_TABLE}"
    echo "flush table ${CFO_NFT_TABLE}"
    echo "table ${CFO_NFT_TABLE} {"
    _nft_emit_set cf_v4     ipv4_addr "$v4"
    _nft_emit_set cf_v6     ipv6_addr "$v6"
    _nft_emit_set cf_asn_v4 ipv4_addr "$asn4"
    _nft_emit_set cf_asn_v6 ipv6_addr "$asn6"
    _nft_emit_set allow_v4  ipv4_addr "$allow4"
    _nft_emit_set allow_v6  ipv6_addr "$allow6"

    cat <<EOF
    chain input_filter {
        type filter hook input priority -10; policy accept;
        # Loopback: never touched (v1 bug fix — localhost was dropped).
        iif "lo" return
EOF
    # SSH insurance: even if a port-list bug ever includes an SSH port,
    # this rule exits the chain before any verdict logic can run.
    if [[ -n "$ssh_ports" ]]; then
        echo "        tcp dport { ${ssh_ports} } return"
    fi
    cat <<EOF
        # Localhost sources (non-lo-interface local traffic).
        ip  saddr 127.0.0.0/8 tcp dport { ${ports} } return
        ip6 saddr ::1         tcp dport { ${ports} } return
EOF
    [[ -s "$allow4" ]] && echo "        ip  saddr @allow_v4  tcp dport { ${ports} } return"
    [[ -s "$allow6" ]] && echo "        ip6 saddr @allow_v6  tcp dport { ${ports} } return"
    [[ -s "$v4"     ]] && echo "        ip  saddr @cf_v4     tcp dport { ${ports} } return"
    [[ -s "$v6"     ]] && echo "        ip6 saddr @cf_v6     tcp dport { ${ports} } return"
    [[ -s "$asn4"   ]] && echo "        ip  saddr @cf_asn_v4 tcp dport { ${ports} } return"
    [[ -s "$asn6"   ]] && echo "        ip6 saddr @cf_asn_v6 tcp dport { ${ports} } return"

    if [[ "$mode" == "deploy" ]]; then
        cat <<EOF
        # Everything else on managed ports: not Cloudflare, not whitelisted — drop.
        tcp dport { ${ports} } counter drop
EOF
    else
        cat <<EOF
        # TEST MODE: log + count would-blocked traffic; nothing is dropped.
        tcp dport { ${ports} } limit rate 10/second burst 20 packets log prefix "cfo-wouldblock "
        tcp dport { ${ports} } counter
EOF
    fi
    echo "    }"
    echo "}"
}

nftables_check() {
    local file="$1"
    nft -c -f "$file" 2>&1
}

nftables_apply() {
    local file="$1"
    log_info "applying nftables ruleset"
    nft -f "$file" || return 1
    return 0
}

nftables_snapshot() {
    local out="$1"
    if nft list table ${CFO_NFT_TABLE} >/dev/null 2>&1; then
        nft list table ${CFO_NFT_TABLE} > "$out"
    else
        : > "$out"
    fi
}

nftables_restore() {
    local snap="$1"
    if [[ -s "$snap" ]]; then
        log_warn "restoring previous nftables table"
        nft delete table ${CFO_NFT_TABLE} 2>/dev/null || true
        nft -f "$snap" || log_error "nftables restore failed"
    else
        log_warn "removing nftables table (no prior state)"
        nft delete table ${CFO_NFT_TABLE} 2>/dev/null || true
    fi
}

nftables_persist() {
    local include_marker="# cf-owntracks-include"
    local nft_conf="/etc/nftables.conf"
    local persist_file="/etc/nftables.d/cf-owntracks.conf"

    mkdir -p /etc/nftables.d
    if nft list table ${CFO_NFT_TABLE} >/dev/null 2>&1; then
        nft list table ${CFO_NFT_TABLE} > "$persist_file" || {
            log_warn "could not write $persist_file; rules will not survive reboot"
            return 0
        }
    fi

    if [[ -f "$nft_conf" ]] && ! grep -q "$include_marker" "$nft_conf"; then
        if cat >> "$nft_conf" <<EOF

${include_marker}
include "/etc/nftables.d/*.conf"
EOF
        then
            log_info "added cf-owntracks include to $nft_conf"
        else
            log_warn "could not update $nft_conf; add the include manually"
        fi
    fi

    systemctl enable nftables.service >/dev/null 2>&1 || true
}

# Count would-block hits (test mode observability).
nftables_wouldblock_count() {
    nft list chain inet cf_owntracks input_filter 2>/dev/null \
        | grep -F 'counter' | grep -v drop \
        | sed -n 's/.*packets \([0-9]\+\).*/\1/p' | tail -1
}
