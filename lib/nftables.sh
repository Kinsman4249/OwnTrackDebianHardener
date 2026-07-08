#!/usr/bin/env bash
# =============================================================================
# cf-owntracks: nftables backend (v2 — mode-aware).
#
# (New to the bash idioms used here? See the guide at the top of common.sh.)
#
# How this backend works:
#   - Everything lives in ONE dedicated nftables table: `inet cf_owntracks`.
#     "inet" means the table handles IPv4 and IPv6 together.
#   - IP ranges go into named "sets" with `flags interval`, which lets
#     nftables match "is this address inside any of these CIDR ranges?" in
#     one fast lookup, no matter how many ranges there are.
#   - We render the whole table as TEXT first, then hand the file to
#     `nft -f`. Because the file starts with "flush table", the old contents
#     and the new contents are swapped in ONE kernel transaction — there is
#     never a moment with half-applied rules.
#
# Test mode:   non-matched traffic on managed ports is LOGGED + COUNTED,
#              never dropped.
# Deploy mode: non-matched traffic on managed ports is dropped.
#
# SSH guarantee: managed ports never include SSH ports (enforced upstream),
# AND the chain opens with `iif lo return` + an explicit return for SSH ports
# as insurance.
# =============================================================================

# The table name, used in every nft command below.
CFO_NFT_TABLE="inet cf_owntracks"

# Emit a named set definition when the source file has entries; nothing
# otherwise (nft errors on a set with an empty elements list, so we simply
# skip the set — and the rule that would use it — when the list is empty).
#
# auto-merge is essential: BGP-announced prefix lists (the ASN failsafe)
# routinely contain aggregate + more-specific overlaps (e.g. a /32 and a /48
# inside it). Interval sets REJECT overlapping elements unless auto-merge
# tells nft to merge them — without it, `nft -c` fails validation the moment
# real ASN data lands (found in production on 2026-07-08).
# _nft_emit_set <name> <type> <cidr-file>
_nft_emit_set() {
    local name="$1" type="$2" file="$3"
    local elements
    # `paste -sd, -` joins all input lines into one comma-separated line —
    # exactly the "a, b, c" format nft wants inside elements = { ... }.
    elements=$(read_cidr_file "$file" 2>/dev/null | paste -sd, -)
    [[ -z "$elements" ]] && return 0
    cat <<EOF
    set ${name} {
        type ${type}
        flags interval
        auto-merge
        elements = { ${elements} }
    }
EOF
}

# nftables_render <mode> <ports-csv> <ssh-ports-csv> <v4> <v6> <asn4> <asn6> <allow4> <allow6>
# Prints a complete nft ruleset to stdout. The six trailing arguments are
# FILES containing CIDR lists; any of them may be empty or missing — the
# matching sets and rules are then simply left out.
nftables_render() {
    local mode="$1" ports="$2" ssh_ports="$3"
    local v4="$4" v6="$5" asn4="$6" asn6="$7" allow4="$8" allow6="$9"

    echo "# cf-owntracks managed table — generated $(date -u +%FT%TZ), mode=${mode}"
    echo "# DO NOT EDIT — regenerated on every refresh"
    # "add" is a no-op if the table already exists; "flush" then empties it.
    # Both happen inside the same nft -f transaction as the re-fill below.
    echo "add table ${CFO_NFT_TABLE}"
    echo "flush table ${CFO_NFT_TABLE}"
    echo "table ${CFO_NFT_TABLE} {"
    _nft_emit_set cf_v4     ipv4_addr "$v4"
    _nft_emit_set cf_v6     ipv6_addr "$v6"
    _nft_emit_set cf_asn_v4 ipv4_addr "$asn4"
    _nft_emit_set cf_asn_v6 ipv6_addr "$asn6"
    _nft_emit_set allow_v4  ipv4_addr "$allow4"
    _nft_emit_set allow_v6  ipv6_addr "$allow6"

    # The chain hooks into "input" (packets addressed to this machine).
    # priority -10 runs us just BEFORE the standard filter chains (priority 0),
    # and "policy accept" means packets we don't explicitly handle continue on
    # to those other chains untouched.
    #
    # Verdicts used below:
    #   return = leave THIS chain now; other firewall chains still see the
    #            packet (that is how we "never touch" SSH and friends).
    #   drop   = discard the packet (deploy mode only).
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
    # "saddr @setname" = source address is inside that named set.
    # Each rule is only emitted when its backing file has content ([[ -s ]]).
    [[ -s "$allow4" ]] && echo "        ip  saddr @allow_v4  tcp dport { ${ports} } return"
    [[ -s "$allow6" ]] && echo "        ip6 saddr @allow_v6  tcp dport { ${ports} } return"
    [[ -s "$v4"     ]] && echo "        ip  saddr @cf_v4     tcp dport { ${ports} } return"
    [[ -s "$v6"     ]] && echo "        ip6 saddr @cf_v6     tcp dport { ${ports} } return"
    [[ -s "$asn4"   ]] && echo "        ip  saddr @cf_asn_v4 tcp dport { ${ports} } return"
    [[ -s "$asn6"   ]] && echo "        ip6 saddr @cf_asn_v6 tcp dport { ${ports} } return"

    # Anything still in the chain at this point is on a managed port and is
    # NOT loopback / SSH / localhost / allowlisted / Cloudflare.
    if [[ "$mode" == "deploy" ]]; then
        cat <<EOF
        # Everything else on managed ports: not Cloudflare, not whitelisted — drop.
        tcp dport { ${ports} } counter drop
EOF
    else
        # Test mode: record, never block. "limit rate" stops a flood from
        # spamming the kernel log; the separate counter rule counts EVERY
        # would-block (the log rule alone would undercount when rate-limited).
        cat <<EOF
        # TEST MODE: log + count would-blocked traffic; nothing is dropped.
        tcp dport { ${ports} } limit rate 10/second burst 20 packets log prefix "cfo-wouldblock "
        tcp dport { ${ports} } counter
EOF
    fi
    echo "    }"
    echo "}"
}

# Validate a rendered ruleset without applying it (`nft -c` = check only).
nftables_check() {
    local file="$1"
    nft -c -f "$file" 2>&1
}

# Apply a rendered ruleset. Atomic: the flush + refill inside the file are one
# kernel transaction.
nftables_apply() {
    local file="$1"
    log_info "applying nftables ruleset"
    nft -f "$file" || return 1
    return 0
}

# Save the current contents of OUR table to a file so a failed apply can be
# rolled back. An empty snapshot file means "no table existed before".
nftables_snapshot() {
    local out="$1"
    if nft list table ${CFO_NFT_TABLE} >/dev/null 2>&1; then
        nft list table ${CFO_NFT_TABLE} > "$out"
    else
        : > "$out"
    fi
}

# Put the table back the way the snapshot recorded it (or remove it entirely
# when the snapshot says it didn't exist).
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

# Make our rules survive a reboot: dump the live table into a drop-in file and
# make sure /etc/nftables.conf includes that directory. Debian's nftables
# service replays /etc/nftables.conf at boot.
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

    # Append the include line exactly once (the marker comment is how we know
    # we already did it on a previous run).
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

# Count would-block hits (test mode observability). Reads the packet counter
# off the test-mode counter rule ("counter" without "drop").
nftables_wouldblock_count() {
    nft list chain inet cf_owntracks input_filter 2>/dev/null \
        | grep -F 'counter' | grep -v drop \
        | sed -n 's/.*packets \([0-9]\+\).*/\1/p' | tail -1
}
