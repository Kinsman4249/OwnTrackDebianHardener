#!/usr/bin/env bash
# cf-owntracks: ufw backend (v2 — mode-aware, mawk-safe).
#
# v1 bugs fixed here:
#  - gawk-only 3-arg match() replaced with sed (Debian's default awk is mawk)
#  - IPv6 rules were inserted at position 1, which ufw rejects when IPv4 rules
#    exist ("Invalid position"); v2 computes the correct v6 base position
#
# Rebuild strategy: remove all tagged rules, then insert the fresh set. The
# brief gap FAILS OPEN (traffic allowed, ufw's own policy still applies) —
# never a lockout.
#
# Test mode:   CF/whitelist allows + a tagged catch-all ALLOW LOG rule on the
#              managed ports (kernel-logs would-blocks, drops nothing).
# Deploy mode: CF/whitelist allows + a tagged DENY on the managed ports.

CFO_UFW_COMMENT="cf-owntracks"

# First tagged rule number (or empty). mawk-safe.
_ufw_first_tagged_num() {
    ufw status numbered 2>/dev/null \
        | grep -F "${CFO_UFW_COMMENT}" \
        | sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' \
        | head -1
}

ufw_remove_all_tagged() {
    local n
    while :; do
        n="$(_ufw_first_tagged_num)"
        [[ -z "$n" ]] && break
        ufw --force delete "$n" >/dev/null 2>&1 || break
    done
}

# Count of numbered IPv4 rules: numbered lines NOT containing "(v6)". mawk-safe.
_ufw_v4_count() {
    ufw status numbered 2>/dev/null \
        | grep '^\[' | grep -vc '(v6)' || true
}

# ufw_apply <mode> <ports-csv> <v4> <v6> <asn4> <asn6> <allow4> <allow6>
ufw_apply() {
    local mode="$1" ports="$2"
    local v4="$3" v6="$4" asn4="$5" asn6="$6" allow4="$7" allow6="$8"

    log_info "rebuilding ufw rules (mode=${mode})"
    ufw_remove_all_tagged

    local cidr
    # ---- IPv4 block: insert terminal rule at 1, then allows on top of it ----
    if [[ "$mode" == "deploy" ]]; then
        ufw --force insert 1 deny proto tcp from any to any port "$ports" \
            comment "${CFO_UFW_COMMENT}" >/dev/null
    else
        ufw --force insert 1 allow log proto tcp from any to any port "$ports" \
            comment "${CFO_UFW_COMMENT} wouldblock-observer" >/dev/null
    fi
    # Localhost guarantee (ufw's before.rules already allows lo; explicit anyway).
    ufw --force insert 1 allow proto tcp from 127.0.0.0/8 to any port "$ports" \
        comment "${CFO_UFW_COMMENT}" >/dev/null
    local f tmp
    tmp="$(mktemp)"
    for f in "$allow4" "$v4" "$asn4"; do
        [[ -s "$f" ]] || continue
        read_cidr_file "$f" > "$tmp" || true
        while IFS= read -r cidr; do
            [[ -z "$cidr" ]] && continue
            ufw --force insert 1 allow proto tcp from "$cidr" to any port "$ports" \
                comment "${CFO_UFW_COMMENT}" >/dev/null
        done < "$tmp"
    done

    # ---- IPv6 block: base position is right after the last v4 rule ----------
    local v6_pos
    v6_pos=$(( $(_ufw_v4_count) + 1 ))
    if [[ "$mode" == "deploy" ]]; then
        ufw --force insert "$v6_pos" deny proto tcp from ::/0 to any port "$ports" \
            comment "${CFO_UFW_COMMENT}" >/dev/null
    else
        ufw --force insert "$v6_pos" allow log proto tcp from ::/0 to any port "$ports" \
            comment "${CFO_UFW_COMMENT} wouldblock-observer" >/dev/null
    fi
    ufw --force insert "$v6_pos" allow proto tcp from ::1 to any port "$ports" \
        comment "${CFO_UFW_COMMENT}" >/dev/null
    for f in "$allow6" "$v6" "$asn6"; do
        [[ -s "$f" ]] || continue
        read_cidr_file "$f" > "$tmp" || true
        while IFS= read -r cidr; do
            [[ -z "$cidr" ]] && continue
            ufw --force insert "$v6_pos" allow proto tcp from "$cidr" to any port "$ports" \
                comment "${CFO_UFW_COMMENT}" >/dev/null
        done < "$tmp"
    done
    rm -f "$tmp"

    # Rule-count sanity: ufw materializes one rule per CIDR — nftables scales
    # far better once the ASN failsafe is in play.
    local total
    total=$(ufw status numbered 2>/dev/null | grep -cF "${CFO_UFW_COMMENT}" || true)
    if (( total > CFO_UFW_RULE_WARN )); then
        log_warn "ufw now carries ${total} cf-owntracks rules — consider switching to nftables (--force nftables)"
    fi

    return 0
}

ufw_snapshot() {
    local out="$1"
    ufw status numbered 2>/dev/null | grep -F "${CFO_UFW_COMMENT}" > "$out" || : > "$out"
}

ufw_restore() {
    # Rebuilding ufw rules from a textual snapshot is fragile; tear down our
    # tagged rules (fail-open, ufw's own policy still applies) and let the
    # next refresh rebuild authoritatively.
    local snap="$1"; : "$snap"
    log_warn "ufw_restore: removing tagged rules; next refresh will rebuild"
    ufw_remove_all_tagged
}

ufw_persist() {
    # ufw rules persist by default — nothing to do.
    return 0
}
