#!/usr/bin/env bash
# =============================================================================
# cf-owntracks: ufw backend (v2 — mode-aware, mawk-safe).
#
# (New to the bash idioms used here? See the guide at the top of common.sh.)
#
# ufw has no transaction or "swap everything at once" concept, so this backend
# works imperatively: every rule we add carries the comment "cf-owntracks" as
# a tag, and a rebuild means "delete every tagged rule, then insert the fresh
# set". ufw evaluates rules TOP-DOWN, first match wins — ordering matters and
# is explained inline below.
#
# v1 bugs fixed here:
#  - gawk-only 3-arg match() replaced with sed (Debian's default awk is mawk,
#    which doesn't support that form — the old code crashed on a stock box)
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
# =============================================================================

# The tag we stamp on every rule we own (via ufw's `comment`).
CFO_UFW_COMMENT="cf-owntracks"

# First tagged rule number (or empty). `ufw status numbered` prints rules as
# "[ 3] ..." — the sed pulls that leading number out. mawk-safe.
_ufw_first_tagged_num() {
    ufw status numbered 2>/dev/null \
        | grep -F "${CFO_UFW_COMMENT}" \
        | sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' \
        | head -1
}

# Delete tagged rules one at a time. We always delete the FIRST tagged rule
# and re-scan, because deleting a rule renumbers everything after it —
# remembering a list of numbers up front would go stale immediately.
ufw_remove_all_tagged() {
    local n
    while :; do                              # ":" = infinite loop; we break out
        n="$(_ufw_first_tagged_num)"
        [[ -z "$n" ]] && break
        ufw --force delete "$n" >/dev/null 2>&1 || break
    done
}

# Count of numbered IPv4 rules: numbered lines NOT containing "(v6)". ufw
# numbers IPv4 rules first, then IPv6 — so this count tells us where the
# IPv6 block starts. mawk-safe.
_ufw_v4_count() {
    ufw status numbered 2>/dev/null \
        | grep '^\[' | grep -vc '(v6)' || true
}

# ufw_apply <mode> <ports-csv> <v4> <v6> <asn4> <asn6> <allow4> <allow6>
# The six trailing arguments are FILES containing CIDR lists (may be empty).
ufw_apply() {
    local mode="$1" ports="$2"
    local v4="$3" v6="$4" asn4="$5" asn6="$6" allow4="$7" allow6="$8"

    log_info "rebuilding ufw rules (mode=${mode})"
    ufw_remove_all_tagged

    local cidr
    # ---- IPv4 block: insert terminal rule at 1, then allows on top of it ----
    # Trick: we insert the deny/observer FIRST at position 1, then insert every
    # allow at position 1 afterwards. Each new insert pushes earlier rules
    # down, so the final order is: [allows..., deny, ...pre-existing rules].
    # First match wins, so allowed sources hit their allow before the deny.
    if [[ "$mode" == "deploy" ]]; then
        ufw --force insert 1 deny proto tcp from any to any port "$ports" \
            comment "${CFO_UFW_COMMENT}" >/dev/null
    else
        # Test mode: an ALLOW with `log` — records the hit, blocks nothing.
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
    # ufw refuses to insert an IPv6 rule at a position inside the IPv4 block,
    # so we compute the first legal v6 position and use the same
    # insert-terminal-then-stack-allows trick there.
    local v6_pos
    v6_pos=$(( $(_ufw_v4_count) + 1 ))
    if [[ "$mode" == "deploy" ]]; then
        # "from ::/0" (the IPv6 everything-range) forces ufw to treat this as
        # an IPv6 rule.
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

# Record which tagged rules exist (informational snapshot for the logs).
ufw_snapshot() {
    local out="$1"
    ufw status numbered 2>/dev/null | grep -F "${CFO_UFW_COMMENT}" > "$out" || : > "$out"
}

# "Restore" for ufw = fail open. Rebuilding ufw rules from a textual snapshot
# is fragile (the numbered-status text is not valid ufw command syntax), so we
# tear down our tagged rules — leaving ufw's own policy in charge — and let
# the next refresh rebuild authoritatively.
ufw_restore() {
    local snap="$1"; : "$snap"     # accepted for API symmetry; intentionally unused
    log_warn "ufw_restore: removing tagged rules; next refresh will rebuild"
    ufw_remove_all_tagged
}

ufw_persist() {
    # ufw saves its own rules to /etc/ufw and reloads them at boot — nothing
    # extra needed from us.
    return 0
}
