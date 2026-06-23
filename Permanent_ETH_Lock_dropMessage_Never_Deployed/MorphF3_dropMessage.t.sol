// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// ─── Interfaces ───────────────────────────────────────────────────────────────

interface IL1CrossDomainMessenger {
    function maxReplayTimes() external view returns (uint256);
}

// ─── Morph F3: Permanent ETH Lock — dropMessage Never Deployed ────────────────
//
// Root cause:  L1CrossDomainMessenger caps retries at maxReplayTimes = 3.
//              When L2 execution permanently fails and 3 replays are exhausted,
//              the bridged ETH is irrecoverable — the designed escape hatch
//              (dropMessage + onDropMessage refund) was never deployed to mainnet.
//
// Verified: Ethereum mainnet — ethereum.publicnode.com
//   Messenger proxy: 0xDc71366EFFA760804DCFC3EDF87fa2A6f1623304
//   Messenger impl:  0x0cC37d5239f9027a1269f53d83c73094d538f3a9
//   L1ETHGateway:    0x1C1Ffb5828c3A48B54E8910F1c75256a498aDE68
// ─────────────────────────────────────────────────────────────────────────────

contract MorphF3_dropMessageTest is Test {
    // ── Contracts (Ethereum mainnet) ──────────────────────────────────────────
    address constant MESSENGER      = 0xDc71366EFFA760804DCFC3EDF87fa2A6f1623304; // proxy
    address constant MESSENGER_IMPL = 0x0cc37d5239F9027A1269F53d83c73094d538F3A9; // implementation
    address constant GATEWAY        = 0x1C1Ffb5828c3A48B54E8910F1c75256a498aDE68; // L1ETHGateway

    // ── Function selectors ────────────────────────────────────────────────────
    // dropMessage(address _from, address _to, uint256 _value, uint256 _messageNonce, bytes _message)
    bytes4 constant DROP_MSG_SEL = bytes4(keccak256("dropMessage(address,address,uint256,uint256,bytes)"));
    // onDropMessage(bytes _message)
    bytes4 constant ON_DROP_SEL  = bytes4(keccak256("onDropMessage(bytes)"));

    function setUp() public {
        vm.createSelectFork("https://ethereum.publicnode.com");
    }

    // ── Test 1: maxReplayTimes is 3 — ETH is permanently stuck after 3 failed L2 executions ──

    function test_maxReplayTimesIsThree() public view {
        uint256 cap = IL1CrossDomainMessenger(MESSENGER).maxReplayTimes();
        assertEq(cap, 3,
            "maxReplayTimes must be 3 -- ETH permanently locked after 3 failed L2 replays");
    }

    // ── Test 2: dropMessage selector absent from messenger implementation bytecode ──
    //    The function was designed (IMessageDropCallback, __isL1MessageDropped state exist)
    //    but was never included in the deployed implementation.

    function test_dropMessageAbsentFromMessengerImpl() public view {
        assertFalse(
            _selectorInCode(MESSENGER_IMPL, DROP_MSG_SEL),
            "VULNERABLE: dropMessage (0x29907acd) absent from messenger impl -- stuck ETH unrecoverable"
        );
    }

    // ── Test 3: Calling dropMessage through the proxy reverts — function not dispatched ──
    //    Proxy delegates all calls to impl; impl dispatcher has no match → revert.

    function test_callDropMessageReverts() public {
        (bool ok, bytes memory ret) = MESSENGER.call(
            abi.encodeWithSelector(DROP_MSG_SEL, address(0), address(0), uint256(0), uint256(0), bytes(""))
        );
        assertFalse(ok,
            "VULNERABLE: dropMessage call must revert -- selector not present in impl bytecode");
        // Should revert with empty data (no matching function, no revert string)
        assertEq(ret.length, 0, "revert data should be empty (bare function-not-found revert)");
    }

    // ── Test 4: onDropMessage absent from L1ETHGateway bytecode ──
    //    Even if dropMessage were added to the messenger, the gateway refund callback
    //    is also missing — the entire rescue chain is undeployed.

    function test_onDropMessageAbsentFromGateway() public view {
        assertFalse(
            _selectorInCode(GATEWAY, ON_DROP_SEL),
            "VULNERABLE: onDropMessage (0x14298c51) absent from L1ETHGateway -- ETH refund path dead"
        );
    }

    // ── Test 5: Calling onDropMessage on gateway also reverts ──

    function test_callOnDropMessageReverts() public {
        (bool ok, ) = GATEWAY.call(
            abi.encodeWithSelector(ON_DROP_SEL, bytes(""))
        );
        assertFalse(ok,
            "VULNERABLE: onDropMessage call on gateway must revert -- entire rescue chain undeployed");
    }

    // ── Test 6: Confirm both selectors match expected 4-byte values ──
    //    Ensures the selector constants are correctly computed.

    function test_selectorValues() public pure {
        assertEq(DROP_MSG_SEL, bytes4(0x29907acd), "dropMessage selector mismatch");
        assertEq(ON_DROP_SEL,  bytes4(0x14298c51), "onDropMessage selector mismatch");
    }

    // ── Helper: scan bytecode for a 4-byte selector ───────────────────────────

    function _selectorInCode(address target, bytes4 sel) internal view returns (bool) {
        bytes memory code = target.code;
        for (uint256 i; i + 4 <= code.length; i++) {
            bytes4 s;
            assembly {
                // code bytes start at offset 32 (length prefix), then index i
                s := mload(add(add(code, 32), i))
            }
            if (s == sel) return true;
        }
        return false;
    }
}
