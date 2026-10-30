// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// Rhino.fi — DVFDepositContract commitment-deposit PoC (DEPLOYED variant).
///
/// Target: Optimism mainnet FORK ONLY. Never run against the live chain;
/// the pack workflow runs this inside the runner as a local fork
/// (fork_rpc_url = https://mainnet.optimism.io), or setUp() creates the
/// fork itself when the proxy has no code (plain `forge test`).
///
///   Proxy (TransparentUpgradeableProxy):
///     0x0bCa65bf4b4c8803d2f0B49353ed57CAAF3d66Dc
///   Implementation (source-verified on Blockscout, read in full):
///     0x7595433A8D01E8e3183EEd8251d288409D3423e5
///
/// This suite is re-aimed at the DEPLOYED Optimism variant, which differs
/// from repo HEAD (rhinofi/contracts_public @ 654c38c):
///   - The deployed build has NO legacy deposit()/depositNative(), NO
///     checkMaxDepositAmount, NO allowDeposits/allowDepositsGlobal.
///     The commitment functions are the ONLY deposit path, gated by
///     nothing but a `noVmCall` same-transaction VM-reentrancy guard.
///   - `depositsDisallowed` / `maxDepositAmount` still exist as storage
///     (public getters answer) but no live function reads or writes them:
///     dead control state.
/// Claims proven (see rhino-commitment-scan.md / rhino-firsthand-read.md):
///   T1  Commitment deposits are unconditional (any EOA, any id).
///   T2  commitmentId has no binding, no dedup, no token whitelist:
///       reuse across accounts, repeats, zero-amount events, and
///       worthless-token events with arbitrary claimed amounts (H1
///       precondition + H4(a): the event carries the *requested* amount).
///   T3  The permit path works with a self-signed permit and credits the
///       same event (H2 stays killed: owner is pinned to msg.sender).
///   T4  No refund path: every value-out function reverts UNAUTHORIZED
///       for the depositor; the funds stay in the proxy (H3 code half).
///   T5  Dead controls: the control *setters* are absent from the
///       deployed implementation while the control *getters* still
///       answer — the state exists, nothing can set or enforce it.
///   C1  Control: an honest deposit's event fields match the transfer
///       exactly (harness reads the real proxy, not a mock).
///
/// Expected green output (quoted BEFORE the run, per pack discipline):
///   "Suite result: ok. 9 passed; 0 failed" — T1 x2, T2 x3, T3, T4, T5, C1.
/// A failure is then classifiable: harness/setup bug (fork, deal(),
/// permit digest) vs fixture bug vs genuine refutation of a claim.

// ---------------------------------------------------------------------------
// Minimal interfaces — the proxy's REAL deployed ABI (from the verified
// Optimism implementation source). No repo imports.
// ---------------------------------------------------------------------------

/// BridgeVM.Call in the deployed build: (address target, uint256 value,
/// bytes data) — canonical struct, affects the withdrawWithData selector.
struct BridgeVMCall {
    address target;
    uint256 value;
    bytes data;
}

interface IDVFDeposit {
    function depositWithId(address token, uint256 amount, uint256 commitmentId) external;
    function depositWithPermit(
        address token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 commitmentId
    ) external;
    function depositNativeWithId(uint256 commitmentId) external payable;
    function withdrawV2(address token, address to, uint256 amount) external;
    function withdrawV2WithNative(address token, address to, uint256 amountToken, uint256 amountNative) external;
    function withdrawV2WithNativeNoEvent(address token, address to, uint256 amountToken, uint256 amountNative)
        external;
    function withdrawNativeV2(address payable to, uint256 amount) external;
    function withdrawWithData(
        address token,
        uint256 amount,
        uint256 amountNative,
        BridgeVMCall[] calldata datas,
        bytes calldata ref_
    ) external payable;
    function withdrawWithDataNoEvent(address token, uint256 amount, uint256 amountNative, BridgeVMCall[] calldata datas)
        external
        payable;
    function removeFunds(address token, address to, uint256 amount) external;
    function removeFundsNative(address payable to, uint256 amount) external;
    function depositsDisallowed() external view returns (bool);
    function maxDepositAmount(address token) external view returns (int256);
    function authorized(address user) external view returns (bool);
}

interface IERC20Min {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// Native USDC on Optimism is Circle FiatTokenV2_2 (impl
/// 0xdEd3b9a8DBeDC2F9CB725B55d0E686A81E6d06dC). Its deployed ABI exposes
/// DOMAIN_SEPARATOR(), nonces(address) and the (v, r, s) permit overload
/// that DVFDepositContract calls — all verified against the Blockscout
/// record of the implementation before writing this suite.
interface IUSDCExtras {
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// Minimal worthless ERC20, deployed by the test itself (T2): proves the
/// commitment path has no token whitelist and emits the claimed amount.
contract MockWorthlessToken {
    string public name = "Worthless Test Token";
    string public symbol = "WORTH";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Mock/insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "Mock/allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        require(balanceOf[from] >= amount, "Mock/insufficient");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract RhinoCommitmentPoC is Test {
    // --- Real Optimism addresses (fork state) ---
    IDVFDeposit internal constant BRIDGE = IDVFDeposit(0x0bCa65bf4b4c8803d2f0B49353ed57CAAF3d66Dc);
    IERC20Min internal constant USDC = IERC20Min(0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85);

    string internal constant FORK_RPC = "https://mainnet.optimism.io";

    /// EIP-2612 permit typehash — read from the deployed USDC source
    /// (PERMIT_TYPEHASH constant in FiatTokenV2_2, verified on Blockscout).
    bytes32 internal constant PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    // The deployed event (no indexed fields).
    event BridgedDepositWithId(address sender, address origin, address token, uint256 amount, uint256 commitmentId);

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    address internal victim;
    address internal carol;

    function setUp() public {
        // Primary mode: the pack workflow passes --fork-url, so the fork
        // is already active and the proxy has code. Fallback mode: plain
        // `forge test` — create the Optimism fork here (latest block).
        if (address(BRIDGE).code.length == 0) {
            vm.createSelectFork(FORK_RPC);
        }
        (alice, alicePk) = makeAddrAndKey("alice");
        bob = makeAddr("bob");
        victim = makeAddr("victim");
        carol = makeAddr("carol");
    }

    // --- helpers -----------------------------------------------------------

    function _fundUsdc(address who, uint256 amount) internal {
        deal(address(USDC), who, amount);
        // Visible, classifiable failure if deal() cannot write USDC's
        // balance slot on the fork (harness bug, not a claim refutation).
        assertEq(USDC.balanceOf(who), amount, "deal() failed to fund USDC");
    }

    function _approveMax(address who) internal {
        vm.prank(who);
        USDC.approve(address(BRIDGE), type(uint256).max);
    }

    function _expectDepositEvent(address sender, address token, uint256 amount, uint256 id) internal {
        // origin is tx.origin at call time: constant across the test tx,
        // and exactly what the deployed contract records.
        vm.expectEmit(false, false, false, true, address(BRIDGE));
        emit BridgedDepositWithId(sender, tx.origin, token, amount, id);
    }

    // --- T1: unconditional deposits ----------------------------------------

    /// A fresh EOA deposits USDC under an arbitrary commitmentId. No
    /// registration, no whitelist entry, no prior interaction — the call
    /// succeeds, the proxy's balance grows by exactly the amount, and the
    /// event carries the exact (sender, origin, token, amount, id).
    function test_T1_depositWithId_unconditional_succeedsAndEmits() public {
        uint256 amount = 100e6; // 100 USDC
        uint256 id = 424242;
        _fundUsdc(alice, 1_000e6);
        _approveMax(alice);

        uint256 proxyBefore = USDC.balanceOf(address(BRIDGE));
        uint256 aliceBefore = USDC.balanceOf(alice);

        _expectDepositEvent(alice, address(USDC), amount, id);
        vm.prank(alice);
        BRIDGE.depositWithId(address(USDC), amount, id);

        assertEq(USDC.balanceOf(address(BRIDGE)), proxyBefore + amount, "proxy balance must increase by amount");
        assertEq(USDC.balanceOf(alice), aliceBefore - amount, "alice balance must decrease by amount");
    }

    /// Same for the native path: anyone can deposit ETH under any id;
    /// the event records token = address(0) and amount = msg.value.
    function test_T1_depositNativeWithId_unconditional_succeedsAndEmits() public {
        uint256 id = 989898;
        vm.deal(alice, 10 ether);

        uint256 proxyBefore = address(BRIDGE).balance;

        _expectDepositEvent(alice, address(0), 1 ether, id);
        vm.prank(alice);
        BRIDGE.depositNativeWithId{value: 1 ether}(id);

        assertEq(address(BRIDGE).balance, proxyBefore + 1 ether, "proxy ETH balance must increase by msg.value");
        assertEq(alice.balance, 9 ether, "alice ETH balance must decrease by msg.value");
    }

    // --- T2: no binding, no dedup, no whitelist -----------------------------

    /// The same commitmentId is accepted from two different accounts and
    /// repeatedly from the same account. Nothing on-chain records the id
    /// as used, binds it to a sender, or rejects a replay.
    function test_T2_sameCommitmentId_reusableAcrossAccountsAndRepeats() public {
        uint256 id = 31337;
        _fundUsdc(alice, 1_000e6);
        _fundUsdc(bob, 1_000e6);
        _approveMax(alice);
        _approveMax(bob);

        uint256 proxyBefore = USDC.balanceOf(address(BRIDGE));

        _expectDepositEvent(alice, address(USDC), 10e6, id);
        vm.prank(alice);
        BRIDGE.depositWithId(address(USDC), 10e6, id);

        // A DIFFERENT account reuses the very same commitmentId.
        _expectDepositEvent(bob, address(USDC), 20e6, id);
        vm.prank(bob);
        BRIDGE.depositWithId(address(USDC), 20e6, id);

        // The SAME account deposits twice more under that id.
        _expectDepositEvent(alice, address(USDC), 30e6, id);
        vm.prank(alice);
        BRIDGE.depositWithId(address(USDC), 30e6, id);

        _expectDepositEvent(alice, address(USDC), 40e6, id);
        vm.prank(alice);
        BRIDGE.depositWithId(address(USDC), 40e6, id);

        assertEq(
            USDC.balanceOf(address(BRIDGE)), proxyBefore + 100e6, "all four same-id deposits must land in the proxy"
        );
    }

    /// A zero-amount deposit emits a syntactically valid commitment event:
    /// the event stream for any id can be squatted/flooded at gas cost
    /// only (strengthens the H1 precondition).
    function test_T2_zeroAmountDeposit_emitsValidEvent() public {
        uint256 id = 606060;
        _fundUsdc(alice, 1_000e6);
        _approveMax(alice);

        uint256 proxyBefore = USDC.balanceOf(address(BRIDGE));

        _expectDepositEvent(alice, address(USDC), 0, id);
        vm.prank(alice);
        BRIDGE.depositWithId(address(USDC), 0, id);

        assertEq(USDC.balanceOf(address(BRIDGE)), proxyBefore, "zero-amount deposit moves no value");
    }

    /// A worthless, test-deployed token with an astronomical claimed
    /// amount produces a perfectly valid BridgedDepositWithId event:
    /// there is no token whitelist, and the event amount is the
    /// *requested* parameter, never a measured balance delta (H4(a)).
    function test_T2_worthlessToken_hugeClaimedAmount_emitsEvent() public {
        uint256 id = 121212;
        uint256 huge = 1_000_000_000e18; // 1 billion "tokens"
        MockWorthlessToken worthless = new MockWorthlessToken();
        worthless.mint(bob, huge);
        vm.prank(bob);
        worthless.approve(address(BRIDGE), type(uint256).max);

        _expectDepositEvent(bob, address(worthless), huge, id);
        vm.prank(bob);
        BRIDGE.depositWithId(address(worthless), huge, id);

        assertEq(worthless.balanceOf(address(BRIDGE)), huge, "proxy holds the worthless tokens");
        // The crediting event claims `huge` of an asset with no value and
        // no listing anywhere — indistinguishable in form from a USDC one.
    }

    // --- T3: permit path -----------------------------------------------------

    /// depositWithPermit with a self-signed EIP-2612 permit succeeds with
    /// NO prior on-chain approval and credits the same event. (The permit
    /// owner is pinned to msg.sender in the deployed code, so the signer
    /// must be the caller — H2 stays killed; this proves the permit entry
    /// point itself is live and unconditional.)
    function test_T3_depositWithPermit_selfSigned_succeeds() public {
        uint256 amount = 75e6; // 75 USDC
        uint256 id = 777003;
        _fundUsdc(alice, 1_000e6);
        // Deliberately NO approve(): the permit alone must carry it.
        assertEq(USDC.allowance(alice, address(BRIDGE)), 0, "precondition: no existing allowance");

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = IUSDCExtras(address(USDC)).nonces(alice);
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                IUSDCExtras(address(USDC)).DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_TYPEHASH, alice, address(BRIDGE), amount, nonce, deadline))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);

        uint256 proxyBefore = USDC.balanceOf(address(BRIDGE));

        _expectDepositEvent(alice, address(USDC), amount, id);
        vm.prank(alice);
        BRIDGE.depositWithPermit(address(USDC), amount, deadline, v, r, s, id);

        assertEq(USDC.balanceOf(address(BRIDGE)), proxyBefore + amount, "permit deposit must land in the proxy");
        assertEq(USDC.allowance(alice, address(BRIDGE)), 0, "permit allowance must be fully consumed by the deposit");
    }

    // --- T4: no refund path --------------------------------------------------

    /// After depositing under a garbage commitmentId (which the contract
    /// itself warns "will result in a deposit not being processed"), the
    /// victim tries EVERY value-out function on the proxy. Each reverts
    /// UNAUTHORIZED — the only keyholders who could return the funds are
    /// the operator's authorized addresses. The victim's money does not
    /// move. (H3 code half, against the deployed variant.)
    function test_T4_noRefundPath_allValueOutFunctions_revertUnauthorized() public {
        uint256 garbageId = 0xdeadbeef;
        _fundUsdc(victim, 1_000e6);
        _approveMax(victim);
        vm.deal(victim, 10 ether);

        vm.prank(victim);
        BRIDGE.depositWithId(address(USDC), 50e6, garbageId);
        vm.prank(victim);
        BRIDGE.depositNativeWithId{value: 0.5 ether}(garbageId);

        // Precondition: the victim is not an authorized operator.
        assertFalse(BRIDGE.authorized(victim), "precondition: victim must not be authorized");

        uint256 proxyUsdcAfter = USDC.balanceOf(address(BRIDGE));
        uint256 proxyEthAfter = address(BRIDGE).balance;
        uint256 victimUsdcAfter = USDC.balanceOf(victim);
        uint256 victimEthAfter = victim.balance;

        BridgeVMCall[] memory noCalls = new BridgeVMCall[](0);

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.withdrawV2(address(USDC), victim, 50e6);

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.withdrawV2WithNative(address(USDC), victim, 50e6, 0.5 ether);

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.withdrawV2WithNativeNoEvent(address(USDC), victim, 50e6, 0.5 ether);

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.withdrawNativeV2(payable(victim), 0.5 ether);

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.withdrawWithData(address(USDC), 50e6, 0, noCalls, bytes(""));

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.withdrawWithDataNoEvent(address(USDC), 50e6, 0, noCalls);

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.removeFunds(address(USDC), victim, 50e6);

        vm.prank(victim);
        vm.expectRevert("UNAUTHORIZED");
        BRIDGE.removeFundsNative(payable(victim), 0.5 ether);

        // Nothing came back and nothing left: the deposit is stranded
        // unless an authorized operator chooses to act.
        assertEq(USDC.balanceOf(address(BRIDGE)), proxyUsdcAfter, "proxy USDC balance must be unchanged");
        assertEq(address(BRIDGE).balance, proxyEthAfter, "proxy ETH balance must be unchanged");
        assertEq(USDC.balanceOf(victim), victimUsdcAfter, "victim recovered no USDC");
        assertEq(victim.balance, victimEthAfter, "victim recovered no ETH");
    }

    // --- T5: dead controls (deployed-variant specific) -----------------------

    /// The deployed implementation still carries the deposit-control
    /// STATE (the getters answer), but the functions that could set or
    /// enforce it were removed entirely: low-level calls carrying the
    /// allowDeposits / allowDepositsGlobal selectors FAIL (no such
    /// function behind the proxy), and so do the legacy deposit
    /// selectors — the controlled path does not exist in this build.
    function test_T5_deadControls_gettersAnswerButSettersAbsent() public {
        // Getters DO answer through the proxy: the state exists.
        (bool okDisallowed, bytes memory retDisallowed) =
            address(BRIDGE).call(abi.encodeWithSignature("depositsDisallowed()"));
        assertTrue(okDisallowed, "depositsDisallowed() getter must answer");
        abi.decode(retDisallowed, (bool)); // decodes without reverting

        (bool okMax, bytes memory retMax) =
            address(BRIDGE).call(abi.encodeWithSignature("maxDepositAmount(address)", address(USDC)));
        assertTrue(okMax, "maxDepositAmount(address) getter must answer");
        abi.decode(retMax, (int256)); // decodes without reverting

        // The setters DO NOT exist in the deployed implementation: the
        // proxy delegates, the implementation has no fallback, the call
        // fails. There is no live way to arm either control.
        (bool okAllow,) =
            address(BRIDGE).call(abi.encodeWithSignature("allowDeposits(address,int256)", address(USDC), int256(-1)));
        assertFalse(okAllow, "allowDeposits(address,int256) must be ABSENT from the deployed implementation");

        (bool okGlobal,) = address(BRIDGE).call(abi.encodeWithSignature("allowDepositsGlobal(bool)", true));
        assertFalse(okGlobal, "allowDepositsGlobal(bool) must be ABSENT from the deployed implementation");

        // Bonus (same fact, enforcement side): the legacy controlled
        // deposit entry points are gone from this build too.
        (bool okLegacy,) =
            address(BRIDGE).call(abi.encodeWithSignature("deposit(address,uint256)", address(USDC), uint256(1)));
        assertFalse(okLegacy, "legacy deposit(address,uint256) must be ABSENT from the deployed implementation");

        (bool okLegacyNative,) = address(BRIDGE).call(abi.encodeWithSignature("depositNative()"));
        assertFalse(okLegacyNative, "legacy depositNative() must be ABSENT from the deployed implementation");
    }

    // --- C1: control ---------------------------------------------------------

    /// Control: an honest deposit through the primary path, with a fresh
    /// unique commitmentId, lands exactly — balances move by exactly the
    /// amount and every event field matches the transfer. Proves the
    /// harness is reading the REAL proxy on the REAL fork (code present,
    /// deltas exact), so the T1–T5 results isolate the contract's
    /// behaviour rather than a broken fixture.
    function test_C1_control_honestDeposit_eventMatchesTransfer() public {
        assertGt(address(BRIDGE).code.length, 0, "proxy must have code on the fork");
        assertGt(address(USDC).code.length, 0, "USDC must have code on the fork");

        uint256 amount = 250e6; // 250 USDC
        uint256 id = 0xC0FFEE;
        _fundUsdc(carol, 1_000e6);
        _approveMax(carol);

        uint256 proxyBefore = USDC.balanceOf(address(BRIDGE));
        uint256 carolBefore = USDC.balanceOf(carol);

        _expectDepositEvent(carol, address(USDC), amount, id);
        vm.prank(carol);
        BRIDGE.depositWithId(address(USDC), amount, id);

        assertEq(USDC.balanceOf(address(BRIDGE)) - proxyBefore, amount, "proxy delta must equal the deposit amount");
        assertEq(carolBefore - USDC.balanceOf(carol), amount, "sender delta must equal the deposit amount");
    }
}
