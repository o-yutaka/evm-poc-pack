// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IUSDC {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function nonces(address owner) external view returns (uint256);
    function name() external view returns (string memory);
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external;
    function allowance(address owner, address spender) external view returns (uint256);
}

/// Diagnostic for the Rhino PoC T3 permit failure (run #2:
/// "EIP2612: invalid signature"). Logs every ingredient instead of
/// asserting, so a single run identifies the mismatching component.
/// NOT part of the submission suite.
contract DiagPermit is Test {
    IUSDC internal constant USDC = IUSDC(0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85);
    address internal constant BRIDGE = 0x0bCa65bf4b4c8803d2f0B49353ed57CAAF3d66Dc;

    bytes32 internal constant PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    bytes32 internal constant EIP712DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    address internal alice;
    uint256 internal alicePk;

    function setUp() public {
        (alice, alicePk) = makeAddrAndKey("alice");
    }

    function _digestWithSeparator(bytes32 separator, uint256 amount, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                separator,
                keccak256(abi.encode(PERMIT_TYPEHASH, alice, BRIDGE, amount, nonce, deadline))
            )
        );
    }

    function test_diag_permit() public {
        uint256 amount = 75e6;
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = USDC.nonces(alice);
        bytes32 storedSep = USDC.DOMAIN_SEPARATOR();

        // Recompute the separator from first principles.
        bytes32 recomputedSep = keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(USDC.name())),
                keccak256(bytes("2")),
                block.chainid,
                address(USDC)
            )
        );

        emit log_named_bytes32("stored DOMAIN_SEPARATOR", storedSep);
        emit log_named_bytes32("recomputed separator (name, v2, chainid, USDC)", recomputedSep);
        emit log_named_uint("chainid", block.chainid);
        emit log_named_uint("nonce(alice)", nonce);
        emit log_named_address("alice", alice);
        emit log_named_address("vm.addr(alicePk)", vm.addr(alicePk));

        // Variant A: stored separator (what T3 signed).
        {
            bytes32 digest = _digestWithSeparator(storedSep, amount, nonce, deadline);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
            address recovered = ecrecover(digest, v, r, s);
            emit log_named_address("A recovered (stored sep)", recovered);
            try USDC.permit(alice, BRIDGE, amount, deadline, v, r, s) {
                emit log_string("A direct permit with stored separator: SUCCESS");
            } catch Error(string memory why) {
                emit log_named_string("A direct permit with stored separator: REVERT", why);
            } catch (bytes memory raw) {
                emit log_named_bytes("A direct permit with stored separator: REVERT raw", raw);
            }
        }

        // Variant B: recomputed separator (fresh nonce read in case A consumed one).
        {
            uint256 nonceB = USDC.nonces(alice);
            bytes32 digest = _digestWithSeparator(recomputedSep, amount, nonceB, deadline);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
            address recovered = ecrecover(digest, v, r, s);
            emit log_named_address("B recovered (recomputed sep)", recovered);
            try USDC.permit(alice, BRIDGE, amount, deadline, v, r, s) {
                emit log_string("B direct permit with recomputed separator: SUCCESS");
            } catch Error(string memory why) {
                emit log_named_string("B direct permit with recomputed separator: REVERT", why);
            } catch (bytes memory raw) {
                emit log_named_bytes("B direct permit with recomputed separator: REVERT raw", raw);
            }
        }

        emit log_named_uint("final allowance(alice, BRIDGE)", USDC.allowance(alice, BRIDGE));
        emit log_named_uint("final nonce(alice)", USDC.nonces(alice));
    }
}
