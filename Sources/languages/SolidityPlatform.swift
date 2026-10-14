// by cipher.org.uk
import Foundation

/// Solidity global APIs that return untrusted / attacker-controlled data. These
/// seed the Solidity AST taint pass (mirroring the scanner's taint-return set).
/// In a smart contract, the classic untrusted sources are msg/tx globals and
/// anything returned by a low-level external call or an ABI decoder over
/// calldata.
let soliditySourceAPIs: Set<String> = [
    // Global transaction context (attacker-supplied).
    "msg", "msg.sender", "msg.value", "msg.data", "msg.sig",
    "tx", "tx.origin", "tx.gasprice",
    "block", "block.timestamp", "block.number", "blockhash", "block.gaslimit",
    // External / low-level calls return untrusted data.
    "call", "delegatecall", "staticcall", "callcode",
    "call.value", "abi.decode", "abi.encode", "abi.encodePacked",
    // Raw calldata / input decoding.
    "calldata", "mload", "sload", "extcodesize", "extcodecopy",
]

/// Solidity write-through sinks (low-level calls that fill an `out`/return
/// buffer with attacker-controlled data, or storage reads into a slot).
let solidityWriteThroughSinks: Set<String> = [
    "call", "delegatecall", "staticcall", "callcode", "abi.decode",
    "sload", "mload", "extcodecopy",
]
