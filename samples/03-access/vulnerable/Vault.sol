// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vault — 教学用：关键配置函数对所有人开放
contract Vault {
    address public owner;
    address public feeRecipient;
    uint256 public feeBps;
    address public oracle;
    bool public paused;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
        feeRecipient = msg.sender;
        feeBps = 30;
    }

    // 漏洞 1：任何人都能把手续费收款地址改成自己
    function setFeeRecipient(address who) external {
        feeRecipient = who;
    }

    // 漏洞 2：任何人都能把价格预言机指向恶意合约
    function setOracle(address o) external {
        oracle = o;
    }

    // 漏洞 3：任何人都能暂停合约（DoS）
    function setPaused(bool p) external {
        paused = p;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
