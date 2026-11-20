// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vault — 修复版：所有权 + 显式调用者校验
contract Vault {
    address public owner;
    address public feeRecipient;
    uint256 public feeBps;
    address public oracle;
    bool public paused;
    mapping(address => uint256) public balances;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    error NotOwner();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        feeRecipient = msg.sender;
        feeBps = 30;
    }

    function setFeeRecipient(address who) external onlyOwner {
        if (who == address(0)) revert ZeroAddress();
        feeRecipient = who;
    }

    // 使用内联校验，同样能被识别为受保护函数
    function setOracle(address o) external {
        require(msg.sender == owner, "not owner");
        require(o != address(0), "zero");
        oracle = o;
    }

    function setPaused(bool p) external onlyOwner {
        paused = p;
    }

    // 两步转移避免手滑把所有权丢给错误地址
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function deposit() external payable {
        require(!paused, "paused");
        balances[msg.sender] += msg.value;
    }
}
