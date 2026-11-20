// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Token — 修复版：0.8 内建检查 + SafeCast 式上界校验
contract Token {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public totalSupply;

    error InsufficientBalance(uint256 available, uint256 required);
    error ValueTooLarge(uint256 value, uint256 max);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(uint256 amount) external onlyOwner {
        totalSupply += amount;              // 0.8 会在溢出时 revert
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        uint256 bal = balances[msg.sender];
        if (bal < amount) revert InsufficientBalance(bal, amount);  // 显式检查，错误信息精确
        unchecked {
            balances[msg.sender] = bal - amount;  // 已证明不会下溢，省 gas 安全
        }
        payable(msg.sender).transfer(amount);
    }

    function setReward(uint256 r) external {
        if (r > type(uint96).max) revert ValueTooLarge(r, type(uint96).max);
        rewards[msg.sender] = r;
        uint96 packed = uint96(r);
        emit Packed(packed);
    }

    // 先乘后除，避免精度损失
    function scaledReward(uint256 amount, uint256 num, uint256 den) public pure returns (uint256) {
        return amount * num / den;
    }

    event Packed(uint96 v);
}
