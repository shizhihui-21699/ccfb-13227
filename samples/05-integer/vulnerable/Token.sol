// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/// @title Token — 教学用：0.7 的整数溢出 + 收窄转换
contract Token {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public totalSupply;

    function mint(uint256 amount) external {
        // 漏洞 1：0.7 下 + 会静默回绕
        totalSupply = totalSupply + amount;
        balances[msg.sender] += amount;
    }

    // 漏洞 2：先减后检查——余额为 0 时下溢成 2^256-1
    function withdraw(uint256 amount) external {
        balances[msg.sender] = balances[msg.sender] - amount;
        payable(msg.sender).transfer(amount);
    }

    // 漏洞 3：uint256 -> uint96 收窄转换，没有上界检查
    function setReward(uint256 r) external {
        rewards[msg.sender] = r;
        uint96 packed = uint96(r);
        emit Packed(packed);
    }

    event Packed(uint96 v);
}
