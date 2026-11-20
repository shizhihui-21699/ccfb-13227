// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/// @title VulnerableBank — 教学用：重入 + 未检查返回值
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // 漏洞 1：先转账给 msg.sender，再清零余额。
    // 攻击者在 receive() 里再次调用 withdraw，balances 仍是旧值。
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        // 返回值虽被接收但从未检查
        balances[msg.sender] = 0;
    }

    // 漏洞 2：低级调用结果完全丢弃
    function payout(address payable to, uint256 amount) external payable {
        to.call{value: amount}("");
        balances[to] = 0;
    }

    function total() external view returns (uint256) {
        return address(this).balance;
    }
}
