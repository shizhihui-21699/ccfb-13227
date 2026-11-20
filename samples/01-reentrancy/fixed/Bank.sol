// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SafeBank — 修复版：checks-effects-interactions + 互斥锁 + 返回值检查
contract SafeBank {
    mapping(address => uint256) public balances;

    uint256 private _locked = 1;
    modifier nonReentrant() {
        require(_locked == 1, "reentrant");
        _locked = 2;
        _;
        _locked = 1;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // 修复 1：先清零余额（effects），再转账（interaction）；并检查返回值
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        balances[msg.sender] = 0;              // effects before interaction
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");        // 检查返回值，失败则回滚
    }

    // 修复 2：先注销余额，再付款，并检查结果
    function payout(address payable to, uint256 amount) external {
        require(msg.sender == to, "only self");
        require(balances[to] >= amount, "insufficient");
        balances[to] -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "payout failed");
    }

    function total() external view returns (uint256) {
        return address(this).balance;
    }
}
