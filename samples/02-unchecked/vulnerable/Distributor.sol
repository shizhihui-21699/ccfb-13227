// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Distributor — 教学用：所有失败路径都被忽略
contract Distributor {
    IERC20 public token;
    mapping(address => uint256) public credits;

    function claim(uint256 amount, address payable dest) external {
        // 漏洞 1：低级调用返回值被完全丢弃。失败时合约仍继续执行。
        dest.call{value: amount}("");
        credits[msg.sender] += amount;
    }

    // 漏洞 2：ERC20 transfer 返回 false（如 USDT 黑名单、余额不足）时无人检查
    function withdrawToken(uint256 amount) external {
        token.transfer(msg.sender, amount);
        credits[msg.sender] = 0;
    }

    // 漏洞 3：返回值赋给了变量，但从未读取
    function pull(uint256 amount) external {
        (bool ok, ) = address(token).call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, address(this), amount)
        );
        credits[msg.sender] += amount;
    }
}
