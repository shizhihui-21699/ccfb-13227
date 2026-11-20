// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Distributor — 修复版：每条外部调用都检查结果
contract Distributor {
    IERC20 public token;
    mapping(address => uint256) public credits;

    error TransferFailed();

    function claim(uint256 amount, address payable dest) external {
        credits[msg.sender] += amount;
        (bool ok, ) = dest.call{value: amount}("");
        if (!ok) revert TransferFailed();      // 失败即回滚，不会留下错误的记账
    }

    function withdrawToken(uint256 amount) external {
        credits[msg.sender] = 0;
        // 兼容不返回 bool 的代币：同时检查返回数据长度与内容
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transfer.selector, msg.sender, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function pull(uint256 amount) external {
        // 记账先于外部调用：即使代币在转账过程中回调本合约，看到的额度已更新
        credits[msg.sender] += amount;
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, address(this), amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "pull failed");
    }
}
