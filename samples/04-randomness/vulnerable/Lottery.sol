// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/// @title Lottery — 教学用：用区块属性当随机数
contract Lottery {
    address[] public players;
    address public winner;
    uint256 public round;

    function buy() external payable {
        require(msg.value == 1 ether, "1 ether");
        players.push(msg.sender);
    }

    // 漏洞 1：timestamp 取模决定中奖者
    function drawByTime() external {
        require(players.length > 0, "empty");
        uint256 idx = block.timestamp % players.length;
        winner = players[idx];
        round++;
        payable(winner).transfer(address(this).balance);
    }

    // 漏洞 2：keccak256 里唯一的熵还是区块属性
    function drawByHash() external {
        uint256 idx = uint256(keccak256(abi.encodePacked(block.difficulty, block.number))) % players.length;
        winner = players[idx];
        round++;
        payable(winner).transfer(address(this).balance);
    }

    // 漏洞 3：用 block.coinbase 决定中奖号码
    function coinbaseTicket(address who) public view returns (uint256) {
        return uint256(uint160(who)) % 7 + uint256(uint160(block.coinbase)) % 3;
    }
}
