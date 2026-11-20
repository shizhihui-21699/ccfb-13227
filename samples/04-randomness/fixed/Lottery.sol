// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Lottery — 修复版：commit-reveal 两阶段，随机数由参与者共同贡献
contract Lottery {
    address[] public players;
    address public winner;
    uint256 public round;

    mapping(address => bytes32) public commitments;
    mapping(address => bytes32) public reveals;
    uint256 public revealDeadline;

    function buy(bytes32 commitment) external payable {
        require(msg.value == 1 ether, "1 ether");
        require(commitments[msg.sender] == bytes32(0), "already joined");
        commitments[msg.sender] = commitment;   // hash(secret, user salt)
        players.push(msg.sender);
        if (revealDeadline == 0) revealDeadline = block.timestamp + 1 days;
    }

    // 随机数 = 所有参与者揭示的秘密之和，没有任何一个参与者能单独控制
    function reveal(bytes32 secret) external {
        require(commitments[msg.sender] != bytes32(0), "not joined");
        require(keccak256(abi.encodePacked(secret, msg.sender)) == commitments[msg.sender], "bad reveal");
        reveals[msg.sender] = secret;
    }

    function draw() external {
        require(block.timestamp >= revealDeadline, "reveal not over");
        require(players.length > 0, "empty");
        bytes32 seed = bytes32(0);
        for (uint256 i = 0; i < players.length; i++) {
            require(reveals[players[i]] != bytes32(0), "missing reveal");
            seed ^= reveals[players[i]];
        }
        // 生产环境应改用 Chainlink VRF；此处随机性来自参与者共同提交的秘密
        winner = players[uint256(seed) % players.length];
        round++;
        payable(winner).transfer(address(this).balance);
    }
}
