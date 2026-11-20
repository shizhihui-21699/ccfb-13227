// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Fixture for parser coverage: it is not a vulnerability sample, it exists to
/// prove that the tolerant parser accepts ordinary, complex Solidity without
/// diagnostics.
interface IOracle {
    function latest() external view returns (uint256 price, uint256 updatedAt);
}

library MathLib {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

abstract contract Base {
    uint256 internal immutable deployedAt;
    error Unauthorized(address caller);
    event Changed(address indexed who, uint256 amount);

    constructor() {
        deployedAt = block.timestamp;
    }

    function _check() internal view virtual;
}

contract Kitchen is Base {
    using MathLib for uint256;

    enum Status { Idle, Active, Closed }

    struct Position {
        uint128 size;
        uint64 openedAt;
        Status status;
        address owner;
    }

    mapping(address => Position[]) public positions;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256[] public history;
    IOracle public oracle;
    Status public status;
    bytes32 public constant ROLE = keccak256("ROLE");
    string public name = unicode"测试代币";
    bytes public blob = hex"deadbeef";

    modifier onlyActive() {
        require(status == Status.Active, "inactive");
        _;
    }

    function _check() internal view override {
        require(msg.sender != address(0), "zero");
    }

    function open(uint128 size) external onlyActive returns (uint256 id) {
        Position memory p = Position({
            size: size,
            openedAt: uint64(block.timestamp),
            status: Status.Active,
            owner: msg.sender
        });
        positions[msg.sender].push(p);
        id = positions[msg.sender].length - 1;

        unchecked {
            history.push(id);
        }
        emit Changed(msg.sender, size);
    }

    function readOracle() external view returns (uint256) {
        (uint256 price, ) = IOracle(oracle).latest();
        return price;
    }

    function safeRead() external returns (uint256 out) {
        try IOracle(address(oracle)).latest() returns (uint256 price, uint256) {
            out = price;
        } catch Error(string memory reason) {
            revert(reason);
        } catch (bytes memory) {
            out = 0;
        }
    }

    function loops(uint256 n) external pure returns (uint256 acc) {
        for (uint256 i = 0; i < n; i++) {
            if (i % 2 == 0) {
                continue;
            }
            acc += i;
        }
        uint256 j = 0;
        while (j < 3) {
            j++;
        }
        do {
            j--;
        } while (j > 0);
    }

    function asm(uint256 x) external pure returns (uint256 y) {
        assembly {
            y := add(x, 1)
        }
    }

    function payableFlow() external payable {
        (bool ok, bytes memory ret) = payable(msg.sender).call{value: msg.value, gas: 5000}("");
        require(ok && ret.length == 0, "failed");
        uint256 a = msg.value > 1 ether ? msg.value : 1 ether;
        a = a ** 2 % 100;
        a <<= 1;
        delete history;
    }

    function tup() external view returns (uint256, uint256) {
        uint256[] storage h = history;
        return (h.length, positions[msg.sender].length);
    }
}
