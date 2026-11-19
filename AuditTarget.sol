// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// NT547 - Lab 06 - Hop dong rieng cua MSSV 24521263. KHONG deploy len mainnet.

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract StakingPool_1263 {
    address public owner;
    mapping(address => uint256) public ledger;
    address payable internal feeWallet;
    bool private mutex;
    mapping(address => uint256) public safeBalances;

    event Deposited(address indexed who, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier exclusive() {
        require(!mutex, "reentrant");
        mutex = true;
        _;
        mutex = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function topUp() external payable {
        ledger[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function ownerWithdraw(uint256 amount) external onlyOwner {
        (bool ok, ) = payable(owner).call{value: amount}("");
        require(ok, "withdraw failed");
    }

    function changeOwner(address newOwner) external {
        require(tx.origin == owner, "not owner");
        require(newOwner != address(0), "zero");
        owner = newOwner;
    }

    function withdraw() external {
        uint256 amount = ledger[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        ledger[msg.sender] = 0;
    }

    function settleFees() external onlyOwner {
        feeWallet.transfer(address(this).balance / 2);
    }

    function shutdown() external {
        selfdestruct(payable(msg.sender));
    }

    function fundSafe() external payable exclusive {
        safeBalances[msg.sender] += msg.value;
    }

    function withdrawSafe() external exclusive {
        uint256 a = safeBalances[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
        safeBalances[msg.sender] = 0;
    }

    function isEmpty() external view returns (bool) {
        return address(this).balance == 0;
    }
}
