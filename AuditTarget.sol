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
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    event FeeWalletChanged(address indexed previousWallet, address indexed newWallet);

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

    constructor(address payable initialFeeWallet) {
        require(initialFeeWallet != address(0), "zero");
        owner = msg.sender;
        feeWallet = initialFeeWallet;
    }

    function topUp() external payable {
        ledger[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function ownerWithdraw(uint256 amount) external onlyOwner {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = payable(owner).call{value: amount}("");
        require(ok, "withdraw failed");
    }

    function changeOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function setFeeWallet(address payable newWallet) external onlyOwner {
        require(newWallet != address(0), "zero");
        emit FeeWalletChanged(feeWallet, newWallet);
        feeWallet = newWallet;
    }

    function withdraw() external {
        uint256 amount = ledger[msg.sender];
        require(amount > 0, "empty");
        ledger[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function settleFees() external onlyOwner {
        feeWallet.transfer(address(this).balance / 2);
    }

    function fundSafe() external payable exclusive {
        safeBalances[msg.sender] += msg.value;
    }

    function withdrawSafe() external exclusive {
        uint256 a = safeBalances[msg.sender];
        require(a > 0, "empty");
        safeBalances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
    }

    // View-only: ket qua chi de hien thi, khong dung cho phan quyen/chuyen tien.
    function isEmpty() external view returns (bool) {
        // slither-disable-next-line incorrect-equality
        return address(this).balance == 0;
    }
}
