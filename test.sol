// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vulnerable {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}