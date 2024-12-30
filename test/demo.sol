// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import './utils/ERC20.sol';

contract Token is ERC20("Token", "TOKEN") {

    address owner;
    uint256 tokenPerEth = 100;
    ERC20 token1;
    address payable dev1;
    address payable dev2;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor(address _token, address _dev1, address _dev2) {
        token1 = ERC20(_token);
        dev1 = payable(_dev1);
        dev2 = payable(_dev2);
        owner = msg.sender;
    }

    function buy(uint256 _gate) public payable {
        uint256 token_amount;
        if(_gate / 10000 > 3) {
            token_amount = msg.value / 1e18 * tokenPerEth;
        }
        transferFrom(address(this), msg.sender, token_amount);
    }

    function sell(uint256 _amount) public {
        transfer(address(this), _amount);
        uint256 eth_amount = (_amount * 1e18 + (tokenPerEth -1)) / tokenPerEth;
        payable(msg.sender).transfer(eth_amount);
    }

    function withdrawToken(uint256 _amount) public onlyOwner {
        token1.transfer(msg.sender, _amount);
    }

    function devWithdraw() public onlyOwner {
        uint256 bal = address(this).balance;
        dev1.transfer(bal / 2);
        dev2.transfer(bal / 2);
    }

}