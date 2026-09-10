// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract WCOEN {
    string public name = "Wrapped Rudis";
    string public symbol = "wrudis";
    uint8 public decimals = 18;

    error NativeTransferFailed(address to, uint256 amount);

    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    uint256 private _totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    receive() external payable {
        deposit();
    }

    function deposit() public payable {
        _totalSupply += msg.value;
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad);
        require(address(this).balance >= wad);
        _totalSupply -= wad;
        balanceOf[msg.sender] -= wad;

        (bool success,) = payable(msg.sender).call{value: wad}("");
        if (!success) revert NativeTransferFailed(msg.sender, wad);

        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function increaseAllowance(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] += wad;
        emit Approval(msg.sender, guy, allowance[msg.sender][guy]);
        return true;
    }

    function decreaseAllowance(address guy, uint256 wad) public returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][guy];
        require(currentAllowance >= wad);
        unchecked {
            allowance[msg.sender][guy] = currentAllowance - wad;
        }
        emit Approval(msg.sender, guy, allowance[msg.sender][guy]);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);

        return true;
    }
}
