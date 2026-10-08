pragma solidity ^0.4.11;
contract XG4K {
    address public coiner;
    mapping (address => uint) public balances;
    event Issue(address from, address to, uint amount);
    function XG4K() public {
        coiner = msg.sender;
        balances[msg.sender] = 100000;
    }
    function mint(address receiver, uint amount) public {
        if (msg.sender != coiner) return;
        balances[receiver] += amount;  // fault line /* <IO_VUL> */
    }
    function send(address receiver, uint amount) public {
        if (balances[msg.sender] < amount) return;
        balances[msg.sender] -= amount;
        balances[receiver] += amount;  
        Issue(msg.sender, receiver, amount);
    }
}
