/**
 *Submitted for verification at Etherscan.io on 2017-08-14
*/

pragma solidity ^0.4.14;

 contract ERC20Interface {
     function totalSupply() constant returns (uint256 totalSupply);
     function balanceOf(address _owner) constant returns (uint256 balance);
     function transfer(address _to, uint256 _value) returns (bool success);
     function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
     function approve(address _spender, uint256 _value) returns (bool success);
     function allowance(address _owner, address _spender) constant returns (uint256 remaining);
     event Transfer(address indexed _from, address indexed _to, uint256 _value);
     event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 }
  
 contract APIHeaven is ERC20Interface {
     string public constant symbol = "☁";
     string public constant name = "API Heaven clouds";
     uint8 public constant decimals = 0;
     uint256 _totalSupply = 1000000000000000; 
     
     uint256 public cloudsPerEth = 300000;
     
     address public owner;

     bool public selling = false;
  
     mapping(address => uint256) balances;
  
     mapping(address => mapping (address => uint256)) allowed;
  
     modifier onlyOwner() {
         if (msg.sender != owner) {
             revert();
         }
         _;
     }

    
     function transferOwnership(address newOwner) onlyOwner {
        balances[newOwner] = balances[owner];
        balances[owner] = 0;
        owner = newOwner;
    }

    
     function changeCloudsPerEth(uint256 newcloudworth) onlyOwner {
        cloudsPerEth = newcloudworth;
    }

    
    function changeSale(bool _sale) onlyOwner {
        selling = _sale;
    }
  
     function APIHeaven() {
         owner = msg.sender;
         balances[owner] = _totalSupply;
     }
  
     function totalSupply() constant returns (uint256 totalSupply) {
         totalSupply = _totalSupply;
     }
  
     function balanceOf(address _owner) constant returns (uint256 balance) {
         return balances[_owner];
     }
    function transfer(address _to, uint256 _amount) returns (bool success) {
        
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            
            return true;
        } else {
            return false;
        }
    }
    function sale() payable {
        if(selling == false) revert();     
        uint256 amount = (msg.value / 1000000000000000) * cloudsPerEth;              
        if (balances[owner] < amount) revert();            
        balances[msg.sender] += amount;                
        balances[owner] -= amount;                      
        Transfer(owner, msg.sender, amount);             
    }
  
     function transferFrom(
         address _from,
         address _to,
         uint256 _amount
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}