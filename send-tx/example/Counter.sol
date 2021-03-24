pragma solidity ^0.4.24;

contract Counter {
    uint public count;

    function add() public {
        count += 1;
    }

    function reset() public {
        count = 0;
    }
}
