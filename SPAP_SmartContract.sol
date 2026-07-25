// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

contract SPAPContract {

    address public avaM;
    address public avaN;
    address public custodian;

    uint public sessionTime;
    uint public gracePeriod;
    uint public deposit;

    bool public avatarSigned;
    bool public custodianSigned;

    constructor(
        address _avaN,
        address _custodian,
        uint _gracePeriod
    ) payable {

        avaM = msg.sender;
        avaN = _avaN;
        custodian = _custodian;

        gracePeriod = _gracePeriod;

        sessionTime = block.timestamp;

        deposit = msg.value;
    }



function signByAvatar() public{

    require(msg.sender == avaM);

    avatarSigned = true;

}

function signByCustodian() public{

    require(msg.sender == custodian);

    custodianSigned = true;

}

function settle() public{

    if(

        block.timestamp >

        sessionTime + gracePeriod

    ){

        payable(avaM).transfer(

            address(this).balance

        );

    }

    else if(

        avatarSigned && custodianSigned

    ){

        payable(avaN).transfer(

            address(this).balance

        );

    }

    else{

        revert("Invalid Transaction");

    }

}
    }