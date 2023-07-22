// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.8.13 <0.9.0;

import "fhevm/abstracts/EIP712WithModifier.sol";
import "fhevm/lib/TFHE.sol";

contract EncryptedERC20 is EIP712WithModifier {
    euint32 private totalSupply;
    string public constant name = "FHE Voting"; // City of Zama's battle
    string public constant symbol = "VOTE";

    // used for output authorization
    uint public endTime;
    uint public totalVotes;
    uint public maxVotes = 10;

    euint32 public tally;
    euint32 public tally2;

    // A mapping from address to an encrypted balance.
    mapping(address => ebool) internal list_of_voters;

    // The owner of the contract.
    address internal contractOwner;

    error TooEarly(uint time);
    error TooLate(uint time);

    constructor(uint votingPeriod) EIP712WithModifier("Authorization token", "1") {
        contractOwner = msg.sender;
        endTime = block.timestamp + votingPeriod;
        totalVotes = 0;
    }


    // Sets the balance of the owner to the given encrypted balance.
    function vote(bytes calldata encryptedBallot, bytes calldata encryptedBallot2) public 
    canVote() {
        euint32 ballot = TFHE.asEuint32(encryptedBallot);
        euint32 ballot2 = TFHE.asEuint32(encryptedBallot2);

        ebool has_voted = _has_voted(msg.sender);
        euint32 mask1 = TFHE.and(ballot,  TFHE.asEuint32(4177066232)); 
        mask1 = TFHE.sub(ballot, mask1);
        euint32 mask2 = TFHE.and(ballot2, TFHE.asEuint32(4177066232));
        mask2 = TFHE.sub(ballot, mask2);

        mask1 = TFHE.and(ballot, mask1);
        mask2 = TFHE.and(ballot2, mask2);
        ebool is_valid_vote = TFHE.eq(mask1, euint32.wrap(0)); // true if mask1 == 0 
        ebool is_valid_vote2 = TFHE.eq(mask2, euint32.wrap(0)); // true if mask2 == 0
        is_valid_vote = TFHE.asEbool(TFHE.and(TFHE.asEuint8(is_valid_vote), TFHE.asEuint8(is_valid_vote2))); // true if mask1 == mask2 == true
        is_valid_vote = TFHE.asEbool(TFHE.and(TFHE.neg(TFHE.asEuint8(has_voted)), TFHE.asEuint8(is_valid_vote)));  // true if is_valid_vote and !has_voted

        // ebool voted_now = TFHE.cmux(is_valid_vote, ebool.wrap(true), ebool.wrap(false));
        euint32 ballot_to_add = TFHE.cmux(is_valid_vote, ballot, euint32.wrap(0));
        euint32 ballot_to_add2 = TFHE.cmux(is_valid_vote, ballot2, euint32.wrap(0));

        tally = TFHE.add(tally, ballot_to_add);
        tally2 = TFHE.add(tally2, ballot_to_add2);

        list_of_voters[msg.sender] = ebool.wrap(1);
        totalVotes++;
    }

   
    function _has_voted(
        address owner
    ) internal view returns (ebool) {
        return list_of_voters[owner];
    }

    function reveal_results(bytes32 publicKey,
        bytes calldata signature)  
    public view 
    onlyContractOwner()  
    onlyAfterEnd()
    onlySignedPublicKey(publicKey, signature)
    returns (bytes memory) {
        return TFHE.reencrypt(tally, publicKey);
    }

    modifier onlyContractOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    modifier onlyAfterEnd(){
        if(block.timestamp <= endTime){
            revert TooEarly(endTime);
        }
        _;
    }

    modifier canVote(){
        if(totalVotes <= maxVotes){
            revert TooLate(endTime);
        }
        _;
    }
}
