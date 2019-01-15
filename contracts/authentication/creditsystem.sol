pragma solidity >=0.4.0 <0.6.0;

import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/access/roles/SignerRole.sol";

contract CreditSystem is SignerRole{

    event NewUserRegister(address indexed addr, bytes32 indexed hash);
    event NewIdentity(address indexed addr, bytes32 indexed hash);
    event NewSubRegister(address indexed subAddr, bytes indexed sig, bytes indexed mainAddr);

    mapping (address => UseID) IDs;
    mapping (bytes32 => UseData) DataSet;
    mapping (address => SubRegList) SubRegs;
    mapping (address => bytes[]) accountMapping;
    bytes32[] public unregister;
    address[] public subUnverify;

    struct Hash {
        bytes32 hash;
        bool verify;
    }

    struct UseID {
        //address addr;             // msg.sender
        address useId;              // msg.sender
        string publicKey;           // user's publicKey
        Hash baseHash;              // keccak(idtype + idnum) and verified flag
        HashList hl;                // other certificate's hash and verifiy flag list implements by struct
    }

    struct UseData {
        bytes identity;             // certificate's data
        bytes issuer;               // certificate's issuer
        bool verify;                // same flag with HashList verifies
        uint index;
    }

    struct HashList {
        bytes32[] hashes;           // keccak(idtype + idnum)
        bool[] verifies;            // certificate's status
    }
    
    struct SubRegList {
        string publicKey;           //subAccount's publicKey
        bytes encryptMsg;           //encrypted message with committe's Key
        bytes mainAccount;          //encrypted mainAccount with committe's Key
        bytes subAccount;           //encrypted subAccount with committe's Key
        uint index;
        uint verify;                //1:unverify; 2:verified; 3:verify failed
    }


    function register(string _publicKey,
                    //address _useId,
                    bytes32 _hashKey,
                    bytes _identity,
                    bytes _issuer)
        public
        payable
        returns(bool){
        address addr = msg.sender;
        require(IDs[addr].useId == 0); // unregistered user
        uint index = unregister.push(_hashKey) - 1;
        UseData memory ud = UseData(_identity, _issuer, false, index);
        DataSet[_hashKey] = ud;
        UseID memory user = UseID(addr, _publicKey, Hash(_hashKey, false), HashList(new bytes32[](0), new bool[](0)));
        IDs[addr] = user;
        IDs[addr].hl.hashes.push(_hashKey);
        IDs[addr].hl.verifies.push(false);
        emit NewUserRegister(addr, _hashKey);
        return true;
    }

    function getUserInfo(address addr)
        public
        view
        returns(address, string, bytes32, bytes32[], bool[]){
        return (IDs[addr].useId,
        IDs[addr].publicKey,
        IDs[addr].baseHash.hash,
        IDs[addr].hl.hashes,
        IDs[addr].hl.verifies);
    }

    function addNewIdentity(bytes32 hashKey, bytes _identity, bytes _issuer)
        public
        payable
        returns(bool){
        require(IDs[msg.sender].useId != 0); // registered user
        uint index = unregister.push(hashKey) - 1;
        UseData memory ud = UseData(_identity, _issuer, false, index);
        DataSet[hashKey] = ud;
        IDs[msg.sender].hl.hashes.push(hashKey);
        IDs[msg.sender].hl.verifies.push(false);
        emit NewIdentity(msg.sender, hashKey);
        return true;
    }

    function getBaseData(address addr)
        public
        view
        returns(bytes32, bool){
            Hash memory h = IDs[addr].baseHash;
            return (h.hash, h.verify);
        }

    function getHashData(bytes32 hash)
        public
        view
        returns(bytes, bytes, bool){
            UseData memory ud = DataSet[hash];
            return (ud.identity, ud.issuer, ud.verify);
    }

    function getUnregisterHash()
        public
        view
        returns(bytes32[]){
        return unregister;
    }

    function verifyBase(address addr)
        public
        onlySigner
        returns(bool){
        require(IDs[addr].useId != 0);
        IDs[addr].baseHash.verify = true;
        bytes32 h = bytes32(IDs[addr].baseHash.hash);
        DataSet[h].verify = true;
        for(uint i=0; i<IDs[addr].hl.hashes.length; i++){
            if(h == IDs[addr].hl.hashes[i]) {
                IDs[addr].hl.verifies[i] = true;
                return true;
            }
        }
        return false;
    }

    function verifyHash(address addr, bytes32 hash)
        public
        onlySigner
        returns(bool){
            require(IDs[addr].useId != 0);
            DataSet[hash].verify = true;
            for(uint i=0; i<IDs[addr].hl.hashes.length; i++){
                if(hash == IDs[addr].hl.hashes[i]){
                    IDs[addr].hl.verifies[i] = true;
                    unregister[DataSet[hash].index] = unregister[unregister.length - 1];        // move the last element to the index
                    DataSet[unregister[unregister.length - 1]].index = DataSet[hash].index;     // update former last emement's index
                    unregister.length--;
                    return true;
                }
            }
        return false;
    }
    
    function subRegister(string publicKey, 
                        bytes sig, 
                        bytes main,
                        bytes sub)
        public
        payable
        returns(bool){
            require(SubRegs[msg.sender].verify < 1 || SubRegs[msg.sender].verify > 2);
            address subAddr = msg.sender;
            
            uint index = subUnverify.push(subAddr) - 1;
            SubRegList memory srList = SubRegList(publicKey, sig, main, sub, index, 1);
            
            SubRegs[subAddr] = srList;
            
            emit NewSubRegister(subAddr, sig, main);
            return true;
    }
    //if flag is true,it means verify success; if flag is false,it means verify failed.
    function verifySubregs(address sub, address main, bool flag)
        public
        onlySigner
        returns(bool) {
            require(SubRegs[sub].verify == 1);
            uint index = SubRegs[sub].index;
            if(flag == true) {
                SubRegs[sub].verify = 2;//verify success
                accountMapping[sub].push(SubRegs[sub].mainAccount);
                accountMapping[main].push(SubRegs[sub].subAccount);
            } else {
                SubRegs[sub].verify = 3;//verify failed
            }
            
            subUnverify[index] = subUnverify[subUnverify.length - 1];
            SubRegs[subUnverify[index]].index = index;
            subUnverify.length--;
            return true;
    }
    function getSubUnverify() 
        public
        onlySigner
        view
        returns(address[]) {
            return subUnverify;
    }
    function getRelations(address addr) 
        public
        view
        returns(bytes, uint, uint){
            require(accountMapping[addr].length > 0);
            bytes memory concat = strAllConcat(accountMapping[addr]);
            return (concat, accountMapping[addr].length, concat.length);
    }
    function strAllConcat(bytes[] bs)
        internal
        pure
        returns(bytes) {
            uint len;
            for (uint i = 0; i < bs.length; i++) {
                len = len + bs[i].length;
            }
            bytes memory bret = new bytes(len);
            uint index1;
            uint index2;
            for (uint j = 0; j < bs.length;) {
                bytes memory tmp = bs[j];
                if (index1 < tmp.length) {
                    bret[index2++] =  tmp[index1];
                    index1++;
                } else {
                    index1 = 0;
                    j++;
                }
            }
            return bret;
    }
}
