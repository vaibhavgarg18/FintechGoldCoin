// SPDX-License-Identifier: MIT

pragma solidity ^ 0.8.0;

interface IERC20Upgradeable {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    function totalSupply() external view returns(uint256);

    function balanceOf(address account) external view returns(uint256);

    function transfer(address to, uint256 amount) external returns(bool);

    function allowance(
        address owner,
        address spender
    ) external view returns(uint256);

    function approve(address spender, uint256 amount) external returns(bool);

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns(bool);
}

pragma solidity ^ 0.8.0;
interface IERC20PermitUpgradeable {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function nonces(address owner) external view returns(uint256);

    function DOMAIN_SEPARATOR() external view returns(bytes32);
}

pragma solidity ^ 0.8.1;
library AddressUpgradeable {
    function isContract(address account) internal view returns(bool) {
        return account.code.length > 0;
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        require(
            address(this).balance >= amount,
            "Address: insufficient balance"
        );

        (bool success, ) = recipient.call {
            value: amount
        }("");
        require(
            success,
            "Address: unable to send value, recipient may have reverted"
        );
    }

    function functionCall(
        address target,
        bytes memory data
    ) internal returns(bytes memory) {
        return
        functionCallWithValue(
            target,
            data,
            0,
            "Address: low-level call failed"
        );
    }

    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns(bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns(bytes memory) {
        return
        functionCallWithValue(
            target,
            data,
            value,
            "Address: low-level call with value failed"
        );
    }

    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns(bytes memory) {
        require(
            address(this).balance >= value,
            "Address: insufficient balance for call"
        );
        (bool success, bytes memory returndata) = target.call {
            value: value
        }(
            data
        );
        return
        verifyCallResultFromTarget(
            target,
            success,
            returndata,
            errorMessage
        );
    }

    function functionStaticCall(
        address target,
        bytes memory data
    ) internal view returns(bytes memory) {
        return
        functionStaticCall(
            target,
            data,
            "Address: low-level static call failed"
        );
    }

    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns(bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return
        verifyCallResultFromTarget(
            target,
            success,
            returndata,
            errorMessage
        );
    }

    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal view returns(bytes memory) {
        if (success) {
            if (returndata.length == 0) {
                require(isContract(target), "Address: call to non-contract");
            }
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns(bytes memory) {
        if (success) {
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    function _revert(
        bytes memory returndata,
        string memory errorMessage
    ) private pure {
        if (returndata.length > 0) {
            assembly {
                let returndata_size:= mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert(errorMessage);
        }
    }
}
pragma solidity ^ 0.8.0;
library SafeERC20Upgradeable {
    using AddressUpgradeable
    for address;

    function safeTransfer(
        IERC20Upgradeable token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(token.transfer.selector, to, value)
        );
    }

    function safeTransferFrom(
        IERC20Upgradeable token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(token.transferFrom.selector, from, to, value)
        );
    }

    function safeApprove(
        IERC20Upgradeable token,
        address spender,
        uint256 value
    ) internal {
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(token.approve.selector, spender, value)
        );
    }

    function safeIncreaseAllowance(
        IERC20Upgradeable token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(
                token.approve.selector,
                spender,
                newAllowance
            )
        );
    }

    function safeDecreaseAllowance(
        IERC20Upgradeable token,
        address spender,
        uint256 value
    ) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(
                oldAllowance >= value,
                "SafeERC20: decreased allowance below zero"
            );
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(
                token,
                abi.encodeWithSelector(
                    token.approve.selector,
                    spender,
                    newAllowance
                )
            );
        }
    }

    function safePermit(
        IERC20PermitUpgradeable token,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        uint256 nonceBefore = token.nonces(owner);
        token.permit(owner, spender, value, deadline, v, r, s);
        uint256 nonceAfter = token.nonces(owner);
        require(
            nonceAfter == nonceBefore + 1,
            "SafeERC20: permit did not succeed"
        );
    }

    function _callOptionalReturn(
        IERC20Upgradeable token,
        bytes memory data
    ) private {
        bytes memory returndata = address(token).functionCall(
            data,
            "SafeERC20: low-level call failed"
        );
        if (returndata.length > 0) {
            require(
                abi.decode(returndata, (bool)),
                "SafeERC20: ERC20 operation did not succeed"
            );
        }
    }
}
library SafeMath {
    function tryAdd(
        uint256 a,
        uint256 b
    ) internal pure returns(bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    function trySub(
        uint256 a,
        uint256 b
    ) internal pure returns(bool, uint256) {
        unchecked {
            if (b > a) return (false, 0);
            return (true, a - b);
        }
    }

    function tryMul(
        uint256 a,
        uint256 b
    ) internal pure returns(bool, uint256) {
        unchecked {
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }

    function tryDiv(
        uint256 a,
        uint256 b
    ) internal pure returns(bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a / b);
        }
    }

    function tryMod(
        uint256 a,
        uint256 b
    ) internal pure returns(bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a % b);
        }
    }

    function add(uint256 a, uint256 b) internal pure returns(uint256) {
        return a + b;
    }

    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
        return a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
        return a * b;
    }

    function div(uint256 a, uint256 b) internal pure returns(uint256) {
        return a / b;
    }

    function mod(uint256 a, uint256 b) internal pure returns(uint256) {
        return a % b;
    }

    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns(uint256) {
        unchecked {
            require(b <= a, errorMessage);
            return a - b;
        }
    }

    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns(uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a / b;
        }
    }

    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns(uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a % b;
        }
    }
}
pragma solidity ^ 0.8.7;

contract BasicMetaTransaction {
    event MetaTransactionExecuted(
        address userAddress,
        address payable relayerAddress,
        bytes functionSignature
    );
    mapping(address => uint256) private nonces;

    function getChainID() public view returns(uint256) {
        uint256 id;
        assembly {
            id:= chainid()
        }
        return id;
    }

    function executeMetaTransaction(
        address userAddress,
        bytes memory functionSignature,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) public returns(bytes memory) {
        require(
            verify(
                userAddress,
                nonces[userAddress],
                getChainID(),
                functionSignature,
                sigR,
                sigS,
                sigV
            ),
            "Signer and signature do not match"
        );
        // nonces[userAddress] = nonces[userAddress]++;
        nonces[userAddress] += 1;
        (bool success, bytes memory returnData) = address(this).call(
            abi.encodePacked(functionSignature, userAddress)
        );

        require(success, "Function call not successful");
        emit MetaTransactionExecuted(
            userAddress,
            payable(msg.sender),
            functionSignature
        );
        return returnData;
    }

    function getNonce(address user) external view returns(uint256 nonce) {
        nonce = nonces[user];
    }

    function prefixed(bytes32 hash) internal pure returns(bytes32) {
        return
        keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
    }

    function verify(
        address owner,
        uint256 nonce,
        uint256 chainID,
        bytes memory functionSignature,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) public view returns(bool) {
        require(
            uint256(sigS) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "Invalid signature 's' value"
        );
        require(sigV == 27 || sigV == 28, "Invalid signature 'v' value");
        bytes32 hash = prefixed(
            keccak256(abi.encodePacked(nonce, this, chainID, functionSignature))
        );
        address signer = ecrecover(hash, sigV, sigR, sigS);
        require(signer != address(0), "Invalid signature");
        return (owner == signer);
    }

    function _msgSender() internal view virtual returns(address sender) {
        if (msg.sender == address(this)) {
            bytes memory array = msg.data;
            uint256 index = msg.data.length;
            assembly {
                sender:= and(
                    mload(add(array, index)),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
            }
        } else {
            return msg.sender;
        }
    }

    uint256[50] private __gap;
}

pragma solidity ^ 0.8.2;
abstract contract Initializable {
    uint8 private _initialized;
    bool private _initializing;
    event Initialized(uint8 version);
    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1) ||
            (!AddressUpgradeable.isContract(address(this)) &&
                _initialized == 1),
            "Initializable: contract is already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) {
            _initializing = true;
        }
        _;
        if (isTopLevelCall) {
            _initializing = false;
            emit Initialized(1);
        }
    }
    modifier reinitializer(uint8 version) {
        require(!_initializing && _initialized < version,
            "Initializable: contract is already initialized"
        );
        _initialized = version;
        _initializing = true;
        _;
        _initializing = false;
        emit Initialized(version);
    }
    modifier onlyInitializing() {
        require(_initializing, "Initializable: contract is not initializing");
        _;
    }

    function _disableInitializers() internal virtual {
        require(!_initializing, "Initializable: contract is initializing");
        if (_initialized < type(uint8).max) {
            _initialized = type(uint8).max;
            emit Initialized(type(uint8).max);
        }
    }

    function _getInitializedVersion() internal view returns(uint8) {
        return _initialized;
    }

    function _isInitializing() internal view returns(bool) {
        return _initializing;
    }
}
pragma solidity ^ 0.8.11;
contract FintechDigitalGoldCoin is BasicMetaTransaction, Initializable {
    using SafeMath
    for uint256;

    bool private initialized = false;

    mapping(address => uint256) internal balances;
    uint256 internal totalSupply_;
    string public constant name = "FINTECH DIGITAL GOLD COIN"; // solium-disable-line
    string public constant symbol = "FDGC"; // solium-disable-line uppercase
    uint8 public constant decimals = 6; // solium-disable-line uppercase

    // ERC20 DATA
    mapping(address => mapping(address => uint256)) internal allowed;

    // OWNER DATA
    address public owner;
    address public proposedOwner;

    // PAUSABILITY DATA
    bool public paused = false;

    // ASSET PROTECTION DATA
    address public assetProtectionRole;
    mapping(address => bool) internal frozen;


    // DELEGATED TRANSFER DATA
    address public betaDelegateWhitelister;
    mapping(address => bool) internal betaDelegateWhitelist;
    mapping(address => uint256) internal nextSeqs;
    // EIP191 header for EIP712 prefix
    string internal constant EIP191_HEADER = "\x19\x01";
    // Hash of the EIP712 Domain Separator Schema
    bytes32 internal constant EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH =
        keccak256("EIP712Domain(string name,address verifyingContract)");
    bytes32 internal constant EIP712_DELEGATED_TRANSFER_SCHEMA_HASH =
        keccak256(
            "BetaDelegatedTransfer(address from,address to,uint256 value,uint256 serviceFee,uint256 seq,uint256 deadline)"
        );
    bytes32 public EIP712_DOMAIN_HASH;


    uint256 public constant feeParts = 1000000;
    uint256 public feeRate;
    address public feeController;
    address public feeRecipient;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
    event OwnershipTransferProposed(
        address indexed currentOwner,
        address indexed proposedOwner
    );
    event OwnershipTransferDisregarded(address indexed oldProposedOwner);
    event OwnershipTransferred(
        address indexed oldOwner,
        address indexed newOwner
    );
    event Pause();
    event Unpause();
    event AddressFrozen(address indexed addr);
    event AddressUnfrozen(address indexed addr);
    event FrozenAddressWiped(address indexed addr);
    event AssetProtectionRoleSet(
        address indexed oldAssetProtectionRole,
        address indexed newAssetProtectionRole
    );
    event BetaDelegatedTransfer(
        address indexed from,
        address indexed to,
        uint256 value,
        uint256 seq,
        uint256 serviceFee
    );
    event BetaDelegateWhitelisterSet(
        address indexed oldWhitelister,
        address indexed newWhitelister
    );
    event BetaDelegateWhitelisted(address indexed newDelegate);
    event BetaDelegateUnwhitelisted(address indexed oldDelegate);
    event FeeCollected(address indexed from, address indexed to, uint256 value);
    event FeeRateSet(uint256 indexed oldFeeRate, uint256 indexed newFeeRate);
    event FeeControllerSet(
        address indexed oldFeeController,
        address indexed newFeeController
    );
    event FeeRecipientSet(
        address indexed oldFeeRecipient,
        address indexed newFeeRecipient
    );

    function initialize(address _owner) public {
        require(!initialized, "already initialized");
        owner = _owner;
        proposedOwner = address(0);
        assetProtectionRole = address(0);
        feeRate = 0;
        feeController = _owner;
        feeRecipient = _owner;

        // Set a fixed total supply of 315,000 tokens
        uint256 initialSupply = 315000 * (10 ** uint256(decimals));
        totalSupply_ = initialSupply;
        
        // Assign all tokens to the owner's balance
        balances[_owner] = initialSupply;
        // Emit the standard ERC20 event for token creation
        emit Transfer(address(0), _owner, initialSupply);

        initializeDomainSeparator();
        initialized = true;
    }

    constructor() {
        _disableInitializers();
    }

    function initializeDomainSeparator() internal {
        EIP712_DOMAIN_HASH = keccak256(
            abi.encodePacked(
                EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH,
                keccak256(bytes(name)),
                bytes32(keccak256(abi.encodePacked(address(this))))
            )
        );
    }

    function totalSupply() public view returns(uint256) {
        return totalSupply_;
    }

    function transfer(
        address _to,
        uint256 _value
    ) public whenNotPaused returns(bool) {
        require(_to != address(0), "cannot transfer to address zero");
        require(!frozen[_to] && !frozen[_msgSender()], "address frozen");
        require(_value <= balances[_msgSender()], "insufficient funds");

        _transfer(_msgSender(), _to, _value);
        return true;
    }

    function balanceOf(address _addr) public view returns(uint256) {
        return balances[_addr];
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    ) public whenNotPaused returns(bool) {
        require(_to != address(0), "cannot transfer to address zero");
        require(!frozen[_to] && !frozen[_from] && !frozen[_msgSender()],
            "address frozen"
        );
        require(_value <= balances[_from], "insufficient funds");
        require(
            _value <= allowed[_from][_msgSender()],
            "insufficient allowance"
        );

        allowed[_from][_msgSender()] = allowed[_from][_msgSender()].sub(_value);
        _transfer(_from, _to, _value);

        return true;
    }

    function approve(
        address _spender,
        uint256 _value
    ) public whenNotPaused returns(bool) {
        require(!frozen[_spender] && !frozen[_msgSender()], "address frozen");
        allowed[_msgSender()][_spender] = _value;
        emit Approval(_msgSender(), _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    ) public view returns(uint256) {
        return allowed[_owner][_spender];
    }

    function _transfer(
        address _from,
        address _to,
        uint256 _value
    ) internal returns(uint256) {
        uint256 _fee = getFeeFor(_value);
        uint256 _principle = _value.sub(_fee);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_principle);
        emit Transfer(_from, _to, _principle);
        emit Transfer(_from, feeRecipient, _fee);
        if (_fee > 0) {
            balances[feeRecipient] = balances[feeRecipient].add(_fee);
            emit FeeCollected(_from, feeRecipient, _fee);
        }

        return _principle;
    }

    modifier onlyOwner() {
        require(_msgSender() == owner, "onlyOwner");
        _;
    }

    function proposeOwner(address _proposedOwner) public onlyOwner {
        require(
            _proposedOwner != address(0),
            "cannot transfer ownership to address zero"
        );
        require(_msgSender() != _proposedOwner, "caller already is owner");
        proposedOwner = _proposedOwner;
        emit OwnershipTransferProposed(owner, proposedOwner);
    }

    function disregardProposeOwner() public {
        require(
            _msgSender() == proposedOwner || _msgSender() == owner,
            "only proposedOwner or owner"
        );
        require(
            proposedOwner != address(0),
            "can only disregard a proposed owner that was previously set"
        );
        address _oldProposedOwner = proposedOwner;
        proposedOwner = address(0);
        emit OwnershipTransferDisregarded(_oldProposedOwner);
    }

    function claimOwnership() public {
        require(_msgSender() == proposedOwner, "onlyProposedOwner");
        address _oldOwner = owner;
        owner = proposedOwner;
        proposedOwner = address(0);
        emit OwnershipTransferred(_oldOwner, owner);
    }

    function reclaimCoin() external onlyOwner {
        uint256 _balance = balances[address(this)];
        balances[address(this)] = 0;
        balances[owner] = balances[owner].add(_balance);
        emit Transfer(address(this), owner, _balance);
    }

    modifier whenNotPaused() {
        require(!paused, "whenNotPaused");
        _;
    }

    function pause() public onlyOwner {
        require(!paused, "already paused");
        paused = true;
        emit Pause();
    }

    function unpause() public onlyOwner {
        require(paused, "already unpaused");
        paused = false;
        emit Unpause();
    }

    function setAssetProtectionRole(address _newAssetProtectionRole) public {
        require(
            _msgSender() == assetProtectionRole || _msgSender() == owner,
            "only assetProtectionRole or Owner"
        );
        emit AssetProtectionRoleSet(
            assetProtectionRole,
            _newAssetProtectionRole
        );
        assetProtectionRole = _newAssetProtectionRole;
    }

    modifier onlyAssetProtectionRole() {
        require(_msgSender() == assetProtectionRole, "onlyAssetProtectionRole");
        _;
    }

    function freeze(address _addr) public onlyAssetProtectionRole {
        require(!frozen[_addr], "address already frozen");
        frozen[_addr] = true;
        emit AddressFrozen(_addr);
    }

    function unfreeze(address _addr) public onlyAssetProtectionRole {
        require(frozen[_addr], "address already unfrozen");
        frozen[_addr] = false;
        emit AddressUnfrozen(_addr);
    }

    function wipeFrozenAddress(address _addr) public onlyAssetProtectionRole {
        require(frozen[_addr], "address is not frozen");
        uint256 _balance = balances[_addr];
        balances[_addr] = 0;
        totalSupply_ = totalSupply_.sub(_balance);
        emit FrozenAddressWiped(_addr);
        emit Transfer(_addr, address(0), _balance);
    }

    function isFrozen(address _addr) public view returns(bool) {
        return frozen[_addr];
    }

    function nextSeqOf(address target) public view returns(uint256) {
        return nextSeqs[target];
    }

    function betaDelegatedTransfer(
        bytes memory sig,
        address from,
        address to,
        uint256 value,
        uint256 serviceFee,
        uint256 seq,
        uint256 deadline
    ) public returns(bool) {
        require(sig.length == 65, "signature should have length 65");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r:= mload(add(sig, 32))
            s:= mload(add(sig, 64))
            v:= byte(0, mload(add(sig, 96)))
        }
        require(
            _betaDelegatedTransfer(
                r,
                s,
                v,
                from,
                to,
                value,
                serviceFee,
                seq,
                deadline
            ),
            "failed transfer"
        );
        return true;
    }

    function _betaDelegatedTransfer(
        bytes32 r,
        bytes32 s,
        uint8 v,
        address from,
        address to,
        uint256 value,
        uint256 serviceFee,
        uint256 seq,
        uint256 deadline
    ) internal whenNotPaused returns(bool) {
        require(
            betaDelegateWhitelist[_msgSender()],
            "Beta feature only accepts whitelisted delegates"
        );
        require(
            value > 0 || serviceFee > 0,
            "cannot transfer zero tokens with zero service fee"
        );
        require(block.number <= deadline, "transaction expired");
        // prevent sig malleability from ecrecover()
        require(
            uint256(s) <=
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "signature incorrect"
        );
        require(v == 27 || v == 28, "signature incorrect");
        // Compute the EIP-712 typed data hash
        bytes32 hash = keccak256(
            abi.encodePacked(
                EIP191_HEADER,
                EIP712_DOMAIN_HASH,
                keccak256(
                    abi.encodePacked(
                        EIP712_DELEGATED_TRANSFER_SCHEMA_HASH,
                        bytes32(keccak256(abi.encodePacked(from))),
                        bytes32(keccak256(abi.encodePacked(to))),
                        value,
                        serviceFee,
                        seq,
                        deadline
                    )
                )
            )
        );

        address recovered = ecrecover(hash, v, r, s);
        require(recovered != address(0), "error determining from address from signature");
        require(recovered == from, "signature does not match from address");
        require(to != address(0), "cannot use address zero");
        require(!frozen[to] && !frozen[from] && !frozen[_msgSender()], "address frozen");
        require(value.add(serviceFee) <= balances[from], "insufficient funds or bad signature");
        require(nextSeqs[from] == seq, "incorrect seq");

        nextSeqs[from] = nextSeqs[from].add(1);

        uint256 _principle = _transfer(from, to, value);

        if (serviceFee != 0) {
            balances[from] = balances[from].sub(serviceFee);
            balances[_msgSender()] = balances[_msgSender()].add(serviceFee);
            emit Transfer(from, _msgSender(), serviceFee);
        }

        emit BetaDelegatedTransfer(from, to, _principle, seq, serviceFee);
        return true;
    }

    function betaDelegatedTransferBatch(
        address[] memory from,
        bytes32[] memory r,
        bytes32[] memory s,
        uint8[] memory v,
        address[] memory to,
        uint256[] memory value,
        uint256[] memory serviceFee,
        uint256[] memory seq,
        uint256[] memory deadline
    ) public returns(bool) {
        require(
            r.length == s.length &&
            r.length == v.length &&
            r.length == to.length &&
            r.length == value.length &&
            r.length == serviceFee.length &&
            r.length == seq.length &&
            r.length == deadline.length &&
            r.length == from.length,
            "length mismatch"
        );

        for (uint i = 0; i < r.length; i++) {
            require(
                _betaDelegatedTransfer(
                    r[i],
                    s[i],
                    v[i],
                    from[i],
                    to[i],
                    value[i],
                    serviceFee[i],
                    seq[i],
                    deadline[i]
                ),
                "failed transfer"
            );
        }
        return true;
    }


    function isWhitelistedBetaDelegate(
        address _addr
    ) public view returns(bool) {
        return betaDelegateWhitelist[_addr];
    }

    function setBetaDelegateWhitelister(address _newWhitelister) public {
        require(
            _msgSender() == betaDelegateWhitelister || _msgSender() == owner,
            "only Whitelister or Owner"
        );
        betaDelegateWhitelister = _newWhitelister;
        emit BetaDelegateWhitelisterSet(
            betaDelegateWhitelister,
            _newWhitelister
        );
    }

    modifier onlyBetaDelegateWhitelister() {
        require(
            _msgSender() == betaDelegateWhitelister,
            "onlyBetaDelegateWhitelister"
        );
        _;
    }

    function whitelistBetaDelegate(
        address _addr
    ) public onlyBetaDelegateWhitelister {
        require(!betaDelegateWhitelist[_addr], "delegate already whitelisted");
        betaDelegateWhitelist[_addr] = true;
        emit BetaDelegateWhitelisted(_addr);
    }

    function unwhitelistBetaDelegate(
        address _addr
    ) public onlyBetaDelegateWhitelister {
        require(betaDelegateWhitelist[_addr], "delegate not whitelisted");
        betaDelegateWhitelist[_addr] = false;
        emit BetaDelegateUnwhitelisted(_addr);
    }

    function setFeeController(address _newFeeController) public {
        require(
            _msgSender() == feeController || _msgSender() == owner,
            "only FeeController or Owner"
        );
        require(
            _newFeeController != address(0),
            "cannot set fee controller to address zero"
        );
        address _oldFeeController = feeController;
        feeController = _newFeeController;
        emit FeeControllerSet(_oldFeeController, feeController);
    }

    modifier onlyFeeController() {
        require(_msgSender() == feeController, "only FeeController");
        _;
    }

    function setFeeRecipient(
        address _newFeeRecipient
    ) public onlyFeeController {
        require(
            _newFeeRecipient != address(0),
            "cannot set fee recipient to address zero"
        );
        address _oldFeeRecipient = feeRecipient;
        feeRecipient = _newFeeRecipient;
        emit FeeRecipientSet(_oldFeeRecipient, feeRecipient);
    }

    function setFeeRate(uint256 _newFeeRate) public onlyFeeController {
        require(_newFeeRate <= 50000, "Fee rate cannot exceed 5%");
        require(_newFeeRate <= feeParts, "cannot set fee rate above 100%");
        uint256 _oldFeeRate = feeRate;
        feeRate = _newFeeRate;
        emit FeeRateSet(_oldFeeRate, feeRate);
    }

    function getFeeFor(uint256 _value) public view returns(uint256) {
        if (feeRate == 0) {
            return 0;
        }

        return _value.mul(feeRate).div(feeParts);
    }

    function _msgSender()
    internal
    view
    virtual
    override
    returns(address sender) {
        if (msg.sender == address(this)) {
            bytes memory array = msg.data;
            uint256 index = msg.data.length;
            assembly {
                sender:= and(
                    mload(add(array, index)),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
            }
        } else {
            return msg.sender;
        }
    }
}
