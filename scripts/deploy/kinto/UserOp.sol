// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

import "forge-std/Test.sol";
import { UserOperation } from "./UserOperation.sol";

interface IKintoWalletFactory {
    function deployContract(
        address _owner,
        uint256 _salt,
        bytes memory _bytecode,
        bytes32 _initCodeHash
    ) external returns (address _contract);

    function createAccount(
        address owner,
        address recoverer,
        bytes32 salt
    ) external returns (IKintoWallet ret);

    function getContractAddress(bytes32 salt, bytes32 byteCodeHash)
        external
        view
        returns (address);
}

interface IEntryPoint {
    function handleOps(UserOperation[] calldata _ops, address _callback)
        external;
}

interface IKintoWallet {
    function execute(
        address _target,
        uint256 _value,
        bytes calldata _data
    ) external;

    function executeBatch(
        address[] calldata _targets,
        uint256[] calldata _values,
        bytes[] calldata _datas
    ) external;

    function entryPoint() external view returns (address);

    function whitelistApp(address[] calldata _apps, bool[] calldata _flags)
        external;

    function getNonce() external view returns (uint256);

    function owners(uint256) external view returns (address);

    function recoverer() external view returns (address);
}

abstract contract UserOp is Test {
    // gas constants
    uint256 constant CALL_GAS_LIMIT = 4_000_000;
    uint256 constant VERIFICATION_GAS_LIMIT = 210_000;
    uint256 constant PRE_VERIFICATION_GAS = 21_000;
    uint256 constant MAX_FEE_PER_GAS = 1;
    uint256 constant MAX_PRIORITY_FEE_PER_GAS = 1e9;

    struct OperationParamsBatch {
        address[] targets;
        uint256[] values;
        bytes[] bytesOps;
    }

    function whitelistApp(
        address _app,
        address _kintoWallet,
        uint256 _signerPk,
        bool _whitelist
    ) internal {
        address[] memory apps = new address[](1);
        apps[0] = _app;

        bool[] memory flags = new bool[](1);
        flags[0] = _whitelist;

        handleOps(
            abi.encodeWithSelector(
                IKintoWallet.whitelistApp.selector,
                apps,
                flags
            ),
            _kintoWallet,
            _kintoWallet,
            _signerPk
        );
    }

    function handleOps(
        bytes memory _selectorAndParams,
        address _to,
        address _kintoWallet,
        uint256 _signerPk
    ) internal {
        address payable _from = payable(_kintoWallet);
        uint256[] memory privateKeys = new uint256[](1);
        privateKeys[0] = _signerPk;

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = _createUserOperation(
            chainId(),
            _from,
            _to,
            0,
            IKintoWallet(_from).getNonce(),
            privateKeys,
            _selectorAndParams,
            address(0),
            [CALL_GAS_LIMIT, MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS]
        );

        IEntryPoint(IKintoWallet(payable(_from)).entryPoint()).handleOps(
            userOps,
            payable(vm.addr(_signerPk))
        );
    }

    function _createUserOperation(
        uint256 _chainID,
        address _from,
        address _target,
        uint256 _value,
        uint256 _nonce,
        uint256[] memory _privateKeyOwners,
        bytes memory _bytesOp,
        address _paymaster,
        uint256[3] memory _gasLimits
    ) internal view returns (UserOperation memory op) {
        op = UserOperation({
            sender: _from,
            nonce: _nonce,
            initCode: bytes(""),
            callData: abi.encodeWithSignature(
                "execute(address,uint256,bytes)",
                _target,
                _value,
                _bytesOp
            ),
            callGasLimit: _gasLimits[0],
            verificationGasLimit: 210_000,
            preVerificationGas: 21_000,
            maxFeePerGas: _gasLimits[1],
            maxPriorityFeePerGas: _gasLimits[2],
            paymasterAndData: abi.encodePacked(_paymaster),
            signature: bytes("")
        });
        op.signature = _signUserOp(
            op,
            IKintoWallet(payable(_from)).entryPoint(),
            _chainID,
            _privateKeyOwners
        );
        return op;
    }

    function _signUserOp(
        UserOperation memory op,
        address _entryPoint,
        uint256 chainID,
        uint256[] memory privateKeys
    ) internal pure returns (bytes memory) {
        bytes32 hash = _getUserOpHash(op, _entryPoint, chainID);
        hash = _toEthSignedMessageHash(hash);

        bytes memory signature;
        for (uint256 i = 0; i < privateKeys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[i], hash);
            if (i == 0) {
                signature = abi.encodePacked(r, s, v);
            } else {
                signature = abi.encodePacked(signature, r, s, v);
            }
        }

        return signature;
    }

    function _getUserOpHash(
        UserOperation memory op,
        address _entryPoint,
        uint256 chainID
    ) internal pure returns (bytes32) {
        bytes32 opHash = keccak256(_packUserOp(op, true));
        return keccak256(abi.encode(opHash, address(_entryPoint), chainID));
    }

    function _packUserOp(UserOperation memory op, bool forSig)
        internal
        pure
        returns (bytes memory)
    {
        if (forSig) {
            return
                abi.encode(
                    op.sender,
                    op.nonce,
                    keccak256(op.initCode),
                    keccak256(op.callData),
                    op.callGasLimit,
                    op.verificationGasLimit,
                    op.preVerificationGas,
                    op.maxFeePerGas,
                    op.maxPriorityFeePerGas,
                    keccak256(op.paymasterAndData)
                );
        }
        return
            abi.encode(
                op.sender,
                op.nonce,
                op.initCode,
                op.callData,
                op.callGasLimit,
                op.verificationGasLimit,
                op.preVerificationGas,
                op.maxFeePerGas,
                op.maxPriorityFeePerGas,
                op.paymasterAndData,
                op.signature
            );
    }

    function _toEthSignedMessageHash(bytes32 hash)
        internal
        pure
        returns (bytes32 message)
    {
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, hash)
            message := keccak256(0x00, 0x3c)
        }
    }

    function chainId() public pure returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    function isContract(address addr) public view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
}
