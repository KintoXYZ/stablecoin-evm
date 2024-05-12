// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

import "./Create2.sol";

interface Admin {
    function admin() external view returns (address);

    function changeAdmin(address newAdmin) external;
}

/**
 * @title KintoDeployer
 * @dev Convenience contract for deploying contracts on Kinto using `CREATE2`
 * and changing admin.
 */
contract KintoDeployer {
    event ContractDeployed(address indexed addr, address indexed admin);

    /**
     * @dev Deploys a contract using `CREATE2` and changes the admin (if given).
     *
     * The bytecode for a contract can be obtained from Solidity with
     * `type(contractName).creationCode`.
     *
     * @param newAdmin address to be set as thew new admin (if set)
     * @param bytecode of the contract to deploy
     * @param salt to use for the calculation
     */
    function deploy(
        address newAdmin,
        bytes memory bytecode,
        bytes32 salt
    ) external payable returns (address) {
        address addr;
        // deploy the contract using `CREATE2`
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Failed to deploy contract");

        // nominate address if contract is Ownable
        try Admin(addr).admin() returns (address admin_) {
            if (admin_ == address(this) && newAdmin != address(0)) {
                Admin(addr).changeAdmin(newAdmin);
            }
        } catch {}
        emit ContractDeployed(addr, newAdmin);
        return addr;
    }

    function computeAddress(
        address deployer,
        bytes memory bytecode,
        bytes32 salt
    ) external pure returns (address) {
        return Create2.computeAddress(salt, keccak256(bytecode), deployer);
    }
}
