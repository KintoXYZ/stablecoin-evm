/**
 * Copyright 2024 Circle Internet Financial, LTD. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

import "forge-std/console.sol"; // solhint-disable no-global-import, no-console
import { Script } from "forge-std/Script.sol";
import { DeployImpl } from "./DeployImpl.sol";
import { FiatTokenProxy } from "../../contracts/v1/FiatTokenProxy.sol";
import { FiatTokenV2_2 } from "../../contracts/v2/FiatTokenV2_2.sol";
import { FiatTokenV2_1 } from "../../contracts/v2/FiatTokenV2_1.sol";
import { FiatTokenV2 } from "../../contracts/v2/FiatTokenV2.sol";
import { FiatTokenV1_1 } from "../../contracts/v1.1/FiatTokenV1_1.sol";
import { FiatTokenV1 } from "../../contracts/v1/FiatTokenV1.sol";
import {
    AdminUpgradeabilityProxy
} from "../../contracts/upgradeability/AdminUpgradeabilityProxy.sol";

import { MasterMinter } from "../../contracts/minting/MasterMinter.sol";
import { Ownable } from "../../contracts/v1/Ownable.sol";

import { KintoDeployer } from "./kinto/KintoDeployer.sol";
import { UserOperation } from "./kinto/UserOperation.sol";
import {
    UserOp,
    IKintoWalletFactory,
    IEntryPoint,
    IKintoWallet
} from "./kinto/UserOp.sol";

/**
 * A utility script to directly deploy Fiat Token contract with the latest implementation
 *
 * @dev The proxy needs to be deployed before the master minter; the proxy cannot
 * be initialized until the master minter is deployed.
 */
contract DeployFiatToken is Script, DeployImpl, UserOp {
    address private immutable THROWAWAY_ADDRESS = address(1);

    address private impl;
    address private masterMinterOwner;
    address private proxyAdmin;
    address private owner;
    address private pauser;
    address private blacklister;

    string private tokenName;
    string private tokenSymbol;
    string private tokenCurrency;
    uint8 private tokenDecimals;

    uint256 private deployerPrivateKey;
    address private kintoWallet;
    address private deployer;
    IEntryPoint private entryPoint;
    IKintoWalletFactory private factory;

    FiatTokenV2_2 fiatTokenV2_2;
    FiatTokenProxy proxy;
    MasterMinter masterMinter;

    /**
     * @notice initialize variables from environment
     */
    function setUp() public {
        // Kinto variables
        deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        kintoWallet = vm.envAddress("KINTO_WALLET");
        entryPoint = IEntryPoint(vm.envAddress("ENTRYPOINT"));
        factory = IKintoWalletFactory(vm.envAddress("KINTO_WALLET_FACTORY"));

        tokenName = vm.envString("TOKEN_NAME");
        tokenSymbol = vm.envString("TOKEN_SYMBOL");
        tokenCurrency = vm.envString("TOKEN_CURRENCY");
        tokenDecimals = uint8(vm.envUint("TOKEN_DECIMALS"));

        impl = vm.envOr("FIAT_TOKEN_IMPLEMENTATION_ADDRESS", address(0));
        masterMinterOwner = vm.envAddress("MASTER_MINTER_OWNER_ADDRESS");
        proxyAdmin = vm.envAddress("PROXY_ADMIN_ADDRESS");
        owner = vm.envAddress("OWNER_ADDRESS");

        // Ensure that the proxy admin and owner addresses are different
        // because we are using AdmingUpgradeabilityProxy and the address used as admin there
        // won't be able to make calls to the implementation contract.
        if (proxyAdmin == owner) {
            revert("PROXY_ADMIN and OWNER_ADDRESS cannot be the same");
        }

        // Ensure that the proxy admin and owner addresses are KintoWallets
        try IKintoWallet(proxyAdmin).getNonce() returns (uint256) {
            console.log("PROXY_ADMIN_ADDRESS is a KintoWallet");
        } catch {
            revert("PROXY_ADMIN_ADDRESS is not a KintoWallet");
        }

        try IKintoWallet(owner).getNonce() returns (uint256) {
            console.log("OWNER_ADDRESS is a KintoWallet");
        } catch {
            revert("OWNER_ADDRESS is not a KintoWallet");
        }

        // Pauser and blacklister addresses can default to owner address
        pauser = vm.envOr("PAUSER_ADDRESS", owner);
        blacklister = vm.envOr("BLACKLISTER_ADDRESS", owner);

        console.log("TOKEN_NAME: '%s'", tokenName);
        console.log("TOKEN_SYMBOL: '%s'", tokenSymbol);
        console.log("TOKEN_CURRENCY: '%s'", tokenCurrency);
        console.log("TOKEN_DECIMALS: '%s'", tokenDecimals);
        console.log("FIAT_TOKEN_IMPLEMENTATION_ADDRESS: '%s'", impl);
        console.log("PROXY_ADMIN_ADDRESS: '%s'", proxyAdmin);
        console.log("MASTER_MINTER_OWNER_ADDRESS: '%s'", masterMinterOwner);
        console.log("OWNER_ADDRESS: '%s'", owner);
        console.log("PAUSER_ADDRESS: '%s'", pauser);
        console.log("BLACKLISTER_ADDRESS: '%s'", blacklister);
    }

    /**
     * @dev For testing only: splitting deploy logic into an internal function to expose for testing
     */
    function _deploy(address _impl)
        internal
        returns (
            FiatTokenV2_2,
            MasterMinter,
            FiatTokenProxy
        )
    {
        bytes memory selectorAndParams;

        vm.startBroadcast(deployerPrivateKey);

        deployDeployer();

        // If there is an existing implementation contract,
        // we can simply point the newly deployed proxy contract to it.
        // Otherwise, deploy the latest implementation contract code to the network.
        // FiatTokenV2_2 fiatTokenV2_2 = getOrDeployImpl(_impl);
        deployImplementation(_impl);
        deployProxy();

        // Now that the proxy contract has been deployed, we can deploy the master minter.
        deployMasterMinter();

        // Now that the master minter is set up, we can go back to setting up the proxy and
        // implementation contracts.
        // Need to change admin first, or the call to initialize won't work
        // since admin can only call methods in the proxy, and not forwarded methods
        if (proxy.admin() != proxyAdmin) {
            console.log(
                "Proxy admin is %s, changing to %s",
                proxy.admin(),
                proxyAdmin
            );
            selectorAndParams = abi.encodeWithSelector(
                AdminUpgradeabilityProxy.changeAdmin.selector,
                proxyAdmin
            );
            handleOps(
                selectorAndParams,
                address(proxy),
                kintoWallet,
                deployerPrivateKey
            );
        } else {
            console.log("Proxy admin already set to %s", proxyAdmin);
        }

        // Do the initial (V1) initialization.
        // Note that this takes in the master minter contract's address as the master minter.
        // The master minter contract's owner is a separate address.
        FiatTokenV2_2 proxyAsV2_2 = FiatTokenV2_2(address(proxy));
        selectorAndParams = abi.encodeWithSelector(
            FiatTokenV1.initialize.selector,
            tokenName,
            tokenSymbol,
            tokenCurrency,
            tokenDecimals,
            address(masterMinter),
            pauser,
            blacklister,
            owner
        );
        handleOps(
            selectorAndParams,
            address(proxyAsV2_2),
            kintoWallet,
            deployerPrivateKey
        );

        // Do the V2 initialization
        selectorAndParams = abi.encodeWithSelector(
            FiatTokenV2.initializeV2.selector,
            tokenName
        );
        handleOps(
            selectorAndParams,
            address(proxyAsV2_2),
            kintoWallet,
            deployerPrivateKey
        );

        // Do the V2_1 initialization
        selectorAndParams = abi.encodeWithSelector(
            FiatTokenV2_1.initializeV2_1.selector,
            owner
        );
        handleOps(
            selectorAndParams,
            address(proxyAsV2_2),
            kintoWallet,
            deployerPrivateKey
        );

        // Do the V2_2 initialization
        selectorAndParams = abi.encodeWithSelector(
            FiatTokenV2_2.initializeV2_2.selector,
            new address[](0),
            tokenSymbol
        );
        handleOps(
            selectorAndParams,
            address(proxyAsV2_2),
            kintoWallet,
            deployerPrivateKey
        );

        vm.stopBroadcast();

        require(
            keccak256(abi.encodePacked(FiatTokenV2_2(address(proxy)).name())) ==
                keccak256(abi.encodePacked("Bridged USDC (Kinto)")),
            "name must be Bridged USDC (Kinto)"
        );
        require(
            keccak256(
                abi.encodePacked(FiatTokenV2_2(address(proxy)).symbol())
            ) == keccak256(abi.encodePacked("USDC.e")),
            "name must be USDC.e"
        );
        require(
            keccak256(
                abi.encodePacked(FiatTokenV2_2(address(proxy)).currency())
            ) == keccak256(abi.encodePacked("USD")),
            "currency must be USD"
        );
        require(
            FiatTokenV2_2(address(proxy)).decimals() == 6,
            "decimals must be 6"
        );
        require(
            FiatTokenV2_2(address(proxy)).pauser() == pauser,
            "pauser mismatch"
        );
        require(
            FiatTokenV2_2(address(proxy)).blacklister() == blacklister,
            "blacklister mismatch"
        );
        require(
            FiatTokenV2_2(address(proxy)).owner() == owner,
            "owner mismatch"
        );
        require(
            FiatTokenV2_2(address(proxy)).masterMinter() ==
                address(masterMinter),
            "masterMinter mismatch"
        );

        return (fiatTokenV2_2, masterMinter, proxy);
    }

    /**
     * @dev For testing only: Helper function that runs deploy script with a specific implementation address
     */
    function deploy(address _impl)
        external
        returns (
            FiatTokenV2_2,
            MasterMinter,
            FiatTokenProxy
        )
    {
        return _deploy(_impl);
    }

    /**
     * @notice main function that will be run by forge
     */
    function run()
        external
        returns (
            FiatTokenV2_2,
            MasterMinter,
            FiatTokenProxy
        )
    {
        return _deploy(impl);
    }

    function deployDeployer() internal {
        // deploy KintoDeployer
        bytes memory bytecode = type(KintoDeployer).creationCode;
        deployer = factory.deployContract(kintoWallet, 0, bytecode, bytes32(0));
        whitelistApp(deployer, kintoWallet, deployerPrivateKey, true);
    }

    function deployImplementation(address _impl) internal {
        if (_impl == address(0)) {
            // Deploy the implementation contract
            bytes memory bytecode = abi.encodePacked(
                type(FiatTokenV2_2).creationCode
            );
            fiatTokenV2_2 = FiatTokenV2_2(
                factory.deployContract(kintoWallet, 0, bytecode, bytes32(0))
            );
            whitelistApp(
                address(fiatTokenV2_2),
                kintoWallet,
                deployerPrivateKey,
                true
            );

            // Initializing the implementation contract with dummy values here prevents
            // the contract from being reinitialized later on with different values.
            // Dummy values can be used here as the proxy contract will store the actual values
            // for the deployed token.

            bytes memory selectorAndParams = abi.encodeWithSelector(
                FiatTokenV1.initialize.selector,
                "",
                "",
                "",
                0,
                THROWAWAY_ADDRESS,
                THROWAWAY_ADDRESS,
                THROWAWAY_ADDRESS,
                THROWAWAY_ADDRESS
            );
            handleOps(
                selectorAndParams,
                address(fiatTokenV2_2),
                kintoWallet,
                deployerPrivateKey
            );

            selectorAndParams = abi.encodeWithSelector(
                FiatTokenV2.initializeV2.selector,
                ""
            );
            handleOps(
                selectorAndParams,
                address(fiatTokenV2_2),
                kintoWallet,
                deployerPrivateKey
            );

            selectorAndParams = abi.encodeWithSelector(
                FiatTokenV2_1.initializeV2_1.selector,
                THROWAWAY_ADDRESS
            );
            handleOps(
                selectorAndParams,
                address(fiatTokenV2_2),
                kintoWallet,
                deployerPrivateKey
            );

            selectorAndParams = abi.encodeWithSelector(
                FiatTokenV2_2.initializeV2_2.selector,
                new address[](0),
                ""
            );
            handleOps(
                selectorAndParams,
                address(fiatTokenV2_2),
                kintoWallet,
                deployerPrivateKey
            );
        } else {
            fiatTokenV2_2 = FiatTokenV2_2(_impl);
        }

        console.log("USDCV1-impl", address(fiatTokenV2_2));
    }

    function deployProxy() internal {
        bytes memory bytecode = abi.encodePacked(
            type(FiatTokenProxy).creationCode,
            abi.encode(address(fiatTokenV2_2))
        );

        // compute USDC proxy address
        proxy = FiatTokenProxy(
            payable(
                KintoDeployer(deployer).computeAddress(
                    deployer,
                    bytecode,
                    bytes32(0)
                )
            )
        );

        // generate bytecode to deploy contract
        bytes memory selectorAndParams = abi.encodeWithSelector(
            KintoDeployer.deploy.selector,
            proxyAdmin, // new admin for the proxy
            bytecode, // USDC proxy bytecode
            0 // salt
        );

        handleOps(selectorAndParams, deployer, kintoWallet, deployerPrivateKey);

        require(FiatTokenProxy(proxy).admin() == proxyAdmin, "admin mismatch");

        // whitelist proxy
        whitelistApp(address(proxy), kintoWallet, deployerPrivateKey, true);

        console.log("USDC-proxy", address(proxy));
    }

    function deployMasterMinter() internal {
        bytes memory bytecode = abi.encodePacked(
            type(MasterMinter).creationCode,
            abi.encode(address(proxy))
        );
        masterMinter = MasterMinter(
            factory.deployContract(kintoWallet, 0, bytecode, bytes32(0))
        );

        // Change the master minter to be owned by the master minter owner
        bytes memory selectorAndParams = abi.encodeWithSelector(
            Ownable.transferOwnership.selector,
            masterMinterOwner
        );
        handleOps(
            selectorAndParams,
            address(masterMinter),
            kintoWallet,
            deployerPrivateKey
        );
        whitelistApp(
            address(masterMinter),
            kintoWallet,
            deployerPrivateKey,
            true
        );
    }
}
