// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./PassportRegistry.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PassportFactory
 * @notice Deploys and tracks independent PassportRegistry instances
 *         per country or authority. Useful for multi-authority deployments.
 */
contract PassportFactory is Ownable {

    struct AuthorityInfo {
        address registry;
        string  countryCode;   // ISO 3-letter
        string  authorityName;
        bool    isActive;
        uint256 deployedAt;
    }

    mapping(string => AuthorityInfo) private _authorities; // countryCode => info
    string[] private _allCodes;

    event RegistryDeployed(
        string indexed countryCode,
        address registry,
        string authorityName,
        address rootAuthority
    );

    event RegistryDeactivated(string indexed countryCode);

    constructor() Ownable(msg.sender) {}

    /**
     * @notice Deploy a new PassportRegistry for a country/authority.
     */
    function deployRegistry(
        string  calldata countryCode,
        string  calldata authorityName,
        address rootAuthority
    ) external onlyOwner returns (address registry) {
        require(bytes(_authorities[countryCode].countryCode).length == 0, "Already deployed");
        require(rootAuthority != address(0), "Invalid root authority");

        PassportRegistry reg = new PassportRegistry(rootAuthority);
        registry = address(reg);

        _authorities[countryCode] = AuthorityInfo({
            registry:      registry,
            countryCode:   countryCode,
            authorityName: authorityName,
            isActive:      true,
            deployedAt:    block.timestamp
        });

        _allCodes.push(countryCode);

        emit RegistryDeployed(countryCode, registry, authorityName, rootAuthority);
    }

    function deactivateRegistry(string calldata countryCode) external onlyOwner {
        require(bytes(_authorities[countryCode].countryCode).length != 0, "Not found");
        _authorities[countryCode].isActive = false;
        emit RegistryDeactivated(countryCode);
    }

    function getRegistry(string calldata countryCode)
        external view returns (AuthorityInfo memory)
    {
        return _authorities[countryCode];
    }

    function getAllCodes() external view returns (string[] memory) {
        return _allCodes;
    }

    function totalDeployed() external view returns (uint256) {
        return _allCodes.length;
    }
}
