// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPassportRegistry
 * @notice Interface for cross-contract integrations and external verifiers.
 */
interface IPassportRegistry {

    enum PassportStatus { Active, Revoked, Expired, Suspended, Lost }
    enum AlertLevel     { None, Watch, Detain, Arrest }

    function getPassportStatus(string calldata passportId)
        external view
        returns (
            PassportStatus status,
            AlertLevel     alert,
            uint256        expiresAt,
            bool           isCurrentlyValid
        );

    function getPassportByWallet(address wallet)
        external view returns (string memory);

    function recordCrossing(
        string calldata passportId,
        string calldata fromCountry,
        string calldata toCountry,
        bool   isEntry,
        string calldata portOfEntry
    ) external returns (uint256 crossingId);
}

/**
 * @title BorderGateway
 * @notice Stateless gateway contract used by port-of-entry kiosks.
 *         Calls the PassportRegistry to validate a traveller in real time
 *         and automatically records the border crossing if cleared.
 *
 *         Designed to be called by automated kiosk wallets that hold
 *         BORDER_AGENT_ROLE on the registry.
 */
contract BorderGateway {

    IPassportRegistry public immutable registry;

    event TravellerCleared(
        string  indexed passportId,
        address indexed travellerWallet,
        string  toCountry,
        uint256 crossingId,
        uint256 timestamp
    );

    event TravellerDenied(
        string  indexed passportId,
        string  reason,
        uint256 timestamp
    );

    constructor(address _registry) {
        registry = IPassportRegistry(_registry);
    }

    /**
     * @notice Validate and process a border crossing for a traveller
     *         identified by their bound wallet address.
     * @param fromCountry  Country traveller is departing from
     * @param toCountry    Country traveller is entering
     * @param portOfEntry  Port/airport name
     * @return cleared     Whether the traveller was cleared
     * @return crossingId  The recorded crossing ID (0 if denied)
     */
    function processCrossing(
        string calldata fromCountry,
        string calldata toCountry,
        string calldata portOfEntry
    ) external returns (bool cleared, uint256 crossingId) {
        string memory passportId = registry.getPassportByWallet(msg.sender);
        require(bytes(passportId).length != 0, "No passport bound to this wallet");

        (
            IPassportRegistry.PassportStatus status,
            IPassportRegistry.AlertLevel alert,
            ,
            bool isValid
        ) = registry.getPassportStatus(passportId);

        if (!isValid) {
            string memory reason = status == IPassportRegistry.PassportStatus.Revoked
                ? "Passport revoked"
                : status == IPassportRegistry.PassportStatus.Suspended
                    ? "Passport suspended"
                    : "Passport invalid or expired";
            emit TravellerDenied(passportId, reason, block.timestamp);
            return (false, 0);
        }

        if (alert == IPassportRegistry.AlertLevel.Detain ||
            alert == IPassportRegistry.AlertLevel.Arrest) {
            emit TravellerDenied(passportId, "Active security alert, refer to officer", block.timestamp);
            return (false, 0);
        }

        crossingId = registry.recordCrossing(passportId, fromCountry, toCountry, true, portOfEntry);

        emit TravellerCleared(passportId, msg.sender, toCountry, crossingId, block.timestamp);
        return (true, crossingId);
    }
}
