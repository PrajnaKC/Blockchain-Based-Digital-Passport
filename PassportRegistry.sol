// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PassportRegistry
 * @author ChainPass Authority
 * @notice On-chain digital passport registry with role-based access,
 *         biometric hash binding, visa stamping, travel history,
 *         cross-border alerts, and multi-sig revocation.
 *
 * Compatible with OpenZeppelin Contracts v5.x
 * Counters.sol was removed in OZ v5 — uses plain uint256 counters instead.
 */
contract PassportRegistry is AccessControl, Pausable, ReentrancyGuard {

    bytes32 public constant ISSUER_ROLE       = keccak256("ISSUER_ROLE");
    bytes32 public constant VERIFIER_ROLE     = keccak256("VERIFIER_ROLE");
    bytes32 public constant REVOKER_ROLE      = keccak256("REVOKER_ROLE");
    bytes32 public constant BORDER_AGENT_ROLE = keccak256("BORDER_AGENT_ROLE");

    enum PassportStatus { Active, Revoked, Expired, Suspended, Lost }
    enum PassportType   { Regular, Diplomatic, Service, Official, Emergency }
    enum VisaType       { Tourist, Business, Student, Work, Transit, Diplomatic }
    enum AlertLevel     { None, Watch, Detain, Arrest }

    struct Passport {
        string         passportId;
        bytes32        biometricHash;
        bytes32        dataHash;
        string         nationality;
        PassportType   docType;
        PassportStatus status;
        AlertLevel     alertLevel;
        uint256        issuedAt;
        uint256        expiresAt;
        uint256        lastUpdatedAt;
        address        issuedBy;
        address        holder;
        uint32         visaCount;
        uint32         crossingCount;
        bool           multiSigRevokePending;
        uint8          revokeVotes;
    }

    struct Visa {
        uint256  visaId;
        string   passportId;
        string   issuingCountry;
        VisaType visaType;
        uint256  issuedAt;
        uint256  validFrom;
        uint256  validUntil;
        uint8    allowedEntries;
        uint8    usedEntries;
        bool     isValid;
        address  issuedBy;
        string   conditions;
    }

    struct BorderCrossing {
        uint256 crossingId;
        string  passportId;
        string  fromCountry;
        string  toCountry;
        uint256 timestamp;
        bool    isEntry;
        address recordedBy;
        string  portOfEntry;
    }

    struct RevocationProposal {
        string    passportId;
        string    reason;
        address   proposedBy;
        uint256   proposedAt;
        address[] voters;
        bool      executed;
    }

    // Plain uint256 counters — OZ v5 removed Counters.sol
    uint256 private _passportCount;
    uint256 private _visaCount;
    uint256 private _crossingCount;

    mapping(string  => Passport)                    private _passports;
    mapping(string  => uint256[])                   private _passportVisas;
    mapping(uint256 => Visa)                        private _visas;
    mapping(string  => uint256[])                   private _travelHistory;
    mapping(uint256 => BorderCrossing)              private _crossings;
    mapping(string  => RevocationProposal)          private _revokeProposals;
    mapping(string  => mapping(address => bool))    private _revokeVoted;
    mapping(address => string)                      private _holderPassport;
    mapping(bytes32 => string)                      private _biometricRegistry;
    string[] private _allPassportIds;

    uint8 public multiSigThreshold = 2;

    event PassportIssued(string indexed passportId, string nationality, PassportType docType, bytes32 biometricHash, address issuedBy, uint256 expiresAt);
    event PassportRenewed(string indexed passportId, uint256 oldExpiry, uint256 newExpiry, address renewedBy);
    event PassportStatusChanged(string indexed passportId, PassportStatus oldStatus, PassportStatus newStatus, string reason, address changedBy);
    event VisaIssued(uint256 indexed visaId, string indexed passportId, string issuingCountry, VisaType visaType, uint256 validUntil);
    event VisaRevoked(uint256 indexed visaId, string indexed passportId, address revokedBy);
    event BorderCrossingRecorded(uint256 indexed crossingId, string indexed passportId, string fromCountry, string toCountry, bool isEntry, address recordedBy);
    event AlertRaised(string indexed passportId, AlertLevel level, string reason, address raisedBy);
    event AlertCleared(string indexed passportId, address clearedBy);
    event RevocationProposed(string indexed passportId, string reason, address proposedBy);
    event RevocationVoted(string indexed passportId, address voter, uint8 currentVotes, uint8 threshold);
    event RevocationExecuted(string indexed passportId, string reason);
    event HolderWalletBound(string indexed passportId, address holder);
    event MultiSigThresholdUpdated(uint8 oldValue, uint8 newValue);

    error PassportNotFound(string passportId);
    error PassportAlreadyExists(string passportId);
    error PassportNotActive(string passportId, PassportStatus status);
    error PassportExpired(string passportId, uint256 expiredAt);
    error BiometricAlreadyRegistered(bytes32 biometricHash);
    error WalletAlreadyBound(address wallet, string existingPassport);
    error VisaNotFound(uint256 visaId);
    error VisaExpiredError(uint256 visaId);
    error VisaEntryLimitReached(uint256 visaId);
    error InvalidDates();
    error AlreadyVoted(address voter);
    error ProposalAlreadyExecuted(string passportId);
    error NoActiveProposal(string passportId);

    modifier passportExists(string memory passportId) {
        if (bytes(_passports[passportId].passportId).length == 0) revert PassportNotFound(passportId);
        _;
    }

    modifier passportActive(string memory passportId) {
        Passport storage p = _passports[passportId];
        if (bytes(p.passportId).length == 0)   revert PassportNotFound(passportId);
        if (p.status != PassportStatus.Active)  revert PassportNotActive(passportId, p.status);
        if (block.timestamp > p.expiresAt)      revert PassportExpired(passportId, p.expiresAt);
        _;
    }

    constructor(address rootAuthority) {
        _grantRole(DEFAULT_ADMIN_ROLE, rootAuthority);
        _grantRole(ISSUER_ROLE,        rootAuthority);
        _grantRole(VERIFIER_ROLE,      rootAuthority);
        _grantRole(REVOKER_ROLE,       rootAuthority);
        _grantRole(BORDER_AGENT_ROLE,  rootAuthority);
    }

    function pause()   external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    function issuePassport(
        string       calldata passportId,
        bytes32               biometricHash,
        bytes32               dataHash,
        string       calldata nationality,
        PassportType          docType,
        uint8                 validityYears,
        address               holderWallet
    ) external onlyRole(ISSUER_ROLE) whenNotPaused nonReentrant {
        if (bytes(_passports[passportId].passportId).length != 0)   revert PassportAlreadyExists(passportId);
        if (bytes(_biometricRegistry[biometricHash]).length != 0)    revert BiometricAlreadyRegistered(biometricHash);
        if (holderWallet != address(0) && bytes(_holderPassport[holderWallet]).length != 0)
            revert WalletAlreadyBound(holderWallet, _holderPassport[holderWallet]);

        uint256 expiresAt = block.timestamp + (uint256(validityYears) * 365 days);

        _passports[passportId] = Passport({
            passportId:            passportId,
            biometricHash:         biometricHash,
            dataHash:              dataHash,
            nationality:           nationality,
            docType:               docType,
            status:                PassportStatus.Active,
            alertLevel:            AlertLevel.None,
            issuedAt:              block.timestamp,
            expiresAt:             expiresAt,
            lastUpdatedAt:         block.timestamp,
            issuedBy:              msg.sender,
            holder:                holderWallet,
            visaCount:             0,
            crossingCount:         0,
            multiSigRevokePending: false,
            revokeVotes:           0
        });

        _biometricRegistry[biometricHash] = passportId;
        _allPassportIds.push(passportId);
        _passportCount++;

        if (holderWallet != address(0)) {
            _holderPassport[holderWallet] = passportId;
            emit HolderWalletBound(passportId, holderWallet);
        }

        emit PassportIssued(passportId, nationality, docType, biometricHash, msg.sender, expiresAt);
    }

    function renewPassport(string calldata passportId, bytes32 newDataHash, uint8 validityYears)
        external onlyRole(ISSUER_ROLE) whenNotPaused passportExists(passportId)
    {
        Passport storage p = _passports[passportId];
        require(p.status != PassportStatus.Revoked, "Cannot renew revoked passport");
        uint256 oldExpiry = p.expiresAt;
        uint256 newExpiry = block.timestamp + (uint256(validityYears) * 365 days);
        p.expiresAt     = newExpiry;
        p.dataHash      = newDataHash;
        p.status        = PassportStatus.Active;
        p.lastUpdatedAt = block.timestamp;
        emit PassportRenewed(passportId, oldExpiry, newExpiry, msg.sender);
    }

    function revokePassport(string calldata passportId, string calldata reason)
        external onlyRole(REVOKER_ROLE) whenNotPaused passportExists(passportId)
    {
        Passport storage p = _passports[passportId];
        PassportStatus old = p.status;
        p.status        = PassportStatus.Revoked;
        p.lastUpdatedAt = block.timestamp;
        emit PassportStatusChanged(passportId, old, PassportStatus.Revoked, reason, msg.sender);
    }

    function suspendPassport(string calldata passportId, string calldata reason)
        external onlyRole(REVOKER_ROLE) whenNotPaused passportExists(passportId)
    {
        Passport storage p = _passports[passportId];
        PassportStatus old = p.status;
        p.status        = PassportStatus.Suspended;
        p.lastUpdatedAt = block.timestamp;
        emit PassportStatusChanged(passportId, old, PassportStatus.Suspended, reason, msg.sender);
    }

    function reinstatePassport(string calldata passportId)
        external onlyRole(ISSUER_ROLE) whenNotPaused passportExists(passportId)
    {
        Passport storage p = _passports[passportId];
        require(p.status == PassportStatus.Suspended, "Passport is not suspended");
        require(block.timestamp <= p.expiresAt, "Passport has expired");
        PassportStatus old = p.status;
        p.status        = PassportStatus.Active;
        p.lastUpdatedAt = block.timestamp;
        emit PassportStatusChanged(passportId, old, PassportStatus.Active, "Reinstated", msg.sender);
    }

    function markLost(string calldata passportId, string calldata reason)
        external onlyRole(REVOKER_ROLE) whenNotPaused passportExists(passportId)
    {
        Passport storage p = _passports[passportId];
        PassportStatus old = p.status;
        p.status        = PassportStatus.Lost;
        p.lastUpdatedAt = block.timestamp;
        emit PassportStatusChanged(passportId, old, PassportStatus.Lost, reason, msg.sender);
    }

    function proposeRevocation(string calldata passportId, string calldata reason)
        external onlyRole(REVOKER_ROLE) whenNotPaused passportExists(passportId)
    {
        Passport storage pass = _passports[passportId];
        require(!pass.multiSigRevokePending || _revokeProposals[passportId].executed, "Active proposal exists");

        delete _revokeProposals[passportId];

        RevocationProposal storage prop = _revokeProposals[passportId];
        prop.passportId = passportId;
        prop.reason     = reason;
        prop.proposedBy = msg.sender;
        prop.proposedAt = block.timestamp;
        prop.executed   = false;

        pass.multiSigRevokePending = true;
        pass.revokeVotes           = 0;

        emit RevocationProposed(passportId, reason, msg.sender);
        _castRevokeVote(passportId);
    }

    function voteRevocation(string calldata passportId)
        external onlyRole(REVOKER_ROLE) whenNotPaused passportExists(passportId)
    {
        if (!_passports[passportId].multiSigRevokePending)   revert NoActiveProposal(passportId);
        if (_revokeProposals[passportId].executed)           revert ProposalAlreadyExecuted(passportId);
        if (_revokeVoted[passportId][msg.sender])            revert AlreadyVoted(msg.sender);
        _castRevokeVote(passportId);
    }

    function _castRevokeVote(string memory passportId) internal {
        RevocationProposal storage prop = _revokeProposals[passportId];
        Passport storage p              = _passports[passportId];
        _revokeVoted[passportId][msg.sender] = true;
        prop.voters.push(msg.sender);
        p.revokeVotes++;
        emit RevocationVoted(passportId, msg.sender, p.revokeVotes, multiSigThreshold);
        if (p.revokeVotes >= multiSigThreshold) {
            PassportStatus old      = p.status;
            p.status                = PassportStatus.Revoked;
            p.multiSigRevokePending = false;
            p.lastUpdatedAt         = block.timestamp;
            prop.executed           = true;
            emit RevocationExecuted(passportId, prop.reason);
            emit PassportStatusChanged(passportId, old, PassportStatus.Revoked, prop.reason, msg.sender);
        }
    }

    function raiseAlert(string calldata passportId, AlertLevel level, string calldata reason)
        external onlyRole(BORDER_AGENT_ROLE) whenNotPaused passportExists(passportId)
    {
        require(level != AlertLevel.None, "Use clearAlert to remove alerts");
        _passports[passportId].alertLevel    = level;
        _passports[passportId].lastUpdatedAt = block.timestamp;
        emit AlertRaised(passportId, level, reason, msg.sender);
    }

    function clearAlert(string calldata passportId)
        external onlyRole(REVOKER_ROLE) whenNotPaused passportExists(passportId)
    {
        _passports[passportId].alertLevel    = AlertLevel.None;
        _passports[passportId].lastUpdatedAt = block.timestamp;
        emit AlertCleared(passportId, msg.sender);
    }

    function issueVisa(
        string   calldata passportId,
        string   calldata issuingCountry,
        VisaType          visaType,
        uint256           validFrom,
        uint256           validUntil,
        uint8             allowedEntries,
        string   calldata conditions
    ) external onlyRole(VERIFIER_ROLE) whenNotPaused passportActive(passportId) returns (uint256 visaId) {
        if (validUntil <= validFrom) revert InvalidDates();
        _visaCount++;
        visaId = _visaCount;
        _visas[visaId] = Visa({
            visaId: visaId, passportId: passportId, issuingCountry: issuingCountry,
            visaType: visaType, issuedAt: block.timestamp, validFrom: validFrom,
            validUntil: validUntil, allowedEntries: allowedEntries, usedEntries: 0,
            isValid: true, issuedBy: msg.sender, conditions: conditions
        });
        _passportVisas[passportId].push(visaId);
        _passports[passportId].visaCount++;
        _passports[passportId].lastUpdatedAt = block.timestamp;
        emit VisaIssued(visaId, passportId, issuingCountry, visaType, validUntil);
    }

    function revokeVisa(uint256 visaId) external onlyRole(REVOKER_ROLE) whenNotPaused {
        Visa storage v = _visas[visaId];
        if (v.visaId == 0) revert VisaNotFound(visaId);
        v.isValid = false;
        emit VisaRevoked(visaId, v.passportId, msg.sender);
    }

    function useVisaEntry(uint256 visaId) external onlyRole(BORDER_AGENT_ROLE) whenNotPaused {
        Visa storage v = _visas[visaId];
        if (v.visaId == 0) revert VisaNotFound(visaId);
        if (!v.isValid || block.timestamp > v.validUntil) revert VisaExpiredError(visaId);
        if (v.allowedEntries != 0 && v.usedEntries >= v.allowedEntries) revert VisaEntryLimitReached(visaId);
        v.usedEntries++;
    }

    function recordCrossing(
        string calldata passportId, string calldata fromCountry,
        string calldata toCountry, bool isEntry, string calldata portOfEntry
    ) external onlyRole(BORDER_AGENT_ROLE) whenNotPaused passportExists(passportId) returns (uint256 crossingId) {
        Passport storage p = _passports[passportId];
        require(p.status != PassportStatus.Revoked, "Revoked passport");
        require(p.alertLevel != AlertLevel.Detain && p.alertLevel != AlertLevel.Arrest, "Active high-level alert");
        _crossingCount++;
        crossingId = _crossingCount;
        _crossings[crossingId] = BorderCrossing({
            crossingId: crossingId, passportId: passportId, fromCountry: fromCountry,
            toCountry: toCountry, timestamp: block.timestamp, isEntry: isEntry,
            recordedBy: msg.sender, portOfEntry: portOfEntry
        });
        _travelHistory[passportId].push(crossingId);
        p.crossingCount++;
        p.lastUpdatedAt = block.timestamp;
        emit BorderCrossingRecorded(crossingId, passportId, fromCountry, toCountry, isEntry, msg.sender);
    }

    function bindHolderWallet(string calldata passportId, address newHolder)
        external whenNotPaused passportExists(passportId)
    {
        Passport storage p   = _passports[passportId];
        bool isIssuer        = hasRole(ISSUER_ROLE, msg.sender);
        bool isCurrentHolder = (p.holder == msg.sender && msg.sender != address(0));
        require(isIssuer || isCurrentHolder, "Not authorized");
        if (p.holder != address(0)) delete _holderPassport[p.holder];
        if (bytes(_holderPassport[newHolder]).length != 0)
            revert WalletAlreadyBound(newHolder, _holderPassport[newHolder]);
        p.holder                   = newHolder;
        _holderPassport[newHolder] = passportId;
        p.lastUpdatedAt            = block.timestamp;
        emit HolderWalletBound(passportId, newHolder);
    }

    function setMultiSigThreshold(uint8 threshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(threshold >= 1 && threshold <= 10, "Threshold must be 1-10");
        emit MultiSigThresholdUpdated(multiSigThreshold, threshold);
        multiSigThreshold = threshold;
    }

    function getPassport(string calldata passportId)
        external view onlyRole(VERIFIER_ROLE) passportExists(passportId) returns (Passport memory)
    { return _passports[passportId]; }

    function getPassportStatus(string calldata passportId)
        external view passportExists(passportId)
        returns (PassportStatus status, AlertLevel alert, uint256 expiresAt, bool isCurrentlyValid)
    {
        Passport storage p = _passports[passportId];
        return (p.status, p.alertLevel, p.expiresAt, p.status == PassportStatus.Active && block.timestamp <= p.expiresAt);
    }

    function getPassportVisas(string calldata passportId)
        external view onlyRole(VERIFIER_ROLE) passportExists(passportId) returns (uint256[] memory)
    { return _passportVisas[passportId]; }

    function getVisa(uint256 visaId) external view onlyRole(VERIFIER_ROLE) returns (Visa memory) {
        if (_visas[visaId].visaId == 0) revert VisaNotFound(visaId);
        return _visas[visaId];
    }

    function getTravelHistory(string calldata passportId)
        external view onlyRole(VERIFIER_ROLE) passportExists(passportId) returns (uint256[] memory)
    { return _travelHistory[passportId]; }

    function getCrossing(uint256 crossingId) external view onlyRole(VERIFIER_ROLE) returns (BorderCrossing memory)
    { return _crossings[crossingId]; }

    function getPassportByWallet(address wallet) external view returns (string memory)
    { return _holderPassport[wallet]; }

    function getPassportByBiometric(bytes32 biometricHash)
        external view onlyRole(VERIFIER_ROLE) returns (string memory)
    { return _biometricRegistry[biometricHash]; }

    function getStats() external view returns (uint256 totalPassports, uint256 totalVisas, uint256 totalCrossings)
    { return (_passportCount, _visaCount, _crossingCount); }

    function getPassportIds(uint256 offset, uint256 limit)
        external view onlyRole(VERIFIER_ROLE) returns (string[] memory ids)
    {
        uint256 total = _allPassportIds.length;
        if (offset >= total) return new string[](0);
        uint256 end = offset + limit > total ? total : offset + limit;
        ids = new string[](end - offset);
        for (uint256 i = offset; i < end; i++) ids[i - offset] = _allPassportIds[i];
    }

    function getRevocationProposal(string calldata passportId)
        external view onlyRole(REVOKER_ROLE) passportExists(passportId) returns (RevocationProposal memory)
    { return _revokeProposals[passportId]; }
}
