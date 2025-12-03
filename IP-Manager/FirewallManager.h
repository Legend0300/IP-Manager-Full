// FirewallManager.h
// Minimal IP-based firewall management using WFP
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <map>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "Models.h"

class FirewallManager {
public:
    FirewallManager();
    ~FirewallManager();

    bool Initialize();
    bool BlockIP(const std::string& ipAddress, std::optional<std::uint16_t> port = std::nullopt, const std::string& protocol = "ALL");
    bool RemovePortBlock(const std::string& ipAddress, std::uint16_t port, const std::string& protocol = "ALL");
    bool UnblockIP(const std::string& ipAddress);
    std::vector<RuleEntry> ListRules() const;
    void ClearRules();
    bool EnableWhitelistMode();
    bool DisableWhitelistMode();
    bool IsWhitelistMode() const { return whitelistMode; }
    bool WhitelistIP(const std::string& ipAddress,
                     std::optional<std::vector<std::uint16_t>> ports = std::nullopt,
                     const std::string& protocol = "ALL");
    bool AllowPortsForIP(const std::string& ipAddress, const std::vector<std::uint16_t>& ports, const std::string& protocol = "ALL");
    bool RemoveWhitelistPort(const std::string& ipAddress, std::uint16_t port, const std::string& protocol = "ALL");
    bool RemoveWhitelistedIP(const std::string& ipAddress);

    // NEW: Global Port Blocking methods
    bool BlockGlobalPort(uint16_t port, const std::string& protocol = "ALL");
    bool UnblockGlobalPort(uint16_t port, const std::string& protocol = "ALL");
    std::vector<std::pair<uint16_t, std::string>> GetBlockedGlobalPorts();

    // NEW: Global Protocol Blocking (e.g. Block ALL TCP)
    bool BlockGlobalProtocol(const std::string& protocol);
    bool UnblockGlobalProtocol(const std::string& protocol);
    std::vector<std::string> GetBlockedGlobalProtocols();

private:
    std::map<std::pair<uint16_t, std::string>, std::vector<UINT64>> globalPortRules; // Key: {port, protocol}
    std::map<std::string, std::vector<UINT64>> globalProtocolRules; // Key: protocol ("TCP", "UDP")

    bool AddSublayer();
    bool AddFilterForIP(const std::string& ipAddress,
                        const GUID& layer,
                        UINT64& outFilterId,
                        const std::string& protocol = "ALL");
    bool AddBlockFiltersForPort(const std::string& ipAddress,
                                std::uint16_t port,
                                std::vector<UINT64>& outFilterIds,
                                const std::string& protocol = "ALL");
    bool AddDefaultBlockFilters();
    void RemoveDefaultBlockFilters();

    bool AddOutboundPermitFilters(const std::string& ipAddress,
                                  std::optional<std::uint16_t> port,
                                  std::vector<UINT64>& outFilterIds,
                                  const std::string& protocol = "ALL");
    bool AddInboundPermitFilters(const std::string& ipAddress,
                                 std::optional<std::uint16_t> port,
                                 std::vector<UINT64>& outFilterIds,
                                 const std::string& protocol = "ALL");

    HANDLE engineHandle; // FWPM_SESSION0*
    bool wsaInitialized;
    int nextSerial;
    std::vector<RuleEntry> rules;
    bool whitelistMode;
    std::vector<UINT64> defaultBlockFilterIds;
};
