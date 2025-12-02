// main.cpp
// REST API for AppGate IP Controller
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <mutex>

#include "FirewallManager.h"
#include "Models.h"
#include "Utils.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

enum class FirewallMode { Blacklist, Whitelist };

static constexpr const char* kWhitelistFile = "whitelist.txt";
static constexpr const char* kBlacklistFile = "blacklist.txt";

struct FileLoadStats {
	bool opened = false;
	int applied = 0;
	int failed = 0;
	std::vector<std::string> appliedEntries;
};

// Global state
FirewallManager g_fm;
FirewallMode g_mode = FirewallMode::Blacklist;
std::mutex g_mutex;

const char* ModeLabel(FirewallMode mode) {
	return mode == FirewallMode::Whitelist ? "whitelist" : "blacklist";
}

const char* FileLabel(FirewallMode mode) {
	return mode == FirewallMode::Whitelist ? kWhitelistFile : kBlacklistFile;
}

std::filesystem::path ResolveListPath(FirewallMode mode) {
	std::filesystem::path path = Utils::GetExecutableDir();
	path /= FileLabel(mode);
	return path;
}

void PrintListLocation(FirewallMode mode, const std::filesystem::path& path) {
	std::cout << "[i] " << ModeLabel(mode) << " file: " << path << "\n";
}

std::vector<std::uint16_t> CollectPorts(const RuleEntry& rule) {
	std::vector<std::uint16_t> ports;
	ports.reserve(rule.portRules.size());
	for (const auto& portRule : rule.portRules) {
		ports.push_back(portRule.port);
	}
	std::sort(ports.begin(), ports.end());
	ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
	return ports;
}

void RemoveRulesForMode(FirewallManager& fm, FirewallMode mode) {
	auto rules = fm.ListRules();
	for (const auto& rule : rules) {
		const bool isWhitelistRule = rule.isWhitelist;
		if (mode == FirewallMode::Whitelist && isWhitelistRule) {
			fm.RemoveWhitelistedIP(rule.ipAddress);
			continue;
		}
		if (mode == FirewallMode::Blacklist && !isWhitelistRule) {
			fm.UnblockIP(rule.ipAddress);
		}
	}
}

bool PersistRulesToDisk(const FirewallManager& fm, FirewallMode mode) {
	const auto path = ResolveListPath(mode);
	const auto parent = path.parent_path();
	std::error_code ec;
	if (!parent.empty() && !std::filesystem::exists(parent)) {
		std::filesystem::create_directories(parent, ec);
		if (ec) {
			std::cerr << "[!] Failed to create directory for " << ModeLabel(mode) << " file: " << parent << "\n";
			return false;
		}
	}

	std::ofstream file(path, std::ios::trunc);
	if (!file.is_open()) {
		std::cerr << "[!] Could not open " << ModeLabel(mode) << " file for writing: " << path << "\n";
		return false;
	}

	auto rules = fm.ListRules();
	bool wroteEntry = false;
	for (const auto& rule : rules) {
		const bool matchesMode = (mode == FirewallMode::Whitelist && rule.isWhitelist) ||
			                    (mode == FirewallMode::Blacklist && !rule.isWhitelist);
		if (!matchesMode) {
			continue;
		}

		file << rule.ipAddress;
		if (rule.allPorts || rule.portRules.empty()) {
			file << " all";
		} else {
			auto ports = CollectPorts(rule);
			for (std::uint16_t portValue : ports) {
				file << ' ' << portValue;
			}
		}
		file << '\n';
		wroteEntry = true;
	}

	if (!wroteEntry) {
		file << "# No entries managed in this mode.\n";
	}

	file.flush();
	if (!file.good()) {
		std::cerr << "[!] Failed to write " << ModeLabel(mode) << " file at " << path << "\n";
		return false;
	}

	std::cout << "[i] Saved " << ModeLabel(mode) << " file to " << path << "\n";
	return true;
}

FileLoadStats LoadRulesFromFile(FirewallManager& fm,
	FirewallMode mode,
	const std::filesystem::path& filePath,
	bool quietErrors) {
	FileLoadStats stats;
	std::ifstream file(filePath);
	if (!file.is_open()) {
		return stats;
	}

	stats.opened = true;
	std::string line;
	while (std::getline(file, line)) {
		if (line.empty() || line[0] == '#') {
			continue;
		}

		std::istringstream iss(line);
		std::string ip;
		if (!(iss >> ip)) {
			continue;
		}

		std::vector<std::string> tokens;
		std::string token;
		while (iss >> token) {
			tokens.push_back(token);
		}

		if (mode == FirewallMode::Whitelist) {
			if (tokens.empty()) {
				if (!quietErrors) {
					std::cout << "[!] Whitelist entry for " << ip << " must specify 'all' or a port list.\n";
				}
				++stats.failed;
				continue;
			}

			// Parse ports logic simplified for file loading
			bool allowAll = false;
			std::vector<uint16_t> ports;
			bool error = false;

			for (const auto& token : tokens) {
				std::string lower = token;
				std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
				if (lower == "all" || lower == "any" || lower == "*") {
					allowAll = true;
					break;
				}
				try {
					int val = std::stoi(token);
					if (val > 0 && val <= 65535) ports.push_back((uint16_t)val);
					else error = true;
				} catch(...) { error = true; }
			}

			if (error) {
				if (!quietErrors) std::cout << "[!] Invalid port in file for " << ip << "\n";
				stats.failed++;
				continue;
			}

			bool success = allowAll ? fm.WhitelistIP(ip) : fm.WhitelistIP(ip, ports);
			if (success) {
				++stats.applied;
				stats.appliedEntries.push_back(ip);
			} else {
				++stats.failed;
			}
			continue;
		}

		// Blacklist logic
		if (tokens.empty()) {
			if (fm.BlockIP(ip)) {
				++stats.applied;
				stats.appliedEntries.push_back(ip + " (all ports)");
			} else {
				++stats.failed;
			}
			continue;
		}

		bool requestAll = false;
		for (const auto& t : tokens) {
			std::string lower = t;
			std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
			if (lower == "all" || lower == "any" || lower == "*") {
				requestAll = true;
				break;
			}
		}

		if (requestAll) {
			if (fm.BlockIP(ip)) {
				++stats.applied;
				stats.appliedEntries.push_back(ip + " (all ports)");
			} else {
				++stats.failed;
			}
			continue;
		}

		bool parsedPort = false;
		std::vector<std::uint16_t> successfulPorts;
		for (const auto& portToken : tokens) {
			int value = 0;
			try {
				value = std::stoi(portToken);
			} catch (...) {
				if (!quietErrors) {
					std::cout << "[!] Invalid port '" << portToken << "' for IP " << ip << ".\n";
				}
				++stats.failed;
				continue;
			}

			if (value <= 0 || value > 65535) {
				if (!quietErrors) {
					std::cout << "[!] Port out of range ('" << portToken << "') for IP " << ip << ".\n";
				}
				++stats.failed;
				continue;
			}

			parsedPort = true;
			std::uint16_t portValue = static_cast<std::uint16_t>(value);
			if (fm.BlockIP(ip, portValue)) {
				++stats.applied;
				successfulPorts.push_back(portValue);
			} else {
				++stats.failed;
			}
		}

		if (!parsedPort) {
			if (!quietErrors) {
				std::cout << "[!] No valid ports specified for IP " << ip << ".\n";
			}
			continue;
		}

		if (!successfulPorts.empty()) {
			std::sort(successfulPorts.begin(), successfulPorts.end());
			successfulPorts.erase(std::unique(successfulPorts.begin(), successfulPorts.end()), successfulPorts.end());
			std::ostringstream desc;
			desc << ip << " ports:";
			for (std::uint16_t portValue : successfulPorts) {
				desc << ' ' << portValue;
			}
			stats.appliedEntries.push_back(desc.str());
		}
	}

	return stats;
}

void LoadPersistedRules(FirewallManager& fm, FirewallMode mode) {
	const auto path = ResolveListPath(mode);
	PrintListLocation(mode, path);

	if (!std::filesystem::exists(path)) {
		std::cout << "[i] No " << ModeLabel(mode) << " file found at " << path << ".\n";
		return;
	}

	std::ifstream probe(path);
	if (!probe.is_open()) {
		std::cout << "[!] Could not open " << ModeLabel(mode) << " file at " << path << ".\n";
		return;
	}
	probe.close();

	RemoveRulesForMode(fm, mode);
	FileLoadStats stats = LoadRulesFromFile(fm, mode, path, /*quietErrors=*/true);
	
	if (stats.applied > 0) {
		std::cout << "[+] Restored " << stats.applied << ' ' << ModeLabel(mode)
		          << " entries from " << path << ".\n";
	} else {
		std::cout << "[i] " << path << " contained no " << ModeLabel(mode) << " entries to apply.\n";
	}
}

int main() {
    // Initialize
    if (!g_fm.Initialize()) {
        std::cerr << "[!] Failed to initialize firewall manager.\n";
        return 1;
    }
    std::cout << "[+] Firewall manager initialized.\n";

    // Load initial state
    LoadPersistedRules(g_fm, g_mode);

    httplib::Server svr;

    // CORS headers
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        if (req.method == "OPTIONS") {
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // GET /api/status
    svr.Get("/api/status", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        json j;
        j["mode"] = (g_mode == FirewallMode::Whitelist ? "whitelist" : "blacklist");
        j["rule_count"] = g_fm.ListRules().size();
        j["status"] = "running";
        res.set_content(j.dump(), "application/json");
    });

    // POST /api/mode
    svr.Post("/api/mode", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        try {
            auto j = json::parse(req.body);
            std::string new_mode_str = j["mode"];
            
            if (new_mode_str == "whitelist") {
                if (g_mode != FirewallMode::Whitelist) {
                    if (g_fm.EnableWhitelistMode()) {
                        g_mode = FirewallMode::Whitelist;
                        LoadPersistedRules(g_fm, g_mode); // Reload rules for new mode
                    } else {
                        res.status = 500;
                        res.set_content("{\"error\": \"Failed to enable whitelist mode\"}", "application/json");
                        return;
                    }
                }
            } else if (new_mode_str == "blacklist") {
                if (g_mode != FirewallMode::Blacklist) {
                    g_fm.DisableWhitelistMode();
                    g_mode = FirewallMode::Blacklist;
                    LoadPersistedRules(g_fm, g_mode); // Reload rules for new mode
                }
            } else {
                res.status = 400;
                res.set_content("{\"error\": \"Invalid mode\"}", "application/json");
                return;
            }
            
            json response;
            response["mode"] = (g_mode == FirewallMode::Whitelist ? "whitelist" : "blacklist");
            res.set_content(response.dump(), "application/json");
        } catch (...) {
            res.status = 400;
            res.set_content("{\"error\": \"Invalid JSON\"}", "application/json");
        }
    });

    // --- Global Port Blocking Endpoints ---

    // GET /api/ports/block - Get all blocked ports
    svr.Get("/api/ports/block", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        json response;
        response["blocked_ports"] = g_fm.GetBlockedGlobalPorts();
        res.set_content(response.dump(), "application/json");
    });

    // POST /api/ports/block - Block a specific port
    svr.Post("/api/ports/block", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        try {
            auto json_body = json::parse(req.body);
            if (json_body.contains("port")) {
                uint16_t port = json_body["port"];
                if (g_fm.BlockGlobalPort(port)) {
                    res.set_content("{\"status\":\"success\"}", "application/json");
                } else {
                    res.status = 500;
                    res.set_content("{\"status\":\"error\", \"message\":\"Failed to block port\"}", "application/json");
                }
            } else {
                res.status = 400;
                res.set_content("{\"status\":\"error\", \"message\":\"Missing 'port'\"}", "application/json");
            }
        } catch (...) {
            res.status = 400;
            res.set_content("{\"status\":\"error\", \"message\":\"Invalid JSON\"}", "application/json");
        }
    });

    // DELETE /api/ports/block - Unblock a port
    svr.Delete("/api/ports/block", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (req.has_param("port")) {
            uint16_t port = std::stoi(req.get_param_value("port"));
            if (g_fm.UnblockGlobalPort(port)) {
                res.set_content("{\"status\":\"success\"}", "application/json");
            } else {
                res.status = 404;
                res.set_content("{\"status\":\"error\", \"message\":\"Port not found\"}", "application/json");
            }
        } else {
            res.status = 400;
        }
    });

    // GET /api/rules
    svr.Get("/api/rules", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto rules = g_fm.ListRules();
        json j_rules = json::array();
        for (const auto& rule : rules) {
            json j_rule;
            j_rule["serial"] = rule.serial;
            j_rule["ip"] = rule.ipAddress;
            j_rule["type"] = rule.isWhitelist ? "whitelist" : "blacklist";
            j_rule["all_ports"] = rule.allPorts;
            std::vector<uint16_t> ports;
            for(auto& p : rule.portRules) ports.push_back(p.port);
            j_rule["ports"] = ports;
            j_rules.push_back(j_rule);
        }
        res.set_content(j_rules.dump(), "application/json");
    });

    // POST /api/rules (Add)
    svr.Post("/api/rules", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        try {
            auto j = json::parse(req.body);
            std::string ip = j["ip"];
            if (ip.empty()) {
                res.status = 400;
                res.set_content("{\"error\": \"IP required\"}", "application/json");
                return;
            }

            bool allowAll = j.value("all_ports", true);
            std::vector<uint16_t> ports;
            if (j.contains("ports")) {
                ports = j["ports"].get<std::vector<uint16_t>>();
                if (!ports.empty()) allowAll = false;
            }

            bool success = false;
            if (g_mode == FirewallMode::Whitelist) {
                if (allowAll) success = g_fm.WhitelistIP(ip);
                else success = g_fm.WhitelistIP(ip, ports);
            } else {
                if (allowAll) success = g_fm.BlockIP(ip);
                else {
                    success = true;
                    for (auto p : ports) {
                        if (!g_fm.BlockIP(ip, p)) success = false;
                    }
                    if (ports.empty() && allowAll) success = g_fm.BlockIP(ip);
                }
            }

            if (success) {
                PersistRulesToDisk(g_fm, g_mode);
                res.set_content("{\"status\": \"ok\"}", "application/json");
            } else {
                res.status = 500;
                res.set_content("{\"error\": \"Failed to apply rule\"}", "application/json");
            }
        } catch (...) {
            res.status = 400;
            res.set_content("{\"error\": \"Invalid JSON\"}", "application/json");
        }
    });

    // DELETE /api/rules (Remove)
    svr.Delete("/api/rules", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!req.has_param("ip")) {
            res.status = 400;
            res.set_content("{\"error\": \"IP param required\"}", "application/json");
            return;
        }
        std::string ip = req.get_param_value("ip");
        
        bool success = false;
        if (g_mode == FirewallMode::Whitelist) {
            success = g_fm.RemoveWhitelistedIP(ip);
        } else {
            success = g_fm.UnblockIP(ip);
        }

        if (success) {
            PersistRulesToDisk(g_fm, g_mode);
            res.set_content("{\"status\": \"ok\"}", "application/json");
        } else {
            res.status = 404;
            res.set_content("{\"error\": \"Rule not found or failed to remove\"}", "application/json");
        }
    });

    // POST /api/rules/clear
    svr.Post("/api/rules/clear", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_fm.ClearRules();
        PersistRulesToDisk(g_fm, g_mode);
        res.set_content("{\"status\": \"cleared\"}", "application/json");
    });

    // POST /api/rules/load
    svr.Post("/api/rules/load", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        LoadPersistedRules(g_fm, g_mode);
        res.set_content("{\"status\": \"loaded\"}", "application/json");
    });

    // GET /api/dashboard
    svr.Get("/api/dashboard", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        json j;
        auto rules = g_fm.ListRules();
        int whitelist_count = 0;
        int blacklist_count = 0;
        for(const auto& r : rules) {
            if(r.isWhitelist) whitelist_count++;
            else blacklist_count++;
        }
        
        j["mode"] = (g_mode == FirewallMode::Whitelist ? "whitelist" : "blacklist");
        j["total_rules"] = rules.size();
        j["whitelist_rules"] = whitelist_count;
        j["blacklist_rules"] = blacklist_count;
        
        res.set_content(j.dump(), "application/json");
    });

    std::cout << "[+] Starting REST API on http://localhost:8080\n";
    svr.listen("0.0.0.0", 8080);

    return 0;
}
