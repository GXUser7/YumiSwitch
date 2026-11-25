#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/subscription_parser.hpp"

namespace yumi_nx::store {

// Binary format for active_node.bin so yumi-sysmodule can load active server config without JSON overhead.
inline constexpr uint32_t kActiveNodeMagic = 0x314E4D59u;  // "YMN1" little-endian
inline constexpr uint16_t kActiveNodeVersion = 1;

[[nodiscard]] std::vector<uint8_t> EncodeActiveNodeBinary(const ProxyNode& node);
[[nodiscard]] std::optional<ProxyNode> DecodeActiveNodeBinary(const std::vector<uint8_t>& bytes);

[[nodiscard]] std::string SerializeSettingsJson(const AppSettings& settings);
[[nodiscard]] std::optional<AppSettings> DeserializeSettingsJson(const std::string& json_text);

[[nodiscard]] std::string SerializeSubscriptionsJson(const std::vector<parse::SubscriptionRecord>& subs);
[[nodiscard]] std::optional<std::vector<parse::SubscriptionRecord>> DeserializeSubscriptionsJson(const std::string& json_text);

[[nodiscard]] std::string SerializeNodesJson(const std::vector<ProxyNode>& nodes);
[[nodiscard]] std::optional<std::vector<ProxyNode>> DeserializeNodesJson(const std::string& json_text);

[[nodiscard]] bool WriteFileAtomic(const std::string& path, const std::string& data);
[[nodiscard]] bool WriteFileAtomic(const std::string& path, const std::vector<uint8_t>& data);
[[nodiscard]] std::optional<std::string> ReadTextFile(const std::string& path);
[[nodiscard]] std::optional<std::vector<uint8_t>> ReadBinaryFile(const std::string& path);

}  // namespace yumi_nx::store
