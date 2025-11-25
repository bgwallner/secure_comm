#ifndef MQ_CONFIG_HPP_
#define MQ_CONFIG_HPP_

#include <cstddef>
#include <chrono>
#include <string_view>

// Shared configuration for both sender and receiver.
inline constexpr std::string_view kQueueName = "/mq_modern_cpp";

inline constexpr std::size_t kMessageSize = 20;
inline constexpr long kMaxMessages = 10;

// Sender-specific configuration.
inline constexpr int kNumMessagesToSend = 100;
inline constexpr std::byte kDefaultFillByte = std::byte{0xFF};
inline constexpr std::byte kInitialByteBase = std::byte{0};
inline constexpr int kByteModulo = 256;

// Timing configuration.
inline constexpr auto kSendPeriod = std::chrono::milliseconds(1000);

// POSIX queue permissions.
inline constexpr mode_t kQueuePermissions = 0666;

#endif  // MQ_CONFIG_HPP_
