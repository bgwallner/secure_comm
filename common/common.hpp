#ifndef MQ_CONFIG_HPP_
#define MQ_CONFIG_HPP_

#include <cstddef>
#include <chrono>
#include <string_view>

// Shared configuration for both sender and receiver.
inline constexpr std::string_view kSenderToReceiverQueue = "/mq_sender_to_receiver";
inline constexpr std::string_view kReceiverToSenderQueue = "/mq_receiver_to_sender";

// IPC message queue configuration.
inline constexpr std::size_t kMessageSize = 1024;
inline constexpr long kMaxMessages = 10;

// Buffer size for periodic messages
inline constexpr std::size_t kBufferSize = 20;

// Buffer size for cmac
inline constexpr std::size_t kCmacSize = 16;

// Buffer size for RSA keys
inline constexpr std::size_t kRsaKeySize = 512;

// Sender-specific configuration.
inline constexpr int kNumMessagesToSend = 10;
inline constexpr std::byte kDefaultFillByte = std::byte{0xFF};
inline constexpr std::byte kInitialByteBase = std::byte{0};
inline constexpr int kByteModulo = 256;

// Timing configuration.
inline constexpr auto kSendPeriod = std::chrono::milliseconds(3000);

// POSIX queue permissions.
inline constexpr mode_t kQueuePermissions = 0644;

// Message IDs
inline constexpr unsigned int kMessageIdRsaPublicKey = 0;
inline constexpr unsigned int kMessageIdSymKey = 1;
inline constexpr unsigned int kMessageIdPeriodic = 2;

inline constexpr unsigned int kOK{0};
inline constexpr unsigned int kNOT_OK{1};



#endif  // MQ_CONFIG_HPP_
