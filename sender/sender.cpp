#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include "common.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <mqueue.h>
#include <span>
#include <string_view>
#include <thread>

// Predefined key for CMAC (16 bytes for AES-128)
inline constexpr std::array<uint8_t, 16> KEY = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF
};

// Automatically unlinks the message queue when destroyed.
class MqUnlinker {
 public:
  explicit MqUnlinker(std::string_view name) : name_(name) {}
  ~MqUnlinker() { mq_unlink(name_.data()); }

  MqUnlinker(const MqUnlinker&) = delete;
  MqUnlinker& operator=(const MqUnlinker&) = delete;

 private:
  std::string_view name_;
};

auto calculate_mac(std::span<const std::byte> data) {
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
    mac->set_key(KEY);
    mac->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return mac->final();
}

void print_buffer_hex(const std::array<std::byte, kMessageSize>& buffer) {
    std::cout << "0x";
    for (auto b : buffer) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(b);
    }
    std::cout << std::dec;  // reset to decimal
}

int main() {
  MqUnlinker unlinker(kQueueName);

  mq_attr queue_attr{};
  queue_attr.mq_flags = 0;
  queue_attr.mq_maxmsg = kMaxMessages;
  queue_attr.mq_msgsize = kMessageSize;

  mqd_t mq =
      mq_open(kQueueName.data(), O_CREAT | O_WRONLY, kQueuePermissions, &queue_attr);
  if (mq == static_cast<mqd_t>(-1)) {
    perror("mq_open (sender)");
    return 1;
  }

  // ************************** BOTAN TEST ******************* */
  // Botan::AutoSeeded_RNG rng;
  //  const auto key = rng.random_vec(16); // 128 bit random key
  //  auto data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");

  //  const auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
  //  mac->set_key(key);
  //  mac->update(data);
  //  const auto tag = mac->final();
   
  //  std::cout << "The data is: " << Botan::hex_encode(data) << "\n";
  //  std::cout << "The cmac is: " << Botan::hex_encode(mac) << "\n";

   //***************************************************** */

  std::array<std::byte, kMessageSize> buffer{};
  buffer.fill(kDefaultFillByte);
  std::span<const std::byte> span = buffer;   // ✔ OK


  for (int message_index = 0; message_index < kNumMessagesToSend; ++message_index) {
    // Vary the first byte in a controlled way
    // unsigned int value =
    //     (static_cast<unsigned int>(kInitialByteBase) + (message_index % kByteModulo)) %
    //     kByteModulo;
    //buffer[0] = static_cast<std::byte>(value);
    buffer[kMessageSize-1] = static_cast<std::byte>(message_index);

    // Calculate CMAC for the message
    const auto mac = calculate_mac(buffer);


    const int send_result =
        mq_send(mq, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0);

    if (send_result == -1) {
      perror("mq_send");
      break;
    }

    std::cout << "[Sender] Sent " << buffer.size() << " bytes (msg #"
              << message_index << ")\n";
    std::cout << "The sent data is: ";
    print_buffer_hex(buffer);
    std::cout << "\n";
    std::cout << "The cmac is: 0x" << Botan::hex_encode(mac) << "\n";

    std::this_thread::sleep_for(kSendPeriod);
  }

  mq_close(mq);
  return 0;
}