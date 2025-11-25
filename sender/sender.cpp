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
#include <string_view>
#include <thread>

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
  Botan::AutoSeeded_RNG rng;
   const auto key = rng.random_vec(16); // 128 bit random key
   auto data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");

   const auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
   mac->set_key(key);
   mac->update(data);
   const auto tag = mac->final();
   
   std::cout << "The data is: " << Botan::hex_encode(data) << "\n";
   std::cout << "The cmac is: " << Botan::hex_encode(tag) << "\n";

   //***************************************************** */

  std::array<std::byte, kMessageSize> buffer{};
  buffer.fill(kDefaultFillByte);

  for (int message_index = 0; message_index < kNumMessagesToSend; ++message_index) {
    // Vary the first byte in a controlled way
    // unsigned int value =
    //     (static_cast<unsigned int>(kInitialByteBase) + (message_index % kByteModulo)) %
    //     kByteModulo;
    // buffer[0] = static_cast<std::byte>(value);

    const int send_result =
        mq_send(mq, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0);

    if (send_result == -1) {
      perror("mq_send");
      break;
    }

    std::cout << "[Sender] Sent " << buffer.size() << " bytes (msg #"
              << message_index << ")\n";

    std::this_thread::sleep_for(kSendPeriod);
  }

  mq_close(mq);
  return 0;
}

