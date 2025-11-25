#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include "common.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <mqueue.h>
#include <string_view>
#include <iomanip>

void print_buffer_hex(const std::array<std::byte, kMessageSize>& buffer) {
    std::cout << "0x";
    for (auto b : buffer) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(b);
    }
    std::cout << std::dec;  // reset to decimal
}

int main() {

  mqd_t mq = mq_open(kQueueName.data(), O_RDONLY);
  if (mq == static_cast<mqd_t>(-1)) {
    perror("mq_open (receiver)");
    return 1;
  }

  std::array<std::byte, kMessageSize> buffer{};

  while (true) {
    const ssize_t received_bytes =
        mq_receive(mq, reinterpret_cast<char*>(buffer.data()), buffer.size(),
                   nullptr);

    if (received_bytes >= 0) {
      std::cout << "[Receiver] Received " << received_bytes << " bytes \n";
      std::cout << "The recieved data is: ";
      print_buffer_hex(buffer);
      std::cout << "\n";
    } else {
      perror("mq_receive");
      break;
    }
  }

  mq_close(mq);
  return 0;
}

