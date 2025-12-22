#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include "common.hpp"

#include <botan/rsa.h>
#include <botan/pem.h>
#include <botan/data_src.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <mqueue.h>
#include <string_view>
#include <iomanip>
#include <thread>

void print_buffer_hex(const std::array<std::byte, kMessageSize>& buffer, size_t received_bytes) {
    std::cout << "0x";
    for (size_t i = 0; i < received_bytes; ++i) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(buffer[i]);
    }
    std::cout << std::dec;  // reset to decimal
}

int open_receiver_communication(mqd_t& mq) {

  while(true) {
    mq = mq_open(kSenderQueue.data(), O_RDWR);
    if (mq != static_cast<mqd_t>(-1)) {
        break;  // success
    }
    if (errno == ENOENT) {
        std::cout << "Waiting for sender to create the queue...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } else {
        perror("mq_open - queue for receiving could not open");
        return kNOT_OK;
    }
  }
    return kOK;
}

int open_sender_communication(mqd_t& mq) {

  while(true) {
    mq = mq_open(kReceiverQueue.data(), O_RDWR);
    if (mq != static_cast<mqd_t>(-1)) {
        break;  // success
    }
    if (errno == ENOENT) {
        std::cout << "Waiting for sender to create the queue...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } else {
        perror("mq_open - queue for receiving could not open");
        return kNOT_OK;
    }
  }
    return kOK;
}

int get_public_key(mqd_t mq, std::unique_ptr<Botan::Public_Key>& public_key)
{
    std::array<std::byte, kMessageSize> pub_key_buffer{};
    unsigned int msg_prio;

    const ssize_t received_bytes =
        mq_receive(mq,
                   reinterpret_cast<char*>(pub_key_buffer.data()),
                   pub_key_buffer.size(),
                   &msg_prio);

    if (received_bytes == -1) {
        perror("mq_receive");
        return kNOT_OK;
    }

    Botan::DataSource_Memory ds(
        reinterpret_cast<const uint8_t*>(pub_key_buffer.data()),
        received_bytes
    );

    // Load as generic public key
    public_key = Botan::X509::load_key(ds);

    // Ensure it is RSA
    auto* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    if (!rsa) {
        std::cerr << "Received key is not an RSA public key\n";
        return kNOT_OK;
    }

    std::cout << "[Receiver] Received public key (" << received_bytes << " bytes)\n";
    return kOK;
}


int receive_periodic_messages(mqd_t mq) {
    std::array<std::byte, kMessageSize> buffer{};

    while (true) {
        const ssize_t received_bytes =
            mq_receive(mq, reinterpret_cast<char*>(buffer.data()), buffer.size(),
                       nullptr);

        if (received_bytes > 0) {
          std::cout << "[Receiver] Received " << received_bytes << " bytes \n";
          std::cout << "The recieved data is: ";
          print_buffer_hex(buffer, received_bytes);
          std::cout << "\n";
        } else {
          perror("mq_receive");
          break;
        }
    }
    return kOK;
}

int main() {

  std::cout << "Allow for queues to be created...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(5000));

  // Open for reading from sender queue
  mqd_t mq;
  if (open_receiver_communication(mq) != kOK) {
      return kNOT_OK;
  }

  // Set up queue for sending
  mqd_t sender_mq;
  if (open_sender_communication(sender_mq) != kOK) {
      return kNOT_OK;
  }

  unsigned int message_id{kMessageIdRsaPublicKey};
  unsigned int status{kNOT_OK};
  std::unique_ptr<Botan::Public_Key> public_key;
  switch(message_id) {
      case kMessageIdRsaPublicKey:
          std::cout << "Receive public key.\n";
          status = get_public_key(mq, public_key);
          message_id = kMessageIdSymKey;
          [[fallthrough]];
      case kMessageIdSymKey:
          std::cout << "Send symmetric key.\n";
          [[fallthrough]];
      case kMessageIdPeriodic:
          std::cout << "Receive periodic messages.\n";
          status = receive_periodic_messages(mq);
          break;
      default:
          std::cout << "Unknown message ID.\n";
          break;
  }

  // Don't close terminal right away
  std::cout << "Receiver done. Press Enter to exit.";
  std::cin.get();

  mq_close(mq);
  mq_close(sender_mq);
  return status;
}
