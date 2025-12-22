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
    std::cout << "\n";
}

int open_receiver_communication(mqd_t& mq) {

  mq_attr queue_attr{};
  queue_attr.mq_flags = 0;
  queue_attr.mq_maxmsg = kMaxMessages;
  queue_attr.mq_msgsize = kMessageSize;

  mq =
    mq_open(kSenderQueue.data(), O_CREAT | O_RDWR, kQueuePermissions, &queue_attr);
    if (mq == static_cast<mqd_t>(-1)) {
      perror("mq_open - queue for sending could not open");
      return kNOT_OK;
    }
    return kOK;
}

int open_sender_communication(mqd_t& mq) {

  mq_attr queue_attr{};
  queue_attr.mq_flags = 0;
  queue_attr.mq_maxmsg = kMaxMessages;
  queue_attr.mq_msgsize = kMessageSize;

  mq =
    mq_open(kReceiverQueue.data(), O_CREAT | O_RDWR, kQueuePermissions, &queue_attr);
    if (mq == static_cast<mqd_t>(-1)) {
      perror("mq_open - queue for receiving could not open");
      return kNOT_OK;
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

    std::cout << "[Receiver] Received public key (" << received_bytes << " bytes)\n";
    std::cout << "The received public key raw data is: \n";
    print_buffer_hex(pub_key_buffer, received_bytes);
    std::cout << "\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    Botan::DataSource_Memory ds(
        reinterpret_cast<const uint8_t*>(pub_key_buffer.data()),
        received_bytes
    );

    public_key = Botan::X509::load_key(ds);

    // Ensure it is RSA
    auto* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    if (!rsa) {
        std::cerr << "Received key is not an RSA public key\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        return kNOT_OK;
    }

    std::string pem = Botan::X509::PEM_encode(*public_key);
    std::cout << "Received RSA Public Key in PEM format:\n";
    std::cout << pem << std::endl;

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    return kOK;
}

int send_symmetric_key(mqd_t mq, std::unique_ptr<Botan::Public_Key>& public_key) {
    Botan::AutoSeeded_RNG rng;

    // Generate a random symmetric key (e.g., 16 bytes for AES-128)
    Botan::secure_vector<uint8_t> symmetric_key(16);
    rng.randomize(symmetric_key.data(), symmetric_key.size());

    Botan::RSA_PublicKey* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    Botan::PK_Encryptor_EME encryptor(*rsa, rng, "EME1(SHA-256)");
    
    Botan::secure_vector<uint8_t> encrypted_key = encryptor.encrypt(symmetric_key, rng);

    // Send the encrypted symmetric key via message queue
    const int send_result = mq_send(
        mq,
        reinterpret_cast<const char*>(encrypted_key.data()),
        encrypted_key.size(),
        0
    );

    if (send_result == -1) {
        perror("mq_send");
        return kNOT_OK;
    }

    std::cout << "[Receiver] Sent encrypted symmetric key (" << encrypted_key.size() << " bytes)\n";
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
          std::this_thread::sleep_for(std::chrono::milliseconds(5000));
          message_id = kMessageIdSymKey;
          [[fallthrough]];
      case kMessageIdSymKey:
          std::cout << "Send symmetric key.\n";
          status = send_symmetric_key(sender_mq, public_key);
          message_id = kMessageIdPeriodic;
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
