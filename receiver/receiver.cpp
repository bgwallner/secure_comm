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
    std::cout << "[Receiver] 0x";
    for (size_t i = 0; i < received_bytes; ++i) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(buffer[i]);
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
}

void print_vector_hex(const std::vector<uint8_t>& vec) {
    std::cout << "[Receiver] 0x";
    for (const auto& byte : vec) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
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
    std::cout << "[Receiver] The received public key raw data: \n";
    print_buffer_hex(pub_key_buffer, received_bytes);
    std::cout << "\n";

    Botan::DataSource_Memory ds(
        reinterpret_cast<const uint8_t*>(pub_key_buffer.data()),
        received_bytes
    );

    public_key = Botan::X509::load_key(ds);

    // Ensure it is RSA
    auto* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    if (!rsa) {
        std::cerr << "[Receiver] Received key is not an RSA public key\n";
        return kNOT_OK;
    }

    std::string pem = Botan::X509::PEM_encode(*public_key);
    std::cout << "[Receiver] Received RSA Public Key in PEM format:\n";
    std::cout << "\n";
    std::cout << pem << std::endl;

    return kOK;
}

int send_symmetric_key(mqd_t mq, std::unique_ptr<Botan::Public_Key>& public_key, 
  std::vector<uint8_t>& symmetric_key) {
    Botan::AutoSeeded_RNG rng;

    // Generate a random symmetric key (e.g., 16 bytes for AES-128)
    rng.randomize(symmetric_key.data(), symmetric_key.size());
    std::cout << "[Receiver] Derived symmetric key:\n";
    print_vector_hex(symmetric_key);
    std::cout << "\n";

    // Encrypt the symmetric key using the received RSA public key
    Botan::RSA_PublicKey* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    Botan::PK_Encryptor_EME encryptor(*rsa, rng, "EME1(SHA-256)");
    std::vector<uint8_t> encrypted_key = encryptor.encrypt(symmetric_key, rng);
    std::cout << "[Receiver] Encrypted symmetric key with RSA public key:\n";
    print_vector_hex(encrypted_key);
    std::cout << "\n";


    // Calculate CMAC of the encrypted key
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
    mac->set_key(symmetric_key);
    mac->update(reinterpret_cast<const uint8_t*>(encrypted_key.data()), encrypted_key.size());
    mac->final();
    std::string mac_hex = Botan::hex_encode(mac->final());
    std::cout << "[Receiver] Calculated CMAC of the encrypted symmetric key:\n";
    std::cout << "[Receiver] 0x" << mac_hex << "\n";
    std::cout << "\n";

    // Concatenate CMAC to the encrypted key
    const auto mac_output = mac->final();
    encrypted_key.insert(encrypted_key.end(), mac_output.begin(), mac_output.end());
    std::cout << "[Receiver] Encrypted symmetric key with appended CMAC:\n";
    print_vector_hex(encrypted_key);
    std::cout << "\n";

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
          print_buffer_hex(buffer, received_bytes);
        } else {
          perror("mq_receive");
          break;
        }
    }
    return kOK;
}

int setup_sender_communication(mqd_t& mq) {

  mq_attr queue_attr{};
  queue_attr.mq_flags = 0;
  queue_attr.mq_maxmsg = kMaxMessages;
  queue_attr.mq_msgsize = kMessageSize;

  mq =
    mq_open(kSenderToReceiverQueue.data(), O_CREAT | O_RDWR, kQueuePermissions, &queue_attr);
    if (mq == static_cast<mqd_t>(-1)) {
      perror("mq_open - queue for sending could not open");
      return kNOT_OK;
    }
    return kOK;
}

int setup_receiver_communication(mqd_t& mq) {

  mq_attr queue_attr{};
  queue_attr.mq_flags = 0;
  queue_attr.mq_maxmsg = kMaxMessages;
  queue_attr.mq_msgsize = kMessageSize;

  mq =
    mq_open(kReceiverToSenderQueue.data(), O_CREAT | O_RDWR, kQueuePermissions, &queue_attr);
    if (mq == static_cast<mqd_t>(-1)) {
      perror("mq_open - queue for receiving could not open");
      return kNOT_OK;
    }
    return kOK;
}

int main() {

  // Open for reading from sender queue
  mqd_t mq_receiver_to_sender;
  if (setup_receiver_communication(mq_receiver_to_sender) != kOK) {
      return kNOT_OK;
  }

  // Set up queue for sending
  mqd_t mq_sender_to_receiver;
  if (setup_sender_communication(mq_sender_to_receiver) != kOK) {
      return kNOT_OK;
  }

  std::cout << "[Receiver] Starting receiver in 5 seconds...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(4000));
  std::cout << "[Receiver] Running...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  std::cout << "\n";

  unsigned int message_id{kMessageIdRsaPublicKey};
  unsigned int status{kNOT_OK};
  std::unique_ptr<Botan::Public_Key> public_key;
  std::vector<uint8_t> symmetric_key(16);
  switch(message_id) {
      case kMessageIdRsaPublicKey:
          std::cout << "[Receiver] Receive public key ->\n";
          status = get_public_key(mq_sender_to_receiver, public_key);
          message_id = kMessageIdSymKey;
          [[fallthrough]];
      case kMessageIdSymKey:
          std::cout << "[Receiver] Send symmetric key ->\n";
          status = send_symmetric_key(mq_receiver_to_sender, public_key, symmetric_key);
          message_id = kMessageIdPeriodic;
          [[fallthrough]];
      case kMessageIdPeriodic:
          std::cout << "[Receiver] Receive periodic messages ->\n";
          status = receive_periodic_messages(mq_sender_to_receiver);
          break;
      default:
          std::cout << "Unknown message ID.\n";
          break;
  }

  // Don't close terminal right away
  std::cout << "Receiver done. Press Enter to exit.";
  std::cin.get();

  mq_close(mq_receiver_to_sender);
  mq_close(mq_sender_to_receiver);
  return status;
}
