#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>

#include <botan/rsa.h>
#include <botan/pem.h>

#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <vector>

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

auto calculate_mac(std::span<const std::byte> data, Botan::secure_vector<uint8_t>& symmetric_key) {
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
    mac->set_key(symmetric_key);
    mac->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return mac->final();
}

void print_buffer_hex(const std::array<std::byte, kBufferSize>& buffer) {
    std::cout << "0x";
    for (auto b : buffer) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(b);
    }
    std::cout << std::dec;  // reset to decimal
}

int send_public_key(mqd_t mq, const Botan::RSA_PublicKey& public_key)
{
    // Get X.509 SubjectPublicKeyInfo DER
    std::vector<uint8_t> der = public_key.subject_public_key();

    if (der.size() > kMessageSize) {
        std::cerr << "[Sender]Public key too large for message queue\n";
        return kNOT_OK;
    }

    if (mq_send(mq,
                reinterpret_cast<const char*>(der.data()),
                der.size(),
                0) == -1)
    {
        perror("mq_send");
        std::cout << "[Sender] Public key send failed. Press Enter to exit.";
        std::cin.get();
        return kNOT_OK;
    }

    std::cout << "[Sender] Sent public key (" << der.size() << " bytes)\n";
    return kOK;
}


int send_periodic_message(mqd_t mq, Botan::secure_vector<uint8_t>& symmetric_key) {
    // Implementation for sending periodic messages
 
    std::array<std::byte, kBufferSize> buffer{};
    unsigned int status{kOK};

    buffer.fill(kDefaultFillByte);
    std::span<const std::byte> span2 = buffer;

    for (int message_index = 0; message_index < kNumMessagesToSend; ++message_index) {
      // Add a byte counter at the end of the message
      unsigned int value =
          (static_cast<unsigned int>(kInitialByteBase) + (message_index % kByteModulo)) %
          kByteModulo;
      buffer[kBufferSize-1] = static_cast<std::byte>(value);

      // Calculate CMAC for the message
      const auto mac = calculate_mac(buffer, symmetric_key);

      const int send_result =
          mq_send(mq, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0);

      if (send_result == -1) {
        perror("mq_send");
        status = kNOT_OK;
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

    return status;
}

// Receive, decrypt and return symmetric key
int receive_symmetric_key(mqd_t mq, const Botan::RSA_PrivateKey& private_key,
    Botan::secure_vector<uint8_t>& symmetric_key) {

    std::this_thread::sleep_for(std::chrono::milliseconds(4000));
    // Implementation for receiving symmetric key
    std::array<uint8_t, kMessageSize> sym_key_buffer{};

    unsigned int msg_prio;

    const ssize_t bytes_received = mq_receive(
        mq, reinterpret_cast<char*>(sym_key_buffer.data()), sym_key_buffer.size(), &msg_prio);

    if (bytes_received == -1) {
      perror("mq_receive");
      std::cout << "[Sender]Symmetric key receive failed. Press Enter to exit.";
      std::cin.get();
      return kNOT_OK;
    }

    // Decode the RSA encrypted symmetric key using the private key
    Botan::AutoSeeded_RNG rng;
    Botan::PK_Decryptor_EME decryptor(
    private_key,
    rng,
    "RSA/EME-OAEP(SHA-256)");

    symmetric_key = decryptor.decrypt(
        sym_key_buffer.data(),
        static_cast<size_t>(bytes_received));

    std::fill(sym_key_buffer.begin(), sym_key_buffer.end(), 0);  // Clear sensitive data

    std::cout << "[Sender] Received symmetric key (" << symmetric_key.size() << " bytes)\n";
    return kOK;
}

int setup_sender_communication(mqd_t& mq) {

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

int setup_receiver_communication(mqd_t& mq) {

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

int main() {

  // Setup queue for sending
  mqd_t mq;
  if (setup_sender_communication(mq) != kOK) {
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    return kNOT_OK;
  }

  // Open queue for reading
  mqd_t receiver_mq;
  if (setup_receiver_communication(receiver_mq) != kOK) {
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    return kNOT_OK;
  }

  std::cout << "[Sender] Starting sender in 5 seconds...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(4000));
  std::cout << "[Sender] Running...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  std::cout << "\n";
   
  
  // Generate RSA private key (e.g., 2048 bits)
  Botan::AutoSeeded_RNG rng;
  Botan::RSA_PrivateKey private_key(rng, 2048);

  // Extract public key
  Botan::RSA_PublicKey public_key(private_key);

  std::string public_pem = Botan::X509::PEM_encode(public_key);
  std::string private_pem = Botan::X509::PEM_encode(private_key);

  std::cout << private_pem << "\n";
  std::cout << public_pem  << "\n";
  
  Botan::secure_vector<uint8_t> symmetric_key;
  unsigned int message_id{kMessageIdRsaPublicKey};
  unsigned int status{kNOT_OK};
  switch(message_id) {
      case kMessageIdRsaPublicKey:
          std::cout << "[Sender] Send public key.\n";
          status = send_public_key(mq, public_key);
          message_id = kMessageIdSymKey;
          [[fallthrough]];
      case kMessageIdSymKey:
          std::cout << "[Sender] Wait for symmetric key.\n";
          receive_symmetric_key(receiver_mq, private_key, symmetric_key);
          message_id = kMessageIdPeriodic;
          [[fallthrough]];
      case kMessageIdPeriodic:
          std::cout << "[Sender] Send periodic messages.\n";
          status = send_periodic_message(mq, symmetric_key);
          break;
      default:
          std::cout << "Unknown message ID.\n";
          break;
  }

  MqUnlinker unlinkSenderQueue(kSenderQueue);
  MqUnlinker unlinkReceiverQueue(kReceiverQueue);

  mq_close(mq);
  mq_close(receiver_mq);

  // Don't close terminal right away
  std::cout << "Sender done. Press Enter to exit.";
  std::cin.get();
  return status;
}