#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>

#include <iostream>

int main() {

   Botan::AutoSeeded_RNG rng;
   const auto key = rng.random_vec(16); // 128 bit random key
   auto data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");

   const auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
   mac->set_key(key);
   mac->update(data);
   const auto tag = mac->final();
   
   std::cout << "The data is: " << Botan::hex_encode(data) << "\n";
   std::cout << "The cmac is: " << Botan::hex_encode(tag) << "\n";

   // Corrupting data
   data.back()++;

   // Verify with corrupted data
   mac->update(data);
   
   // To be able to view the new mac create mac2
   const auto mac2 = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
   mac2->set_key(key);
   mac2->update(data);
   const auto tag2 = mac2->final();
   
   std::cout << "The updated data is: " << Botan::hex_encode(data) << "\n";
   std::cout << "The updated cmac is: " << Botan::hex_encode(tag2) << "\n";
   
   std::cout << "Verification with malformed data: " << (mac->verify_mac(tag) ? "success" : "failure") << "\n";

   return 0;
}
