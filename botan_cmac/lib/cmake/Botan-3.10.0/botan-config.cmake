#.rst:
# botan-config.cmake
# -----------
#
# Find the botan library.
#
# This CMake configuration file, installed as part of the Botan build,
# provides support for find_package(Botan).
#
# Required version(s) can be passed as usual:
# find_package(Botan 3.3.0 REQUIRED)
#
# COMPONENTS and OPTIONAL_COMPONENTS can be used to specify Botan
# modules that must or should be enabled in the Botan build:
# find_package(Botan 3.3.0 COMPONENTS rsa ecdsa)
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` targets:
#
# ``botan::botan``
#   The botan shared library, if found.
# ``botan::botan-static``
#   The botan static library, if found.
#
# Previous versions of this CMake module defined the targets in uppercase,
# such as ``Botan::Botan``, for backward-compatibility we define those as
# aliases (if CMake is 3.18 or newer, see GH #5098):
#
# ``Botan::Botan`` as an alias for ``botan::botan``
# ``Botan::Botan-static`` as an alias for ``botan::botan-static``
#
# Result variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   Botan_FOUND          - true if the headers and library were found
#   Botan_VERSION        - library version that was found, if any
#

set(_Botan_supported_components
adler32
aead
aes
aes_crystals_xof
aes_ni
aes_vaes
aes_vperm
argon2
argon2_avx2
argon2_ssse3
argon2fmt
aria
ascon_aead128
ascon_hash256
ascon_perm
ascon_xof128
asn1
auto_rng
base
base32
base58
base64
bcrypt
bcrypt_pbkdf
bigint
bitvector
blake2
blake2mac
blake2s
blinding
block
blowfish
camellia
camellia_gfni
cascade
cast128
cbc
ccm
certstor_flatfile
certstor_sql
certstor_system
cfb
chacha
chacha20poly1305
chacha_avx2
chacha_avx512
chacha_rng
chacha_simd32
checksum
classic_mceliece
cmac
codec
comb4p
compat
cpuid
cpuid_x86
crc24
crc32
cryptobox
cshake_xof
ctr
curve448
des
dh
dilithium
dilithium_aes
dilithium_common
dilithium_round3
dilithium_shake
dl_algo
dl_group
dlies
dsa
dyn_load
eax
ec_group
ecc_key
ecdh
ecdsa
ecgdsa
ecies
eckcdsa
ed25519
ed448
elgamal
eme_oaep
eme_pkcs1
eme_raw
emsa_pkcs1
emsa_pssr
emsa_raw
emsa_x931
enc_padding
entropy
fd_unix
ffi
filters
fpe_fe1
frodokem
frodokem_aes
frodokem_common
gcm
getentropy
ghash
ghash_cpu
ghash_vperm
gmac
gost_28147
gost_3410
gost_3411
hash
hash_id
hex
hkdf
hmac
hmac_drbg
hotp
hss_lms
http_util
hybrid_kem
idea
idea_sse2
iso9796
kdf
kdf1
kdf1_iso18033
kdf2
keccak
keccak_perm
keccak_perm_bmi2
kex_to_kem_adapter
keypair
kmac
kuznyechik
kyber
kyber_90s
kyber_common
kyber_round3
legacy_ec_point
lion
locking_allocator
mac
math
mce
md4
md5
mdx_hash
mem_pool
mgf1
misc
ml_dsa
ml_kem
mode_pad
modes
mp
nist_keywrap
noekeon
noekeon_simd
numbertheory
ocb
ofb
os_utils
par_hash
passhash
passhash9
pbes2
pbkdf
pbkdf2
pcurves
pcurves_brainpool256r1
pcurves_brainpool384r1
pcurves_brainpool512r1
pcurves_frp256v1
pcurves_generic
pcurves_impl
pcurves_numsp512d1
pcurves_secp192r1
pcurves_secp224r1
pcurves_secp256k1
pcurves_secp256r1
pcurves_secp384r1
pcurves_secp521r1
pcurves_sm2p256v1
pem
pgp_s2k
pkcs11
poly1305
poly_dbl
pqcrystals
prf_tls
prf_x942
processor_rng
prov
psk_db
pubkey
raw_hash
rc4
rdseed
rfc3394
rfc6979
rmd160
rng
roughtime
rsa
salsa20
scrypt
seed
serpent
serpent_avx2
serpent_avx512
serpent_simd
sessions_sql
sha1
sha1_avx2
sha1_simd
sha1_x86
sha2_32
sha2_32_avx2
sha2_32_simd
sha2_32_x86
sha2_64
sha2_64_avx2
sha2_64_avx512
sha3
shacal2
shacal2_avx2
shacal2_avx512
shacal2_simd
shacal2_x86
shake
shake_cipher
shake_xof
sig_padding
simd
simd_2x64
simd_4x32
simd_4x64
simd_8x64
simd_avx2
simd_avx512
siphash
siv
skein
slh_dsa_sha2
slh_dsa_shake
sm2
sm3
sm4
sm4_gfni
socket
sodium
sp800_108
sp800_56a
sp800_56c
sphincsplus_common
sphincsplus_sha2
sphincsplus_sha2_base
sphincsplus_shake
sphincsplus_shake_base
sponge
srp6
stateful_rng
stream
streebog
system_rng
thread_utils
threefish_512
tls
tls12
tls13
tls13_pqc
tls_cbc
tree_hash
trunc_hash
tss
twofish
utils
uuid
whirlpool
x25519
x448
x509
x919_mac
xmd
xmss
xof
xts
zfec
zfec_sse2
zfec_vperm

)

unset(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
unset(_Botan_missing_required_modules)

foreach(_comp IN LISTS ${CMAKE_FIND_PACKAGE_NAME}_FIND_COMPONENTS)
  if (NOT _comp IN_LIST _Botan_supported_components)
    set(${CMAKE_FIND_PACKAGE_NAME}_${_comp}_FOUND False)
    if(${CMAKE_FIND_PACKAGE_NAME}_FIND_REQUIRED_${_comp})
      list(APPEND _Botan_missing_required_modules ${_comp})
    endif()
  else()
    set(${CMAKE_FIND_PACKAGE_NAME}_${_comp}_FOUND True)
  endif()
endforeach()

if(_Botan_missing_required_modules)
  set(${CMAKE_FIND_PACKAGE_NAME}_FOUND False)
  list(JOIN _Botan_missing_required_modules ", " _missing_modules)
  set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Unsupported module(s): ${_missing_modules}")
endif()

if(DEFINED ${CMAKE_FIND_PACKAGE_NAME}_FOUND AND NOT ${${CMAKE_FIND_PACKAGE_NAME}_FOUND})
  return()
endif()

# botan-config.cmake lives in "${_Botan_PREFIX}/lib[/<arch_dir>]/cmake/Botan-X"
# traverse up and derive ${_Botan_LIB_PREFIX} and ${_Botan_INCLUDE_DIR} accordingly.
get_filename_component(_Botan_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
if(EXISTS ${_Botan_PREFIX}/include/botan-3)
  set(_Botan_INCLUDE_DIR "${_Botan_PREFIX}/include/botan-3")
  if(NOT DEFINED _Botan_LIB_PREFIX)
    if(EXISTS ${_Botan_PREFIX}/lib/libbotan-3.a)
      set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib")
    elseif(EXISTS ${_Botan_PREFIX}/lib64/libbotan-3.a)
      set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib64")
    endif()
  endif()
  if(NOT DEFINED _Botan_LIB_PREFIX)
    if(EXISTS ${_Botan_PREFIX}/lib/libbotan-3.so.10)
      set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib")
    elseif(EXISTS ${_Botan_PREFIX}/lib64/libbotan-3.so.10)
      set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib64")
    endif()
  endif()
elseif(DEFINED CMAKE_LIBRARY_ARCHITECTURE)
  # likely we have to traverse out of a debian-style multiarch path
  get_filename_component(_Botan_PREFIX "${_Botan_PREFIX}" DIRECTORY)
  if(EXISTS "${_Botan_PREFIX}/include/botan-3")
    set(_Botan_INCLUDE_DIR "${_Botan_PREFIX}/include/botan-3")

    if(NOT DEFINED _Botan_LIB_PREFIX)
      if(EXISTS ${_Botan_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE}/libbotan-3.a)
        set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
      elseif(EXISTS ${_Botan_PREFIX}/lib64/${CMAKE_LIBRARY_ARCHITECTURE}/libbotan-3.a)
        set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib64/${CMAKE_LIBRARY_ARCHITECTURE}")
      endif()
    endif()
    if(NOT DEFINED _Botan_LIB_PREFIX)
      if(EXISTS ${_Botan_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE}/libbotan-3.so.10)
        set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
      elseif(EXISTS ${_Botan_PREFIX}/lib64/${CMAKE_LIBRARY_ARCHITECTURE}/libbotan-3.so.10)
        set(_Botan_LIB_PREFIX "${_Botan_PREFIX}/lib64/${CMAKE_LIBRARY_ARCHITECTURE}")
      endif()
    endif()
  endif()
endif()

if(NOT DEFINED _Botan_INCLUDE_DIR OR NOT DEFINED _Botan_LIB_PREFIX)
  set(${CMAKE_FIND_PACKAGE_NAME}_FOUND False)
  set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Failed to locate installation paths, please consider opening a bug report with details about your setup.")
  return()
endif()

if(NOT TARGET botan::botan-static)
  add_library(botan::botan-static STATIC IMPORTED)
  set_target_properties(botan::botan-static
    PROPERTIES
      IMPORTED_LOCATION                 "${_Botan_LIB_PREFIX}/libbotan-3.a"
      INTERFACE_INCLUDE_DIRECTORIES     "${_Botan_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "CXX"
      INTERFACE_LINK_OPTIONS            "SHELL:-fstack-protector -m64 -pthread")

  # TODO(Botan4): Remove this alias
  if(NOT ${CMAKE_VERSION} VERSION_LESS "3.18.0") # 3.18 allows creating ALIAS targets to non-GLOBAL targets
    add_library(Botan::Botan-static ALIAS botan::botan-static)
  endif()
endif()

set(_Botan_implib "")

if(NOT TARGET botan::botan)
  if(NOT DEFINED _Botan_shared_lib)
    set(_Botan_shared_lib "${_Botan_LIB_PREFIX}/libbotan-3.so.10")
  endif()

  add_library(botan::botan SHARED IMPORTED)
  set_target_properties(botan::botan
    PROPERTIES
      IMPORTED_LOCATION             "${_Botan_shared_lib}"
      IMPORTED_IMPLIB               "${_Botan_implib}"
      INTERFACE_INCLUDE_DIRECTORIES "${_Botan_INCLUDE_DIR}"
      INTERFACE_LINK_OPTIONS        "SHELL:-fstack-protector -m64 -pthread")
  set_property(TARGET botan::botan APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
  set_target_properties(botan::botan
    PROPERTIES
      IMPORTED_LOCATION_NOCONFIG "${_Botan_LIB_PREFIX}/libbotan-3.so.10"
      IMPORTED_SONAME_NOCONFIG   "libbotan-3.so.10"
      IMPORTED_IMPLIB_NOCONFIG   "${_Botan_implib}")

  # TODO(Botan4): Remove this alias
  if(NOT ${CMAKE_VERSION} VERSION_LESS "3.18.0") # 3.18 allows creating ALIAS targets to non-GLOBAL targets
    add_library(Botan::Botan ALIAS botan::botan)
  endif()
endif()

set(${CMAKE_FIND_PACKAGE_NAME}_FOUND True)
