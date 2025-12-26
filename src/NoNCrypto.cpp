#include "NoNCrypto.hpp"
#include "NoNPacket.pb.h"
#include "iostream"
#include "openssl/pem.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <vector>
#include <openssl/kdf.h>
#include <chrono>
#include <ctime>
#include <openssl/kdf.h>
#include <argon2.h>

using namespace std;

// Надо затестить и если че перделать

// Is work
EVP_PKEY_ptr TNonCrypto::generatekey(int nid) {
  try{
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    EVP_PKEY_keygen_init(ctx.get());

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid);
    EVP_PKEY *key = nullptr;
    EVP_PKEY_keygen(ctx.get(), &key);

    return EVP_PKEY_ptr(key);
  } catch (exception e) {
    cout << "Error: " << e.what() << endl;
    return EVP_PKEY_ptr(nullptr);
  }
}
// Is work
void TNonCrypto::save_private_key(const EVP_PKEY *key, string &filename, string &password) {
  if (key == nullptr) throw runtime_error("Failed create file because dont have a key");
  BIO_ptr bio(BIO_new_file(filename.c_str(), "w"));

  if (password.empty()) {
    cout << "Xuy tebe a ne privat key" << endl;
  } else {
    PEM_write_bio_PrivateKey(bio.get(), const_cast<EVP_PKEY *>(key),
                             EVP_aes_256_cbc(),
                             (unsigned char *)password.c_str(),
                             password.length(), nullptr, nullptr);
  }
}
// Is work
void TNonCrypto::save_public_key(const EVP_PKEY *key, string &filename) {
  if (key == nullptr) throw runtime_error("Failed create file because dont have a key");
  BIO_ptr bio(BIO_new_file(filename.c_str(), "w"));

  PEM_write_bio_PUBKEY(bio.get(), const_cast<EVP_PKEY *>(key));
}
// Is work
EVP_PKEY_ptr TNonCrypto::load_private_key(string &filename, string &password) {
  try{
    BIO_ptr bio(BIO_new_file(filename.c_str(), "r"));
    EVP_PKEY *key = nullptr;
    key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr,
                                  (void *)password.c_str());
    return EVP_PKEY_ptr(key);
  } catch (exception e) {
    return EVP_PKEY_ptr(nullptr);
  }
}
// Is work
EVP_PKEY_ptr TNonCrypto::load_public_key(string &filename) {
  try {
    BIO_ptr bio(BIO_new_file(filename.c_str(), "r"));
    EVP_PKEY *key = nullptr;
    key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);

    return EVP_PKEY_ptr(key);
  } catch (exception e) {
    return EVP_PKEY_ptr(nullptr);
  }
}

// Is work
vector<unsigned char> TNonCrypto::sign(const EVP_PKEY *prkey,
                           const vector<unsigned char> &data,
                           const EVP_MD *md) {
  EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
  EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr,
                     const_cast<EVP_PKEY *>(prkey));
  size_t sig_len = 0;
  EVP_DigestSign(ctx.get(), nullptr, &sig_len, data.data(), data.size());

  vector<unsigned char> signature(sig_len);
  EVP_DigestSign(ctx.get(), signature.data(), &sig_len, data.data(),
                 data.size());
  
  signature.resize(sig_len);
  return signature;
}
// Is work
bool TNonCrypto::verify(const EVP_PKEY *pukey, vector<unsigned char> &data,
                        vector<unsigned char> &signature, const EVP_MD *md) {
  EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
  EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr,
                       const_cast<EVP_PKEY *>(pukey));
  int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                data.data(), data.size());
  if (result == 1) {
    return true;
  } else if (result == 0) {
    return false;
  } else {
    throw runtime_error("Error during signature");
  }
}

vector<unsigned char> TNonCrypto::compute_shared_sector(const EVP_PKEY *private_key,
                                            const EVP_PKEY *peer_public_key) {
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(const_cast<EVP_PKEY*>(private_key), NULL));
  EVP_PKEY_derive_init(ctx.get());
  EVP_PKEY_derive_set_peer(ctx.get(), const_cast<EVP_PKEY *>(peer_public_key));
  size_t secret_len = 0;
  EVP_PKEY_derive(ctx.get(), NULL, &secret_len);
  vector<unsigned char> shared_secret(secret_len);
  EVP_PKEY_derive(ctx.get(), shared_secret.data(), &secret_len);

  return shared_secret;
}
// Is work
vector<unsigned char> TNonCrypto::serialize_key(const EVP_PKEY *key) {
  BIO_ptr bio(BIO_new(BIO_s_mem()));
  i2d_PUBKEY_bio(bio.get(), const_cast<EVP_PKEY *>(key));
  BUF_MEM *buf_mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &buf_mem);
  vector<unsigned char> serialized(buf_mem->length);
  memcpy(serialized.data(), buf_mem->data, buf_mem->length);

  return serialized;
}
EVP_PKEY_ptr TNonCrypto::deserialize_key(vector<unsigned char>* serialized){
  BIO_ptr bio(BIO_new_mem_buf(serialized->data(), serialized->size()));
  EVP_PKEY *key = nullptr;
  d2i_PUBKEY_bio(bio.get(), &key);

  return EVP_PKEY_ptr(key);
}
// Is work
Pck TNonCrypto::encrypt(const EVP_PKEY *recipient_pubk,
                                    const EVP_PKEY *prkey,
                                    vector<unsigned char> &data, int nid,
                                    network::Types type) {

  // Generate Ephemeral Key
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
  EVP_PKEY_keygen_init(ctx.get());
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid);
  EVP_PKEY *eph_key = nullptr;
  EVP_PKEY_keygen(ctx.get(), &eph_key);

  // Generate signature
  vector<unsigned char> signature = sign(prkey, data);

  // Generate cipher data
  EVP_CIPHER_CTX_ptr ciptx(EVP_CIPHER_CTX_new());
  vector<unsigned char> cipherdata;
  cipherdata.resize(data.size() + EVP_GCM_TLS_TAG_LEN);

  vector<unsigned char> shared_key = compute_shared_sector(eph_key,
recipient_pubk);

  vector<unsigned char> salt = generate_rand_byte();
  vector<unsigned char> tag(16);
  vector<unsigned char> iv = hkdf_derive(shared_key, 12, salt);
  vector<unsigned char> hkdf_shared_key = hkdf_derive(shared_key, 32,salt);

  int len, cipherdata_len;

  EVP_EncryptInit_ex(ciptx.get(), EVP_aes_256_gcm(), NULL,
                     hkdf_shared_key.data(), iv.data());
  EVP_EncryptUpdate(ciptx.get(), cipherdata.data(), &len, data.data(),
                    data.size());
  cipherdata_len = len;

  EVP_EncryptFinal_ex(ciptx.get(), cipherdata.data() + len, &len);
  cipherdata_len += len;

  EVP_CIPHER_CTX_ctrl(ciptx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());

  auto now = chrono::system_clock::now();
  time_t now_time = chrono::system_clock::to_time_t(now);

  EVP_PKEY_ptr key(eph_key);
  // Compose packet
  Pck pack;
  pack.ciphdata = cipherdata;
  pack.eph_key = move(key);
  pack.iv = iv;
  pack.time = now_time;
  pack.signature = signature;
  pack.salt = salt;
  pack.tag = tag;

  return pack;
}

// Is work
vector<unsigned char> TNonCrypto::hkdf_derive(const vector<unsigned char> &shared_key,
                        size_t output_length, const vector<unsigned char> &salt,
                        const vector<unsigned char> &info,
                        const EVP_MD *hash_algorithm) {

  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL));

  EVP_PKEY_derive_init(ctx.get());
  EVP_PKEY_CTX_set_hkdf_md(ctx.get(), hash_algorithm);
  EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), salt.size());
  EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), shared_key.data(), shared_key.size());
  EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.empty() ? NULL : info.data(), info.size());
  size_t out_len = output_length;
  vector<unsigned char> output_key(out_len);
  EVP_PKEY_derive(ctx.get(), output_key.data(), &out_len);
  output_key.resize(out_len);

  return output_key;
}
// Is work
string TNonCrypto::hash_password(const string &pswd, vector<unsigned char> salt) {
  const uint32_t t_cost = 3;
  const uint32_t m_cost = 1 << 16;
  const uint32_t parallelism = 1;
  const size_t hash_len = 32;

  char encoded[512];
  argon2id_hash_encoded(t_cost, m_cost, parallelism, pswd.data(), pswd.size(),
                        salt.data(), salt.size(), hash_len, encoded,
                        sizeof(encoded));
  
  return string(encoded);
}

bool TNonCrypto::check_password(const string &pswd,
                                const char *encoded) {
  int check = argon2id_verify(encoded, pswd.data(), pswd.size());

  return check == ARGON2_OK;
}