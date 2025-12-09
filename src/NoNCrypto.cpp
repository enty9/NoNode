#include "NoNCrypto.hpp"
#include "NoNPacket.pb.h"
#include "iostream"
#include "openssl/pem.h"
#include <cstddef>
#include <cstring>
#include <exception>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <vector>

using namespace std;

// Все или почти все надо переделать и добавить HKDF

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
void TNonCrypto::save_public_key(const EVP_PKEY *key, string &filename) {
  if (key == nullptr) throw runtime_error("Failed create file because dont have a key");
  BIO_ptr bio(BIO_new_file(filename.c_str(), "w"));

  PEM_write_bio_PUBKEY(bio.get(), const_cast<EVP_PKEY *>(key));
}

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
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(const_cast<EVP_PKEY*>(private_key), nullptr));
  EVP_PKEY_derive_init(ctx.get());
  EVP_PKEY_derive_set_peer(ctx.get(), const_cast<EVP_PKEY *>(peer_public_key));
  size_t secret_len = 0;
  EVP_PKEY_derive(ctx.get(), nullptr, &secret_len);
  vector<unsigned char> shared_secret(secret_len);
  EVP_PKEY_derive(ctx.get(), shared_secret.data(), &secret_len);

  return shared_secret;
}

vector<unsigned char> TNonCrypto::serialize_public_key(const EVP_PKEY *key) {
  BIO_ptr bio(BIO_new(BIO_s_mem()));
  i2d_PUBKEY_bio(bio.get(), const_cast<EVP_PKEY *>(key));
  BUF_MEM *buf_mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &buf_mem);
  vector<unsigned char> serialized(buf_mem->length);
  memcpy(serialized.data(), buf_mem->data, buf_mem->length);

  return serialized;
}
EVP_PKEY_ptr TNonCrypto::deserialize_public_key(vector<unsigned char>* serialized){
  BIO_ptr bio(BIO_new_mem_buf(serialized->data(), serialized->size()));
  EVP_PKEY *key = nullptr;
  d2i_PUBKEY_bio(bio.get(), &key);

  return EVP_PKEY_ptr(key);
}

network::Packet TNonCrypto::encrypt(const EVP_PKEY *recipient_pubk,
                                    const EVP_PKEY *prkey,
                                    vector<unsigned char> &data, int nid) {
  network::Packet pack;
  EVP_PKEY *eph_key;

  EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());

  EVP_PKEY_CTX_ptr kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
  EVP_PKEY_keygen_init(kctx.get());
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), nid);
  EVP_PKEY_keygen(kctx.get(), &eph_key);

  vector<unsigned char> cipherdata;
  cipherdata.resize(data.size() + EVP_MAX_BLOCK_LENGTH);

  vector<unsigned char> signature = sign(prkey, data);
  vector<unsigned char> iv = generate_rand_byte(12);

  vector<unsigned char> shared_key = compute_shared_sector(eph_key, recipient_pubk);

  int len, cipherdata_len;

  try {
    EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, shared_key.data(), iv.data());
    EVP_EncryptUpdate(ctx.get(), cipherdata.data(), &len, data.data(), data.size());
    cipherdata_len = len;
    EVP_EncryptFinal_ex(ctx.get(), cipherdata.data() + len, &len);
    cipherdata_len += len;
    cipherdata.resize(cipherdata_len);

    network::Data data;

  } catch (exception e) {
    cout << "Error:" << e.what() << endl;

  }

  EVP_PKEY_free(eph_key);


  return pack;
}
