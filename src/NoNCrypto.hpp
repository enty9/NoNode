#ifndef NONCRYPTO_HPP
#define NONCRYPTO_HPP

#include "NoNPacket.pb.h"
#include "iostream"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "vector"
#include <argon2.h>
#include <cstddef>
#include <ctime>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <string>
#include <vector>

using namespace std;

struct EVP_PKEY_Deleter{void operator()(EVP_PKEY* p){EVP_PKEY_free(p);}};
using EVP_PKEY_ptr = unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

struct EVP_PKEY_CTX_Deleter{void operator()(EVP_PKEY_CTX* p){EVP_PKEY_CTX_free(p);}};
using EVP_PKEY_CTX_ptr = unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;

struct EVP_MD_CTX_Deleter{void operator()(EVP_MD_CTX* p){EVP_MD_CTX_free(p);}};
using EVP_MD_CTX_ptr = unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;

struct BIO_Deleter{void operator()(BIO* p){BIO_free_all(p);}};
using BIO_ptr = unique_ptr<BIO, BIO_Deleter>;

struct EVP_CIPHER_Deleter{void operator()(EVP_CIPHER_CTX* p){EVP_CIPHER_CTX_free(p);}};
using EVP_CIPHER_CTX_ptr = unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_Deleter>;

struct Pck {
  vector<unsigned char> ciphdata;
  EVP_PKEY_ptr eph_key;
  vector<unsigned char> iv;
  time_t time;
  vector<unsigned char> signature;
  vector<unsigned char> salt;
  vector<unsigned char> tag;
};

class TNonCrypto {
public:
   TNonCrypto() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    EVP_PKEY_ptr generatekey(int nid = NID_X9_62_prime256v1);
    void save_private_key(const EVP_PKEY *key, string &filename, string &password);
    void save_public_key(const EVP_PKEY *key, string &filename);
    vector<unsigned char> compute_shared_sector(const EVP_PKEY* private_key, const EVP_PKEY* peer_public_key);
    EVP_PKEY_ptr load_private_key(string &filename, string &password);
    EVP_PKEY_ptr load_public_key(string &filename);
    vector<unsigned char> sign(const EVP_PKEY *prkey,
                               const vector<unsigned char> &data,
                               const EVP_MD *md = EVP_sha256());
    bool verify(const EVP_PKEY *pukey, vector<unsigned char> &data,
                vector<unsigned char> &signature,
                const EVP_MD *md = EVP_sha256());
    vector<unsigned char> serialize_key(const EVP_PKEY *key);
    EVP_PKEY_ptr deserialize_key(vector<unsigned char> *serialized);
    void cleanup() {
      EVP_cleanup();
      ERR_free_strings();
    }
    Pck encrypt(const EVP_PKEY *recipient_pubk,
                            const EVP_PKEY *prkey, vector<unsigned char> &data,
                            int nid = NID_X9_62_prime256v1,
                            network::Types type = network::Types::UNSPECIFIED);
    
    vector<unsigned char> decrypt(const EVP_PKEY *recipient_privk,
                                  const network::Packet data);

    vector<unsigned char> hkdf_derive(const vector<unsigned char> &shared_key,
                                      size_t output_length,
                                      const vector<unsigned char> &salt,
                                      const vector<unsigned char> &info = {},
                                      const EVP_MD* hash_algorithm = EVP_sha256());

    static string hash_password(const string &pswd, vector<unsigned char> salt);
    bool check_password(const string &pswd, const char *encoded);

    vector<unsigned char> generate_rand_byte(size_t len = 16) {
      vector<unsigned char> byte(len);
      RAND_bytes(byte.data(), len);

      return byte;
    }

private:

  vector<unsigned char> get_pubk(const EVP_PKEY *pkey) {
    size_t pub_len = 0;
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len);

    vector<unsigned char> pub_key(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len);

    return pub_key;
  }
};


#endif