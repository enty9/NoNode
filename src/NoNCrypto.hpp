#ifndef NONCRYPTO_HPP
#define NONCRYPTO_HPP

#include "openssl/evp.h"
#include "openssl/bio.h"
#include "iostream"
#include "vector"
#include <memory>
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
    vector<unsigned char> sign(const EVP_PKEY *key,
                               const vector<unsigned char> &data,
                               const EVP_MD *md = EVP_sha256());
    bool verify(const EVP_PKEY *key, vector<unsigned char> &data,
                vector<unsigned char> &signature,
                const EVP_MD *md = EVP_sha256());
    vector<unsigned char> serialize_public_key(const EVP_PKEY *key);
    EVP_PKEY_ptr deserialize_public_key(vector<unsigned char> *serialized);
    void cleanup() {
      EVP_cleanup();
      ERR_free_strings();
    }
};


#endif