#ifndef NONDHT_HPP
#define NONDHT_HPP

#include <iostream>
#include <cstdint>
#include <opendht.h>
#include <opendht/crypto.h>
#include <opendht/infohash.h>
#include <string>
#include <sys/types.h>
#include <vector>

using namespace std;

struct Filesignature {
  vector<uint8_t> magic;
  string extension;
  string mime_type;
};

class FileDetector {
  public:
    FileDetector() {
      signatures["PNG"] = {{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png", "image/png"};
      signatures["JPEG"] = {{0xFF, 0xD8, 0xFF}, "jpg", "image/jpeg"};
      signatures["GIF"] = {{0x47, 0x49, 0x46, 0x38}, "gif", "image/gif"};
    };
    string detect(const vector<uint8_t> &data);
    bool isfile(const vector<uint8_t> &data);
    void saveFile(const string &path, const vector<uint8_t> &data);

  private:
    std::map<std::string, Filesignature> signatures;
};

class NonDHT {
    public:
      NonDHT(string bootstrap_ip, string bootstrap_port, string &path_identity, uint16_t port) {
        auto identity = GetCreatyIndentity(path_identity);
        node.run(port, identity, true);
        node.bootstrap(bootstrap_ip, bootstrap_port);
      }
      ~NonDHT(){
        node.join();
      }
      void SendInfo(string key, vector<uint8_t> data);
      void SendSigInfo(string uuid, vector<uint8_t> data);
      dht::crypto::Identity GetCreatyIndentity(const string& path);
      vector<vector<uint8_t>> GetData(string key);
      vector<uint8_t> ReadFile(const string &path);

    private:
      uint16_t port = 8989;
      string bootstrap_ip = "127.0.0.1";
      string bootstrap_port = "8888";
      dht::DhtRunner node;
};

#endif

