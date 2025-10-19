#ifndef NONDHT_HPP
#define NONDHT_HPP

#include <iostream>
#include <cstdint>
#include <opendht.h>
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

  private:
    std::map<std::string, Filesignature> signatures;
};

class NonDHT {
    public:
      void Connect();
      void SendInfo(string key, vector<uint8_t> data);
      vector<vector<uint8_t>> GetData(string key);
      vector<uint8_t> ReadFile(const string &path);
      void Close();

    private:
      uint16_t port = 8989;
      string bootstrap_ip = "127.0.0.1";
      string bootstrap_port = "8888";
      dht::DhtRunner node;
};

#endif

