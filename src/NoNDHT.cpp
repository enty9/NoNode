#include "NoNDHT.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <future>
#include <ios>
#include <iostream>
#include <memory>
#include <opendht.h>
#include <opendht/callbacks.h>
#include <opendht/crypto.h>
#include <opendht/infohash.h>
#include <opendht/value.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <fstream>

using namespace std;

void NonDHT::Connect() {
    auto identity = GetCreatyIndentity("Identity.bin");
    node.run(port, identity, true);
    node.bootstrap(bootstrap_ip, bootstrap_port);

    cout << "Connected" << endl;
}
void NonDHT::SendInfo(string key, vector<uint8_t> data) {
    node.put(key, data);
}
void NonDHT::SendSigInfo(string uuid, vector<uint8_t> data) {
    node.putSigned(uuid, data);
}
vector<vector<uint8_t>> NonDHT::GetData(string key) {
    promise<vector<vector<uint8_t>>> promise;
    auto future = promise.get_future();

    node.get(key, [&promise](const vector<shared_ptr<dht::Value>> &values) {
        vector<vector<uint8_t>> all;
        for (auto &vp : values) {
          all.push_back(vp->data);
        }
        promise.set_value(all);

        return false;
  });

  auto results = future.get();
  return results;
}
dht::crypto::Identity NonDHT::GetCreatyIndentity(const string& path){
  if (filesystem::exists(path)) {
    auto identity = dht::crypto::loadIdentity(path);
    return identity;
  } else {
    auto identity = dht::crypto::generateEcIdentity();
    dht::crypto::saveIdentity(identity, path);
    return identity;
  }
}
void NonDHT::SendEncInfo(string key, vector<uint8_t> data, string pass) {
  auto encrypt = dht::crypto::aesEncrypt(data, dht::InfoHash::get(pass).toString());
  vector<uint8_t> d(encrypt.begin(), encrypt.end());
  node.put(key, d);
  cout << "Data send"<< endl;
}
vector<vector<uint8_t>> NonDHT::GetEncInfo(string key, string pass) {
  promise<vector<vector<uint8_t>>> promise;
  auto future = promise.get_future();

  node.get(key, [&promise, pass](const vector<shared_ptr<dht::Value>> &values) {
    vector<vector<uint8_t>> all;
    try{
      for (auto &vp : values) {
        all.push_back(dht::crypto::aesDecrypt(vp->data, dht::InfoHash::get(pass).toString()));
      }
      promise.set_value(all);
    } catch (const exception &e) {
      cerr << "Error:" << e.what() << endl;
    };
    return false;
  });
  auto result = future.get();
  return result;
}
vector<uint8_t> NonDHT::ReadFile(const string &path) {
  ifstream file(path, ios::binary);
  if (!file) throw runtime_error("Dont open file:" + path);
  file.seekg(0, ios::end);
  size_t size = file.tellg();
  file.seekg(0, ios::beg);
  vector<uint8_t> buffer(size);
  file.read(reinterpret_cast<char *>(buffer.data()), size);
  return buffer;
}
void NonDHT::Close() {
  cout << "Close connection" << endl;
  node.join();
}


string FileDetector::detect(const vector<uint8_t> &data) {
  if (data.empty())
    return "unknown";

  for (const auto &[name, signature] : signatures) {
    if (data.size() >= signature.magic.size()) {
      bool match = true;
      for (size_t i = 0; i < signature.magic.size(); ++i) {
        if (data[i] != signature.magic[i]) {
          match = false;
          break;
        }
      }
      if (match)
        return name;
    }
  }

  return "unknown";
}
bool FileDetector::isfile(const vector<uint8_t> &data) {
  return detect(data) != "unknown";
}
void FileDetector::saveFile(const string &path, const vector<uint8_t> &data) {
  ofstream file(path, ios::binary);
  file.write(reinterpret_cast<const char*>(data.data()), data.size());
}