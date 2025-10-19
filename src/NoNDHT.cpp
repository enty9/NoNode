#include "NoNDHT.hpp"
#include <cstddef>
#include <cstdint>
#include <future>
#include <ios>
#include <iostream>
#include <opendht.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <fstream>

using namespace std;

void NonDHT::Connect() {
    auto identity = dht::crypto::generateIdentity();
    node.run(port, identity, true);
    node.bootstrap(bootstrap_ip, bootstrap_port);

    cout << "Connected" << endl;
}
void NonDHT::SendInfo(string key, vector<uint8_t> data) {
    string sdat(data.begin(), data.end());
    node.put(key, data);
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