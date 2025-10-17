#include "NoNDHT.hpp"
#include <cstdint>
#include <future>
#include <iostream>
#include <opendht.h>
#include <string>
#include <vector>

using namespace std;

void NonDHT::Connect() {
    auto identity = dht::crypto::generateIdentity();
    node.run(port, identity, true);
    node.bootstrap(bootstrap_ip, bootstrap_port);

    cout << "Connected" << endl;
}
void NonDHT::SendInfo(string key, string data) {
    vector<uint8_t> sdat(data.begin(), data.end());
    node.put(key, sdat);
    cout << "Data send:" << data << endl; 
}
vector<string> NonDHT::GetData(string key) {
    promise<vector<string>> promise;
    auto future = promise.get_future();
    string datas[] = {};

    node.get(key, [&promise](const vector<shared_ptr<dht::Value>> &values) {
        vector<string> all;
        for (auto &vp : values) {
          all.emplace_back(vp->data.begin(), vp->data.end());
        }
        promise.set_value(all);
        return false;
  });

  auto results = future.get();
  return results;
}
void NonDHT::Close() {
  cout << "Close connection" << endl;
  node.join();
}
