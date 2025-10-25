#include <chrono>
#include <cstdint>
#include <iostream>
#include <opendht.h>
#include <opendht/infohash.h>
#include <opendht/utils.h>
#include <thread>
#include <vector>

using namespace std;

dht::DhtRunner node;

int main() {
  uint16_t port = 8888;
  auto identity = dht::crypto::generateIdentity();
  string data = "Hellos";
  node.run(port, identity, true);

  cout << dht::InfoHash::get(data) << endl;
  cout << "Start open input on 8888 port" << endl;
  while (true) {
    this_thread::sleep_for(chrono::seconds(30));
  }
  
  node.join();
}