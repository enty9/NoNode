#include <chrono>
#include <cstdint>
#include <iostream>
#include <opendht.h>
#include <thread>
#include <vector>

using namespace std;

dht::DhtRunner node;

int main() {
  
  uint16_t port = 8888;
  auto identity = dht::crypto::generateIdentity();

  node.run(port, identity, true);

  cout << "Start open input on 8888 port" << endl;
  while (true) {
    this_thread::sleep_for(chrono::seconds(30));
  }
  
  node.join();
}