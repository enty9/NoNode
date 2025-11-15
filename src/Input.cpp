#include <boost/asio.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <opendht.h>
#include <opendht/infohash.h>
#include <opendht/utils.h>
#include <string>
#include <thread>

using namespace std;

dht::DhtRunner node;

int main() {
  uint16_t port = 8888;
  auto identity = dht::crypto::generateIdentity();
  string data = "Hellos";
  node.run(port, identity, true);
  static boost::uuids::random_generator en;
  static boost::uuids::uuid key = en();

  string ey = to_string(key);

  cout << node.getId() << endl;
  cout << ey << endl;

  cout << "Start open input on 8888 port" << endl;
  while (true) {
    this_thread::sleep_for(chrono::seconds(30));
  }
  
  node.join();
}