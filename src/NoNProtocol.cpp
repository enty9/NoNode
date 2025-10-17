#include <boost/asio.hpp>
#include <boost/uuid/random_generator.hpp>
#include <chrono>
#include <codecvt>
#include <openssl/aes.h>
#include <iostream>
#include "vector"
#include "cstdint"
#include "cstring"
#include <cstddef>
#include <cstdint>
#include <string>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "NoNDHT.hpp"
#include <opendht.h>
#include <thread>
#include <vector>

using boost::asio::ip::udp;
using namespace std;

boost::asio::io_context io;

struct Packet {
  uint8_t version;
  uint32_t length;
  uint8_t type;
  string payload;

  enum Type : uint8_t {
    MSG = 1,
    JOIN = 2,
    KICK = 3,
    PING = 4
  };

  vector<uint8_t> serialize() const {
    vector<uint8_t> buffer(6 + payload.size());
    uint32_t net_length = htonl(1 + payload.size());
    memcpy(buffer.data(), &net_length, 4);
    buffer[4] = type;
    memcpy(buffer.data() + 6, payload.data(), payload.size());
    return buffer;
  }

  static Packet parse(const uint8_t *data, size_t size) {
    Packet pkt;
    uint32_t net_length;
    memcpy(&net_length, data, 4);
    pkt.version = 1;
    pkt.length = ntohl(net_length);
    pkt.type = data[4];
    pkt.payload.assign(reinterpret_cast<const char *>(data + 5),
                       pkt.length - 1);
    return pkt;
  }
};

namespace TNonProto {
    void Send() {
        udp::socket socket(io);
    }
    string Generate_Uuid() {
      static boost::uuids::random_generator gen;
      boost::uuids::uuid key = gen();
      return to_string(key);
    }; 
};

int main() {
  NonDHT ndht;

  ndht.Connect();
  ndht.SendInfo("LOH", TNonProto::Generate_Uuid());
  ndht.SendInfo("LOH", TNonProto::Generate_Uuid());
  vector<string> data = ndht.GetData("LOH");

  for (string d : data) {
    cout << d << endl;
  }
  while (true) {
    this_thread::sleep_for(chrono::seconds(60));
  }
  ndht.Close();
}