#include <array>
#include <boost/asio.hpp>
#include <boost/iostreams/categories.hpp>
#include <boost/system/detail/error_code.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <google/protobuf/message.h>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include "NoNProtocol.hpp"
#include "NoNPacket.pb.h"
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/copy.hpp>

using boost::asio::ip::udp;
using namespace std;

boost::asio::io_context io;

void TNonProto::add_pear(string &host, string &port) {
  udp::resolver res(io);
  auto end = res.resolve(udp::v4(), host, port);

  lock_guard<mutex> lock(peers_mutex);
  for (const auto &e : end) {
    peers.push_back(e);
  }
}

void TNonProto::send_to_all(network::Packet &meesage) {
  lock_guard<mutex> lock(peers_mutex);
  for (const auto &peer : peers) {
    send_message(meesage, peer);
  }
}

void TNonProto::send_to_peer(network::Packet &meesage, string host, string port) {
  udp::resolver resolver(io);
  auto end = resolver.resolve(udp::v4(), host, port);
  for (const auto &e : end) {
    send_message(meesage, e);
  }
}

vector<string> TNonProto::list_peers() const{
  lock_guard<mutex> lock(peers_mutex);
  vector<string> result;
  result.reserve(peers.size());

  for (const auto &peer : peers) {
    result.push_back(peer.address().to_string() + ":" + to_string(peer.port()));
  }

  return result;
}

void TNonProto::start_receive() {
  if(!is_running) return;

  sock.async_receive_from(
      boost::asio::buffer(buffer),
      remot_end,
      [this](boost::system::error_code ec, size_t bytes){
        if(!ec && bytes > 0 && is_running){
          network::Packet pack;
          vector<char> data(buffer.data(), buffer.data() + bytes);
          if (TPacketSerializer::deserialize(data, pack)) {
            m_packetQueue.push(pack);
            if (!has_peer(remot_end)) {
              lock_guard<mutex> lock(peers_mutex);
              peers.push_back(remot_end);
            }
          }
        }
        if (is_running) {
          start_receive();
        }
      }
  );
}

void TNonProto::send_message(network::Packet &message, udp::endpoint end) {
  auto buf = make_shared<vector<char>>(TPacketSerializer::serialize(message));
  sock.async_send_to(
      boost::asio::buffer(*buf),
      end,
      [this, message, end](boost::system::error_code ec, size_t){
        if (ec){
          cerr << "Send Error" << ec.message() << endl;
        }
      }
  );
}

bool TNonProto::has_peer(udp::endpoint end) const {
  lock_guard<mutex> lock(peers_mutex);
  for (const auto &peer : peers) {
    if (peer.address() == end.address() && peer.port() == end.port()) {
      return true;
    }
  }
  return false;
}

vector<char> TPacketSerializer::serialize(const google::protobuf::Message &message) {
  string serialized = message.SerializeAsString();
  vector<char> buff(sizeof(uint32_t) + serialized.size());
  uint32_t size = htonl(static_cast<uint32_t>(serialized.size()));
  memcpy(buff.data(), &size, sizeof(uint32_t));
  memcpy(buff.data() + sizeof(uint32_t), serialized.data(), serialized.size());

  return buff;
}

bool TPacketSerializer::deserialize(const vector<char> &buffer, google::protobuf::Message &message){
  if (buffer.size() < sizeof(uint32_t)) {
    return false;
  }

  uint32_t size;
  memcpy(&size, buffer.data(), sizeof(uint32_t));
  size = ntohl(size);

  if (buffer.size() != sizeof(uint32_t) + size) {
    return false;
  }

  return message.ParseFromArray(buffer.data() + sizeof(uint32_t), size);
}


string terminal(const char *cmd) {
  array<char, 128> buffer;
  string data;

  unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    data += buffer.data();
  }

  return data;
}

Peer TNonProto::getpublicaddres() {
  Peer addres;
  ifstream file("./STUNLIST.txt");
  string lines;

  while (getline(file, lines)) {
    size_t fin = lines.find(':');
    string ip = lines.substr(0, fin);
    string port = lines.substr(fin + 1, -1);

    string com = "./stunclient " + ip + " " + port;
    string retur = terminal(com.c_str());
    size_t st = retur.find(":");
    if (retur.substr(st + 2, 7) == "success") {
      string addr = retur.substr(retur.find('M') + 16, -1);
      string ip = addr.substr(0, addr.find(':'));
      string port = addr.substr(addr.find(':') + 1, -1);

      addres.public_ip = ip;
      addres.public_port = stoi(port);
                           
      break;
    }
  }

  return addres;
};
