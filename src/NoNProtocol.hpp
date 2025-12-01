#ifndef NONPROTOCOL_HPP
#define NONPROTOCOL_HPP

#include <array>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <google/protobuf/message.h>
#include <iostream>
#include <boost/asio.hpp>
#include <mutex>
#include <string>
#include <vector>
#include "NoNPacket.pb.h"

using namespace std;
using boost::asio::ip::udp;

struct Peer {
  string public_ip;
  short public_port;
};

class TPacketSerializer {
public:
  static vector<char> serialize(const google::protobuf::Message &message);
  static bool deserialize(const vector<char> &buffer, google::protobuf::Message& message);
};

class TNonProto {
    public:
      TNonProto(boost::asio::io_context &io, short port, deque<network::Packet> &packet)
          : io_context(io), sock(io, udp::endpoint(udp::v4(), port)),
            is_running(true) {
            start_receive(packet);
      }
      ~TNonProto() {
        is_running = false;
        sock.close();
      }
      void add_pear(string &host, string &port);
      void send_to_all(network::Packet message);
      void send_to_peer(network::Packet meesage, string host, string port);
      vector<string> list_peers();
      void start_receive(deque<network::Packet> &packet);
      void send_message(network::Packet message, udp::endpoint end);
      bool has_peer(const udp::endpoint end);
      Peer getpublicaddres();
      
    private:
      boost::asio::io_context &io_context;
      udp::socket sock;
      bool is_running;
      char header[sizeof(uint32_t)];
      array<char, 66563> buffer;
      vector<udp::endpoint> peers;
      udp::endpoint remot_end;
};

string terminal(const char *cmd);

#endif