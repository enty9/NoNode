#ifndef NONPROTOCOL_HPP
#define NONPROTOCOL_HPP

#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
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

class PacketQueue{
  public:
    void push(network::Packet packet){
      {
      lock_guard<mutex> lock(m_mutex);
      m_queue.push_back(move(packet));
      }
      if(m_callback){
        m_callback();
      }
    }

    bool tryPop(network::Packet& packet){
      lock_guard<mutex> lock(m_mutex);
      if(m_queue.empty()) return false;
      packet = move(m_queue.front());
      m_queue.pop_front();
      return true;
    }

    size_t size() const{
      lock_guard<mutex> lock(m_mutex);
      return m_queue.size();
    }

    void setCallback(function<void()> callback){
      m_callback = callback;
    }

    bool empty() const {
      lock_guard<mutex> lock(m_mutex);
      return m_queue.empty();
    }
  
  private:
    mutable mutex m_mutex;
    deque<network::Packet> m_queue;
    function<void()> m_callback;
};

class TPacketSerializer {
public:
  static vector<char> serialize(const google::protobuf::Message &message);
  static bool deserialize(const vector<char> &buffer, google::protobuf::Message& message);
};

class TNonProto {
    public:
      TNonProto(boost::asio::io_context &io, short port, PacketQueue &PacketQueue)
          : io_context(io), sock(io, udp::endpoint(udp::v4(), port)),
            m_packetQueue(PacketQueue),is_running(true) {
            start_receive();
      }
      ~TNonProto() {
        is_running = false;
        sock.close();
      }
      void add_pear(string &host, string &port);
      void send_to_all(network::Packet &message);
      void send_to_peer(network::Packet &meesage, string host, string port);
      vector<string> list_peers() const;
      void start_receive();
      void send_message(network::Packet &message, udp::endpoint end);
      bool has_peer(const udp::endpoint end) const;
      Peer getpublicaddres();
      
    private:
      boost::asio::io_context &io_context;
      udp::socket sock;
      PacketQueue &m_packetQueue;
      bool is_running;
      char header[sizeof(uint32_t)];
      array<char, 66563> buffer;
      vector<udp::endpoint> peers;
      mutable mutex peers_mutex;
      udp::endpoint remot_end;
};

string terminal(const char *cmd);

#endif