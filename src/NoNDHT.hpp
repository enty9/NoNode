#ifndef NONDHT_HPP
#define NONDHT_HPP

#include <iostream>
#include <cstdint>
#include <opendht.h>
#include <vector>

using namespace std;

class NonDHT {
    public:
      void Connect();
      void SendInfo(string key, string data);
      vector<string> GetData(string key);
      void Close();

    private:
      uint16_t port = 8989;
      string bootstrap_ip = "127.0.0.1";
      string bootstrap_port = "8888";
      dht::DhtRunner node;
};

#endif

