#include <boost/asio.hpp>
#include <cstddef>
#include <exception>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>
#include "time.h"
#include "NoNPacket.pb.h"
#include "NoNProtocol.hpp"

using namespace std;

int main(int argc, char *argv[]) {

  short port = stoi(argv[1]);
  boost::asio::io_context io;
  TNonProto proto(io, port);

  thread io_thread([&io, &proto] {
    try {
      io.run();
    } catch (exception e){
      cerr << e.what() << endl;
    }
  });

  cout << "Client start" << endl;
  string input;
  while (true) {
    auto data = proto.getData();
    if (data.has_value()) {
      cout << data->data() << endl;
    }
    getline(cin, input);
    if (input == "p") {
      string data = "Hello";
      network::Packet spack;
      spack.set_data(data);
      spack.set_time("1");
      spack.set_type(network::Types::TEXT);

      proto.send_to_peer(spack, "127.0.0.1", "8002");
    } else {
      cout << "Its Not comand" << endl;
      continue;
    }
  }

  io_thread.join();
}