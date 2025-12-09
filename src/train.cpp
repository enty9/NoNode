#include <boost/asio.hpp>
#include <exception>
#include <iostream>
#include <openssl/ec.h>
#include <string>
#include <thread>
#include "NoNPacket.pb.h"
#include "NoNProtocol.hpp"
#include "NoNCrypto.hpp"

using namespace std;

int main(int argc, char *argv[]) {
  TNonCrypto crypto;

  auto key = crypto.generatekey();

  string way = "public.pem";
  string ways = "private.pem";
  string password = "hello228!!@??";

  EVP_PKEY_ptr private_key;
  EVP_PKEY_ptr public_key;

  if (crypto.load_private_key(ways, password) != nullptr) {
    crypto.save_public_key(key.get(), way);
    crypto.save_private_key(key.get(), ways, password);
    private_key = crypto.load_private_key(ways, password);
    public_key = crypto.load_public_key(way);
  } else {
    private_key = crypto.load_private_key(ways, password);
    public_key = crypto.load_public_key(way);
  }

  /*
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
  */
}