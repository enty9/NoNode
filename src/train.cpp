#include <boost/asio.hpp>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <openssl/ec.h>
#include <ostream>
#include <string>
#include <thread>
#include <vector>
#include "NoNCrypto.hpp"

using namespace std;

int main(int argc, char *argv[]) {
  TNonCrypto crypto;

  auto key = crypto.generatekey();

  string way = "public.pem";
  string ways = "private.pem";
  string password = "hello228!!@??";

  string data = "Hello";
  vector<unsigned char> bytes(data.begin(), data.end());

  EVP_PKEY_ptr privkey;
  EVP_PKEY_ptr pubkey;

  crypto.save_public_key(key.get(), way);
  crypto.save_private_key(key.get(), ways, password);

  privkey = crypto.load_private_key(ways, password);
  pubkey = crypto.load_public_key(way);

  Pck ret = crypto.encrypt(pubkey.get(), privkey.get(), bytes);

  cout << ret.ciphdata.data() << ":" << ret.ciphdata.size() << endl;

  system("rm -f train public.pem private.pem");
  crypto.cleanup();
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