#include <argon2.h>
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

  EVP_PKEY_ptr key = crypto.generatekey();

  EVP_PKEY_ptr herkey = crypto.generatekey();

  string filenam = "private.pem";
  string file = "public.pem";
  string passwd = "8888";

  string d = "hello";
  vector<unsigned char> data(d.begin(), d.end());

  crypto.save_private_key(key.get(), filenam, passwd);
  crypto.save_public_key(key.get(), file);

  EVP_PKEY_ptr privkey = crypto.load_private_key(filenam, passwd);
  EVP_PKEY_ptr pubkey = crypto.load_public_key(file);

  Pck send = crypto.encrypt(pubkey.get(), privkey.get(), data);

  vector<unsigned char> dd = crypto.decrypt(privkey.get(), send);

  string daa(dd.begin(), dd.end());

  cout << daa << endl;
   
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