#include <argon2.h>
#include <boost/asio.hpp>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <openssl/ec.h>
#include <ostream>
#include <string>
#include <thread>
#include <vector>
#include "NoNCrypto.hpp"
#include "NoNPacket.pb.h"
#include "NoNProtocol.hpp"

using namespace std;

int main(int argc, char *argv[]) {
  TNonCrypto crypto;

  EVP_PKEY_ptr key = crypto.generatekey();

  crypto.save_private_key(key.get(), "privat.pem", "Hello");
  crypto.save_public_key(key.get(), "public.pem");

  EVP_PKEY_ptr privkey = crypto.load_private_key("privat.pem", "Hello");
  EVP_PKEY_ptr pubkey = crypto.load_public_key("public.pem");

  deque<network::Packet> rec_pck;
  short port = stoi(argv[1]);
  boost::asio::io_context io;
  TNonProto proto(io, port, rec_pck);

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
    getline(cin, input);
    if (input == "p") {
      string data = "Hello lol";
      network::Packet spack;
      proto.send_to_peer(spack, "127.0.0.1", "8002");
    } else {
      cout << "Its Not comand" << endl;
      continue;
    }
  }

  io_thread.join();

  crypto.cleanup();
}