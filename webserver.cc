/**
*************************************************************
* @file webserver.cpp
* @brief Breve descripción
* Pequeña documentación del archivo
*
*
*
*
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 03 abr 2015
* Changelog:
*
*
*
*
* Compilation:
*  $ g++ -g -o webserver webserver.cpp glovehttpserver.cpp glove.o -std=c++11 -lpthread -lcrypto -lssl
*
*************************************************************/

#include "glovehttpserver.h"
#include <iostream>
#include <chrono>
#include <thread>

void hello(GloveHttpRequest &request, GloveHttpResponse& response)
{
  std::cout << "TESTING"<<std::endl;
  response << "This is the response\n";
  response << "This is another tesxt" << std::endl;
}

int main(int argc, char *argv[])
{
  GloveHttpServer serv(8080, "", 2048);

  serv.addVhost("testing");
  serv.addRoute("/hello/$anycon/$anything", hello);
  serv.addRoute("/files/$filename/", GloveHttpServer::fileServer, "testing");
  std::cout << "READY"<<std::endl;
  while(1)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }

  std::cout << "TEST"<<std::endl;

}

