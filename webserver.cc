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

#include "glovehttpserver.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <zlib.h>
void hello(GloveHttpRequest &request, GloveHttpResponse& response)
{
  std::cout << "TESTING"<<std::endl;
  response << "This is the response\n";
  response << "This is another tesxt" << std::endl;
}

void chatengine(GloveHttpRequest &request, GloveHttpResponse& response)
{
  response << "Chat with me waaraaaanaaaa\n";
}

void chatreceive(GloveWebSocketData& data, GloveWebSocketHandler& ws)
{
	if (data.length()>300)
		ws.send("Message too long");
	else
		ws.send("ECHO: "+data.data());
	/* ws.ping("PINGIO", [] (GloveWebSocketHandler& ws) */
	/* 				{ */
	/* 					std::cout << "EXECUTING CALLBACK\n"; */
	/* 				}); */
}

bool chatmaintenance(GloveWebSocketHandler& ws)
{
}

int main(int argc, char *argv[])
{
  GloveHttpServer serv(8080, "", 2048);

	std::cout << "Compression: "<< serv.compression("deflate") << std::endl;

	std::cout << "Timeout: "<<serv.timeout()<<std::endl;
	std::cout << "Keepalive: "<<serv.keepalive_timeout()<<std::endl;
  serv.addVhost("testing");
	/* Necesitamos callback de inicializacion (chatengine), de recepcion de mensaje, de salida de cliente y de mantenimiento (que se llamara cada cierto tiempo).

	 Mirar si desde client podemos acceder a un ID.*/
  serv.addWebSocket("/chat/", chatengine, nullptr, chatreceive, chatmaintenance);
  serv.addRoute("/hello/$anycon/$anything", hello);
  serv.addRoute("/files/$filename/", GloveHttpServer::fileServer, "testing");
  std::cout << "READY"<<std::endl;
  while(1)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }

  std::cout << "TEST"<<std::endl;

}

