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

void other(GloveHttpRequest &request, GloveHttpResponse& response)
{
  response << "This is an echo server for web sockets\n";
	auto uri = request.getUri().servicehost("ws");
	response << "Try connecting to " << uri <<"/echo/ \n";
}

/* void echoEngine(GloveHttpRequest &request, GloveWebSocketHandler& ws) */
/* { */
/* } */

void echoEngine(GloveHttpRequest &request, GloveHttpResponse& response)
{
  response << "This is an Echo engine for Web Sockets.\n";
	auto uri = request.getUri().servicehost("ws");
	response << "Try connecting to " << uri <<"/echo/ \n";
}

void echoMessage(GloveWebSocketData& data, GloveWebSocketHandler& ws)
{
	if (data.length()>300)
		ws.send("Message too long");
	else
		ws.send("Echo: "+data.data());
}

bool chatmaintenance(GloveWebSocketHandler& ws)
{
}

int main(int argc, char *argv[])
{
  GloveHttpServer serv(8080, "", 2048);

	std::cout << "Timeout: "<<serv.timeout()<<std::endl;
	std::cout << "Keepalive: "<<serv.keepalive_timeout()<<std::endl;

  serv.addWebSocket("/echo/", echoEngine, nullptr, echoMessage);
  serv.addRoute("/websocket_test.js", std::bind(GloveHttpServer::fileServerFixed, std::placeholders::_1, std::placeholders::_2, "websocket_test.js"));
  serv.addRoute("/websocket_test.css", std::bind(GloveHttpServer::fileServerFixed, std::placeholders::_1, std::placeholders::_2, "websocket_test.css"));
  serv.addRoute("/", std::bind(GloveHttpServer::fileServerFixed, std::placeholders::_1, std::placeholders::_2, "websockets.html"));

  std::cout << "READY"<<std::endl;
  while(1)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

