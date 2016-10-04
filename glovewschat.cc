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
#include "glovewebsockets.hpp"
#include <iostream>
#include <chrono>
#include <thread>

bool secure = true;

class SimpleChat
{
public:
	SimpleChat() {}
	~SimpleChat() {}

	void login(GloveHttpRequest &request, GloveWebSocketHandler& ws)
	{
		users.insert({ws.clientId(), { false, "", ws }});
	}

	void message(GloveWebSocketData& data, GloveWebSocketHandler& ws)
	{
		if (data.type() == GloveWebSocketData::INVALID_DATATYPE)
			return;										/* Invalid data type */
		if (data.empty())
			return;										/* No message. No action */
		
		if (data.length()>300)
			{
				ws.send("!1!Message too big!");
				return;
			}
		auto _data = data.data();
		
		if (_data[0]=='/')
			{
				auto space=_data.find(' ');
				auto word = (space!=std::string::npos)?_data.substr(1, space-1):_data;
				auto rest = (space!=std::string::npos)?_data.substr(space+1):"";

				if (word == "name")
					setName(ws, rest);
				else
					ws.send("!0!Invalid command "+word);
			}
		else
			{
				sendMessage(ws, _data);
			}
	}
	
	void setName(GloveWebSocketHandler& ws, std::string name)
	{
		if (name.length()>15)
			name = name.substr(0, 15); /* cut the name! */

		name = trim(name);
		if ( (name.empty()) || (name.find('@') != std::string::npos) )
			{
				ws.send("!4!Invalid user name");
				return;
			}
		
		auto current = users.find(ws.clientId());
		if (name == current->second.username)			/* This MUST exist */
			return;										/* No name change */

		if (nameIsUsed(name))
			{
				ws.send("!2!Your name is being used by other user");
				return;
			}

		current->second.username = name;
		if (!current->second.fullyLoggedIn)
			{
				broadcast("$User "+name+" has logged in");		
			}
		current->second.fullyLoggedIn = true;
		ws.send("$Name changed successfully");
	}

	bool nameIsUsed(std::string& name)
	{
		for (auto u : users)
			{
				if (u.second.username==name)
					return true;
			}
		return false;
	}

	std::string userName(GloveWebSocketHandler& ws)
	{
		auto current = users.find(ws.clientId());
		return current->second.username;
	}
	
	void sendMessage(GloveWebSocketHandler& ws, std::string& message)
	{
		auto username = userName(ws);
		if (username.empty())
			{
				ws.send("!5!User not identified");
				return;				
			}
		
		broadcast(username+"@"+message, ws.clientId());
	}

	bool quit(GloveWebSocketHandler& ws)
	{
		auto user = users.find(ws.clientId());
		std::string username = user->second.username;
		
		users.erase(user);
		if (!username.empty())
			broadcast("$User "+username+" has quit");		
	}
	
private:
	void broadcast(std::string message, unsigned exclude=0)
	{
		for (auto u : users)
			{
				if ( (exclude) && (u.first == exclude) )
					continue;
				
				if (u.second.fullyLoggedIn)
					u.second.handler.send(message);
			}
	}
	
	struct User
	{
		bool fullyLoggedIn;
		std::string username;
		GloveWebSocketHandler& handler;
	};
	std::map < unsigned, User > users;
};

void getChatJs(GloveHttpRequest& request, GloveHttpResponse& response)
{
	std::string filename = "wschat.js";
	std::string extension = fileExtension(filename);
  std::string fileContents = extractFile(filename.c_str());
  if (fileContents.empty())
    {
      response.code(GloveHttpResponseCode::NOT_FOUND);
      return;
    }
	else
		{
			fileContents = string_replace(fileContents, {
					{ "%CHATURL%", request.getUri().servicehost((secure)?"wss":"ws")+"/chat/" }
				});
		}
  response.contentType(GloveHttpServer::getMimeType(extension));
  response << fileContents;
}

void chatEngine(GloveHttpRequest &request, GloveHttpResponse& response)
{
  response << "This is a Chat engine for Web Sockets in C++.\n";
	auto uri = request.getUri().servicehost();
	response << "Try going to " << uri <<"\n";
}

int main(int argc, char *argv[])
{
  GloveHttpServer serv(8080, "", 2048, GLOVE_DEFAULT_BACKLOG_QUEUE, GLOVE_DEFAULT_DOMAIN, GLOVE_DEFAULT_MAX_CLIENTS, GLOVE_DEFAULT_TIMEOUT, GLOVEHTTP_KEEPALIVE_DEFAULT_TIMEOUT, Glove::ENABLE_SSL, "sslserverchain.pem", "sslserver.key");
	SimpleChat chat;
	std::cout << "Timeout: "<<serv.timeout()<<std::endl;
	std::cout << "Keepalive: "<<serv.keepalive_timeout()<<std::endl;
	
  serv.addWebSocket("/chat/", chatEngine,
										std::bind(&SimpleChat::login, &chat, std::placeholders::_1, std::placeholders::_2),
										std::bind(&SimpleChat::message, &chat, std::placeholders::_1, std::placeholders::_2),
										nullptr,
										std::bind(&SimpleChat::quit, &chat, std::placeholders::_1));
  serv.addRoute("/wschat.js", getChatJs);
  serv.addRoute("/wschat.css", std::bind(GloveHttpServer::fileServerFixed, std::placeholders::_1, std::placeholders::_2, "wschat.css"));
  serv.addRoute("/", std::bind(GloveHttpServer::fileServerFixed, std::placeholders::_1, std::placeholders::_2, "wschat.html"));

  std::cout << "READY"<<std::endl;
  while(1)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

