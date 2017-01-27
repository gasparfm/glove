/**
*************************************************************
* @file example1.cpp
* @brief Breve descripción
* Pequeña documentación del archivo
*
*
*
*
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 07 sep 2014
* Historial de cambios:
*
*
*
*
*
*
*
*************************************************************/

#include "glove.hpp"
#include <iostream>
#include <ctime>
#include <vector>
#include <unistd.h>
#include <thread>
#include <chrono>

using namespace std;

const std::string WHITESPACE = " \n\r\t";

std::string TrimLeft(const std::string& s)
{
    size_t startpos = s.find_first_not_of(WHITESPACE);
    return (startpos == std::string::npos) ? "" : s.substr(startpos);
}

std::string TrimRight(const std::string& s)
{
    size_t endpos = s.find_last_not_of(WHITESPACE);
    return (endpos == std::string::npos) ? "" : s.substr(0, endpos+1);
}

std::string Trim(const std::string& s)
{
    return TrimRight(TrimLeft(s));
}

void errorh (Glove::Client &client, int client_id, GloveException &e)
{
  cout << "Client error: "<<e.what()<<endl;
}

int recibo (Glove::Client &client)
{
  string recv;
  client.add_filter(Glove::FILTER_INPUT, "trim", Trim);
  do
    {
      client>>Glove::Client::set_read_once(true)>>Glove::Client::set_exception_on_timeout(false)>>
	recv;
      if (recv!="")
	{
	  cout << "Received: "<<recv<<endl;
	  client<<"Returned "<<recv<<endl;
	}
    } while (recv.substr(0,3)!="BYE");
  client.send("BYE");
  return 0;
}

int main(int argc, char *argv[])
{
  Glove g;

  try
    {
      cout << g.buffer_size(123)<<endl;
      g.max_accepted_clients(10);
      g.accept_wait(2000);
      g.server_error_callback(errorh);
      g.reject_connections(true);
      g.wait_before_reject_connection(2.9);
      g.tmcRejectMessage("Lo siento, hay muchos");
      /* g.serverDisallowIp("192.168.0.0/24"); */
      /* g.serverDisallowFastConnection(10, 2); */
      g.serverAllowIp("192.168.0.0/24");
      g.default_conn_policy(0);
      g.listen(8080, recibo, "", 1);
      cout << "END" << endl;

      while(1)
	{
	  this_thread::sleep_for(chrono::seconds(1));
	  cout << "Clients connected: "<<g.get_connected_clients().size()<<endl;
	  cout << g.debugLoggedConnections()<<endl;
	}
    } 
  catch (GloveException &e)
    {
      cout << "Exception: "<<e.what() << endl;
    }

  return 0;
}

