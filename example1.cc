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

using namespace std;

int main(int argc, char *argv[])
{
  Glove g;
  try
    {
      cout << g.buffer_size(123)<<endl;
      cout << g.buffer_size(321)<<endl;
      g.timeout_when_data(false);
      g.remove_exceptions (Glove::EXCEPTION_DISCONNECTED);
      g.timeout(2);

      vector<Glove::hostinfo> v = Glove::resolveHost(argv[1]);
      for (auto i = v.begin(); i != v.end(); ++i)
      	{
      	  cout << "HOST: "<<i->host<<"; IP: "<<i->ip_address<<endl;
      	}

      g.connect(argv[1], 80);
      g.send("GET / HTTP/1.1\r\n\r\n");

      cout << "SucceSS: "<<g.receive()<<endl;
      g.send("GET / HTTP/1.1\r\n\r\n");
      cout << "END" << endl;
    } 
  catch (GloveException &e)
    {
      cout << "Exception: "<<e.what() << endl;
    }

  return 0;
}

