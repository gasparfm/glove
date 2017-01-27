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

#include "glovehttpclient.hpp"
#include <iostream>
#include <ctime>
#include <vector>
#include <unistd.h>
#include <chrono>

using namespace std;

void res(GloveHttpClientRequest request, GloveHttpClientResponse response)
{
	auto r = response;
	std::cout << "STATUS: "<< r.statusCode() << std::endl;
	for (auto h : r.headers())
		{
			std::cout << "H ("<<h.first<<") : ["<<h.second<<"]\n";
		}
	/* std::cout << r.htmlOutput() << std::endl;		 */
	std::cout << r.firstByte() << std::endl;
}

void errorh(std::string url, GloveException& e)
{
	std::cout << "Error fetching: "<<url<<"("<<e.what()<<")"<<std::endl;
}

int main(int argc, char *argv[])
{
  try
    {
			GloveHttpClient g(res, errorh);
			g.bgrequest("https://facebook.com");
			g.bgrequest("https://gaspar.totaki.com"); /* Needs SNI */
			g.bgrequest("https://totaki.com");
			/* g.bgrequest("http://facebook.com"); */
			g.bgrequest("http://twitter.com");
			/* Just wait */

			std::cout << "Press enter..."<<std::endl;
			int kk;
			cin >> kk;
    } 
  catch (GloveHttpClientException &e)
    {
      cout << "Exception: "<<e.what() << endl;
    }

  return 0;
}

