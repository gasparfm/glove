/**
*************************************************************
* @file example5.cpp
* @brief Breve descripción
*
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 16 ene 2016
* Historial de cambios:
*
*
*
*************************************************************/

#include "glove.hpp"
#include <iostream>

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

std::string FiltroDeSalida(const std::string& s)
{
  return "VA A SALIR ESTO -- "+s+"---\n";
}

std::string FiltroDeEntrada(const std::string& s)
{
  return "ENTRADA FILTRADA -- "+s+"---\n";
}

int main(int argc, char *argv[])
{
  Glove g;
  try
    {
      cout << "Buffer: "<< g.buffer_size(16386)<<endl;
      //      g.timeout_when_data(false);
      g.timeout(0.01);
      g.remove_exceptions(Glove::EXCEPTION_TIMEOUT);
      g.add_filter(Glove::FILTER_OUTPUT, "outFilter", FiltroDeSalida);
      g.add_filter(Glove::FILTER_INPUT, "trim", Trim);
      g.add_filter(Glove::FILTER_INPUT, "myFilter", FiltroDeEntrada);
      g.connect(argv[1], 50000, -1, GLOVE_DEFAULT_DOMAIN, true);
      g<<"Hello, tell me something..."<<endl;
      /* std::string data = g.receive(-1, true); */
      std::string data;
      g >> GloveBase::set_read_once(true) >> data;
      while (1)
	{
	  if (!data.empty())
	    {
	      if (data.substr(0,3)=="FIN")
		break;
	      else
		{
		  data = Trim (data);
		  cout << "Server sent: "<<data<<endl;
		  g<< "Hi: "<<data<<" for you.";
		}
	    }

	  if (GloveBase::select(0, 0, GloveBase::SELECT_READ) == 0)
	    {
	      std::string input;
	      getline(cin, input);
	      g<<input;
	    }

	  g >> GloveBase::set_read_once(true) >> data;
	}
      g.disconnect();
    } 
  catch (GloveException &e)
    {
      cout << "Exception: "<<e.what() << endl;
    }

  return 0;
}
