/**
*************************************************************
* @file glove.cpp
* @brief Tiny and standalone TCP socket C++11 wrapper
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 07 ago 2014
*
* Notes:
*  - Some ideas borrowed from some projects I've made in the past.
*  - Some code borrowed from r-lyeh's knot ( https://github.com/r-lyeh/knot )
*
* Changelog:
*  20140807 : Begin this project
*  20140908 : Now, it can be a server
*  20140913 : Created GloveBase, deleted Util namespace and duplicated code
*  20140914 : Some bugfixing and Glove constructors
*  20140919 : build_uri(), better test_connected()
*  20140923 : get_from_uri() - The unmaintainable!
*
* To-do:
*  1 - Some more documentation
*  2 - epoll support
*  6 - be able to connect with protocol/service names
*  7 - set_option(...) allowing a variadic template to set every client or server option
*  8 - allowed client list (IPs list with allowed clients)
*  9 - logger callback
* 10 - test_connected fussion with is_connected()
* 15 - Winsock support (far far in the future)
*
* MIT Licensed:
* Copyright (c) 2014 Gaspar Fernández
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* 
*************************************************************/

#include "glove.hpp"
#include <cstdlib>
#include <cstring> // memset(), strerror()
#include <iostream> // debug only
#include <arpa/inet.h>
#include <netinet/tcp.h> // TCP_NODELAY 
#include <thread>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define INIT()                    
#define SOCKET(A,B,C)             ::socket((A),(B),(C))
#define ACCEPT(A,B,C)             ::accept((A),(B),(C))
#define CONNECT(A,B,C)            ::connect((A),(B),(C))
#define CLOSE(A)                  ::close((A))
#define READ(A,B,C)               ::read((A),(B),(C))
#define RECV(A,B,C,D)             ::recv((A), (void *)(B), (C), (D))
#define SELECT(A,B,C,D,E)         ::select((A),(B),(C),(D),(E))
#define SEND(A,B,C,D)             ::send((A), (const char *)(B), (C), (D))
#define WRITE(A,B,C)              ::write((A),(B),(C))
#define GETSOCKOPT(A,B,C,D,E)     ::getsockopt((int)(A),(int)(B),(int)(C),(      void *)(D),(socklen_t *)(E))
#define SETSOCKOPT(A,B,C,D,E)     ::setsockopt((int)(A),(int)(B),(int)(C),(const void *)(D),(socklen_t)(E))

#define BIND(A,B,C)               ::bind((A),(B),(C))
#define LISTEN(A,B)               ::listen((A),(B))
#define SHUTDOWN(A,B)             ::shutdown((A),(B))


const char* GloveBase::CRLF = "\r\n";

namespace
{
enum
  {
    TCP_OK = 0,
    TCP_ERROR = -1,
    TCP_TIMEOUT = -2
  };

  static timeval as_timeval ( double seconds )
  {
    timeval tv;
    tv.tv_sec = (int)(seconds);
    tv.tv_usec = (int)((seconds - (int)(seconds)) * 1000000.0);
    return tv;
  }

  char* __itoa(int val, char* buf)
  {
    int i = 10;
    for(; val && i ; --i, val /= 10)
      {
  	buf[i] = "0123456789"[val % 10];
      }

    return &buf[i+1];
  }

};

void GloveBase::setsockopt(int level, int optname, void *optval, socklen_t optlen)
{
  if (SETSOCKOPT(sockfd, level, optname, optval, optlen) < 0)
    throw GloveException(14, append_errno("Failed to set option on socket: "));
}

void GloveBase::getsockopt(int level, int optname, void *optval, socklen_t *optlen)
{
  if (GETSOCKOPT(sockfd, level, optname, optval, optlen) < 0)
    throw GloveException(15, append_errno("Failed to get option on socket: "));
}

int GloveBase::get_integer_sockopts_level(int optname)
{
  switch (optname)
    {
    case SO_KEEPALIVE:
    case SO_REUSEADDR:
      return SOL_SOCKET;
    default:
      throw GloveException(16, "Unrecognised socket option, or it does not accepts int");
    }
}

void GloveBase::setsockopt(int optname, int val)
{
  int level = get_integer_sockopts_level(optname);

  setsockopt(level, optname, &val, sizeof(val));
}

void GloveBase::getsockopt(int optname, int &val)
{
  socklen_t val_len = sizeof(val);
  int level = get_integer_sockopts_level(optname);

  getsockopt(level, optname, &val, &val_len);
}

void GloveBase::register_dtm()
{
  start_dtm = std::chrono::system_clock::now();
}

std::string GloveBase::append_errno(std::string message)
{
  return message +std::string(strerror(errno));
}

int GloveBase::select(const double timeout, int test)
{
    // set up the file descriptor set
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    fd_set *rset=NULL, *wset=NULL;

    // set up the struct timeval for the timeout
    timeval tv = as_timeval( timeout );

    if (test & SELECT_READ)
      rset=&fds;

    if (test & SELECT_WRITE)
      wset=&fds;

    // wait until timeout or data received
    // if  tv = {n,m}, then select() waits up to n.m seconds
    // if  tv = {0,0}, then select() does polling
    // if &tv =  NULL, then select() waits forever
    int ret = SELECT(sockfd+1, rset, wset, NULL, &tv);

    return ( ret == -1 ? sockfd = -1, TCP_ERROR : ret == 0 ? TCP_TIMEOUT : TCP_OK );
}

void GloveBase::_send(const std::string &data)
{
  std::string out = run_filters(FILTER_OUTPUT, data);

  int bytes_sent;
  do
    {
      // msg_nosignal avoid systems signals
      bytes_sent = SEND( sockfd, out.c_str(), out.size(), MSG_NOSIGNAL);
      if (bytes_sent == -1)
	{
	  throw GloveException(6, append_errno("Socket error when sending: "));
	}

      out = out.substr ( bytes_sent );
    }
  while (out.size() > 0);
}

std::string GloveBase::_receive_fixed(const size_t size, double timeout, const bool timeout_when_data, size_t _buffer_size, short _read_once, bool exception_on_timeout)
{
  std::string in;
  int bytes_received;
  size_t requested_size=size;
  if (timeout==-1)
    timeout = default_values.timeout;

  bool read_once = (_read_once == -1)?default_values.read_once:_read_once;

  do
    {
      int error;
      if ( (timeout > 0.0) && ( ( ( error= select(timeout) ) != TCP_OK) ) ) 
	{
	  if (error == TCP_TIMEOUT)
	    {
	      if ( (!exception_on_timeout) || ( (in.length()>0) && (!timeout_when_data) && (size==0) ) )
		break;	// Sometimes we don't want to return an exception here.
	      // But, we must have low timeout.
	      // Not when fixed
	      else
		throw GloveException(7, "Timed out while receiving data");
	    }
	  else
	    throw GloveException(8, append_errno("Error while waiting for data: "));
	}

      int __buffer_size = (size>0)?((requested_size>_buffer_size)?_buffer_size:requested_size):_buffer_size;

      std::string buffer(__buffer_size, '\0');

      bytes_received = RECV (sockfd, &buffer[0], buffer.size(), 0);

      if (bytes_received < 0)
	throw GloveException(9, append_errno("Error receiving data: "));

      if (bytes_received == 0)
	{
	  if (default_values.exceptions & EXCEPTION_DISCONNECTED)
	    throw GloveException(100, "Peer shutdown");
	  else
	    break;
	}
      // return in;

      requested_size-=bytes_received;

      in +=buffer.substr(0, bytes_received);

      if (size>0)
	{
	  requested_size-=bytes_received;
	  if (requested_size<=0)
	    break;
	}
    }
  while ( (requested_size > 0) && (!read_once) );

  return run_filters(FILTER_INPUT, in);
}

  void GloveBase::add_filter(GloveBase::filter_type type, std::string name, GloveBase::filter_callback filter, std::string option, std::string value)
{
  auto& filter_vector = (type==FILTER_INPUT)?input_filters:output_filters;

  if (option=="start" || option=="beginning")
    filter_vector.insert(filter_vector.begin(), {name, filter});
  else if (option == "before")
    {
      for (auto it = filter_vector.begin(); it!= filter_vector.end(); ++it)
	{
	  if (it->name == value)
	    {
	      filter_vector.insert(it, {name, filter});
	      return;
	    }
	}
    }
  else
    filter_vector.push_back({name, filter});
}

bool GloveBase::remove_filter(GloveBase::filter_type type, std::string name)
{
  auto& filter_vector = (type==FILTER_INPUT)?input_filters:output_filters;

  for(auto it = filter_vector.begin(); it != filter_vector.end(); ++it)
    if (it->name == name)
      {
	filter_vector.erase(it);
	return true;
      }
  // false not removed
  return false;
}

std::vector<std::string> GloveBase::get_filters(GloveBase::filter_type type)
{
  auto& filter_vector = (type==FILTER_INPUT)?input_filters:output_filters;

  std::vector <std::string> out;
  for(auto it = filter_vector.begin(); it != filter_vector.end(); ++it)
    out.push_back(it->name);

  return out;
}

std::string GloveBase::run_filters(GloveBase::filter_type type, const std::string &_input)
{
  if ( (type == FILTER_INPUT) && (!default_values.enable_input_filters) )
    return _input;
  else if ( (type == FILTER_OUTPUT) && (!default_values.enable_output_filters) )
    return _input;

  std::string input = _input;
  auto& filter_vector = (type==FILTER_INPUT)?input_filters:output_filters;
  for (auto f = filter_vector.begin(); f!= filter_vector.end(); ++f)
    {
      input = f->filter(input);
    }

  return input;
}

void GloveBase::disconnect(int how)
{
  if (how == SHUT_XX)
    {
      if (CLOSE(sockfd) < 0)
	throw GloveException(10, append_errno("Socket was not closed successfully: "));
    }
  else if (SHUTDOWN(sockfd, how) < 0)
    throw GloveException(20, append_errno("Socket was not shutted down successfully"));
}

std::string GloveBase::user_and_pass(const std::string& user, const std::string &password)
{
  if ( (password != "") && (user == "") )
    throw GloveUriException(1000, "User must be present if password is");

  std::string res=user;
  if (password != "")
    res+=":"+password;
  if (res != "")
    res+="@";

  return res;
}

std::string GloveBase::build_uri (const std::string &service, const std::string &host, int port, const std::string &username, const std::string &password)
{
  std::string res = std::string();
  // Only tcp at this moment
  if (service!="")
    {
      servent *srv = getservbyname(service.c_str(), "tcp");
      if (srv == NULL)
	throw GloveUriException(1001, "Could'nt find service");

      res=srv->s_name + std::string("://")+user_and_pass(username, password)+host;

      if ( port > 65535 )
	throw GloveUriException(1002, "Port must be lower than 65536");

      if ( (port != 0) && (htons(srv->s_port) != port) )
	res+=":"+std::to_string(port);
    }
  else
    {
      if (port == 0)
	throw GloveUriException(1003, "Bad service or port data");
      else if ( port > 65535 )
	throw GloveUriException(1002, "Port must be lower than 65536");

      servent *srv = getservbyport(ntohs(port), "tcp");
      if (srv == NULL)
	throw GloveUriException(1004, "Could'nt find service port");

      res=srv->s_name + std::string("://")+user_and_pass(username, password)+host;
    }

  return res;
}

// Ladies and gentlemen, the unmaintainable !
GloveBase::uri GloveBase::get_from_uri (const std::string &uristring, bool resolve, std::string service_separator)
{
  // This may be easily done with regex's but my gcc 4.7 is a bit buggy with that
  // or even going through iterators instead of using find and its brothers all the time
  // I hope I have time soon to fix it
  uri _uri;
  std::string _uristring = uristring;

  if (service_separator == "")
    service_separator = "://";

  _uri.uri = uristring;

  auto _space = uristring.find(service_separator);

  if (_space == std::string::npos)
    throw GloveUriException(1005, "Can't find service separator '"+service_separator+"' in provided URI");

  _uristring = uristring.substr(_space+service_separator.length());
  auto _atsign = _uristring.find_first_of('@');
  if (_atsign != std::string::npos)
    {
      auto colon = _uristring.find_first_of(':'); 
      if (colon != std::string::npos)
	{
	  _uri.username = _uristring.substr(0, colon);
	  _uri.password = _uristring.substr(colon+1, _atsign-colon-1);
	}
      else
	{
	  _uri.username = _uristring.substr(0, _atsign);
	}
      _uristring = _uristring.substr(_atsign+1);
    }
  auto _slash = _uristring.find_first_of('/');
  std::string::size_type start = -1;
  do
    {
      if (_slash == std::string::npos)
	_slash = _uristring.length();

      std::string temp = _uristring.substr(start+1, _slash-start-1);
      if (start == -1)
	{
	  // Host have port ?
	  auto _portcolon = temp.find(':');
	  if (_portcolon != std::string::npos)
	    {
	      _uri.host = temp.substr(0, _portcolon);
	      try
		{
		  _uri.port = std::stoi(temp.substr(_portcolon+1));
		} 
	      catch (std::invalid_argument)
		{
		  throw GloveUriException(1006, "Invalid port: "+temp.substr(_portcolon+1));
		}
	      if ( (_uri.port<1) || (_uri.port>56635) )
		throw GloveUriException(1007, "Invalid port: "+std::to_string(_uri.port));
	    }
	  else
	    {
	      _uri.host = temp;
	      _uri.port = 0;
	    }
	  _uri.rawpath = _uristring.substr(_slash);
	}
      else if (start+1 != _slash)
	_uri.path.push_back(temp);
      if ( (_uristring[_slash] == '?') || (_uristring[_slash] == '#') )
	{
	  _uri.rawarguments = _uristring.substr(_slash);
	  _slash = _uri.rawarguments.find_first_of("&#");
	  std::string::size_type astart = 0;
	  do
	    {
	      if (_slash == std::string::npos)
		_slash = _uri.rawarguments.length();
	      if (_uri.rawarguments[_slash] == '?')
		{
		  std::string temp2 = _uri.rawarguments.substr(astart+1, _slash-astart-1);
		  auto _equal = temp2.find('=');
		  if (_equal != std::string::npos)
		    _uri.arguments[temp2.substr(0,_equal)] = temp2.substr(_equal+1);
		  else
		    _uri.arguments[temp2] = "";
		}
	      else if (_uri.rawarguments[_slash] == '#')
		{
		  _uri.fragment = _uri.rawarguments.substr(_slash+1);
		  _uri.rawarguments = _uri.rawarguments.substr(0, _slash);
		  break;
		}
	      astart = _slash;
	    } while (_slash = _uri.rawarguments.find_first_of("&#", _slash+1), astart != _uri.rawarguments.length() );
	  break;
	}

      start = _slash;

    } while (_slash = _uristring.find_first_of("/?#", _slash+1), start != _uristring.length() );

  _uri.service=uristring.substr(0, _space);

  return _uri;
}

// Glove::Glove(): connected(false), _shutdown_on_destroy(false), _resolve_hostnames(false), thread_clients(true), thread_server(true), server_reuseaddr(true), max_accepted_clients(2), _server_error_callback(NULL), accept_clients(false), clientId(0)
Glove::Glove(): connected(false), _shutdown_on_destroy(false), server_options({false, true, true, true, GLOVE_DEFAULT_MAX_CLIENTS, GLOVE_DEFAULT_ACCEPT_WAIT, true}), _server_error_callback(NULL), accept_clients(false), clientId(0)
{
  default_values.buffer_size=GLOVE_DEFAULT_BUFFER_SIZE;
}

// Direct server creation
Glove::Glove(int port, client_callback cb, std::string bind_ip, const size_t buffer_size, server_error_callback_t error_callback, const unsigned backlog_queue, int domain): Glove()
{
  default_values.buffer_size=buffer_size;
  server_error_callback(error_callback);
  listen(port, cb, bind_ip, backlog_queue, domain);
}

// Direct client creation
Glove::Glove( const std::string& host, const int port, double timeout, int domain): Glove()
{
  connect(host, port, timeout, domain);
}

Glove::~Glove()
{
  if (_shutdown_on_destroy)
    disconnect();
}

bool Glove::test_connected()
{
  if (!connected)
    {
      if (default_values.exceptions & EXCEPTION_DISCONNECTED)
	throw GloveException(5, "Not connected");

      return false;
    }
  return true;
}

void Glove::connect(const std :: string & host, const int port, double timeout, int domain)
{
  addrinfo address;
  int error;
  addrinfo *servinfo, *rp;
  char _port[12] = {0};

  if (timeout ==-1)
    timeout = default_values.timeout;

  memset(&address, 0, sizeof(addrinfo));

  address.ai_family = domain;
  address.ai_socktype = SOCK_STREAM;
  address.ai_flags = AI_PASSIVE;

  error = getaddrinfo ( host.c_str(), __itoa(port, _port), &address, &servinfo);
  if ( error != 0)
    throw GloveException(1, append_errno("Failed to resolve: "));

  // try to connect the server 
  for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
    sockfd = SOCKET (rp->ai_family, rp->ai_socktype, rp->ai_protocol);

    if (sockfd == -1 )
      continue;

    if (timeout==0)
      {
	if (CONNECT(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) 
	  this->connected = true;
      }
    else
      {
	if ( connect_nonblocking ( rp->ai_addr, rp->ai_addrlen, timeout) ) 
	  this->connected = true;
      }

    if (this->connected)
      {
	if (server_options.resolve_hostnames)
	  {
	    char hostname[NI_MAXHOST];
	    char service[NI_MAXSERV];

	    error = getnameinfo(rp->ai_addr, rp->ai_addrlen, hostname, NI_MAXHOST, service, NI_MAXSERV, 0); 
	    if (error != 0)
	      throw GloveException(2, append_errno("Failed to resolve: "));
	    connectionInfo.host = hostname;
	    connectionInfo.service = service;
	  }

	char ipaddress[INET_ADDRSTRLEN];

	if ( inet_ntop(AF_INET,  &((sockaddr_in *)rp->ai_addr)->sin_addr, ipaddress, INET_ADDRSTRLEN) == NULL)
	  throw GloveException(3, "Cannot get IP address");
	connectionInfo.ip_address = ipaddress;
      }
    else 
      CLOSE(sockfd);
  }

  if (!this->connected)
    throw GloveException(4, append_errno("Cannot connect to the server: "));

  freeaddrinfo ( servinfo );
  errno = 0;			// clear remaining connect_nonblocking error
}

void Glove::disconnect(int how)
{
  if (!test_connected())
    return;

  GloveBase::disconnect(how);
  if (how==SHUT_XX)
    connected=false;
}

std::vector < Glove::hostinfo > Glove::resolveHost(const std :: string & host)
{
  std::vector < Glove::hostinfo > res;

  addrinfo address;
  int error;
  addrinfo *servinfo, *rp;

  memset(&address, 0, sizeof(addrinfo));

  address.ai_family = AF_UNSPEC;
  address.ai_socktype = SOCK_STREAM;
  address.ai_flags = AI_PASSIVE;

  error = getaddrinfo ( host.c_str(), NULL, &address, &servinfo);
  if ( error != 0)
    throw GloveException(1, append_errno("Failed to resolve: "));

  for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
    char hostname[NI_MAXHOST];
    char ipaddress[INET_ADDRSTRLEN];

    error = getnameinfo(rp->ai_addr, rp->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0); 
    if (error != 0)
      throw GloveException(2, append_errno("Failed to resolve: "));

    if ( inet_ntop(AF_INET,  &((sockaddr_in *)rp->ai_addr)->sin_addr, ipaddress, INET_ADDRSTRLEN) == NULL)
      throw GloveException(3, "Cannot get IP address");

    res.push_back({hostname, ipaddress});
  }

  freeaddrinfo ( servinfo );

  return res;
}

// based on from unpv12e/lib/connect_nonb.c
bool Glove::connect_nonblocking(const sockaddr * saptr, socklen_t salen, const double timeout)
{
  int flags, n, error;

  flags = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

  error = 0;
  if ( (n = CONNECT(sockfd, (struct sockaddr *) saptr, salen)) < 0) 
    {
      if (errno != EINPROGRESS)
	return false;
    }

  if (n < 0)
    {
      int sres = select(timeout, SELECT_READ | SELECT_WRITE);
      if ( sres == TCP_ERROR )
	throw GloveException(17, append_errno("TCP Error: ")); // Write a proper error
      else if ( sres == TCP_TIMEOUT )
      	{
      	  errno = ETIMEDOUT;
      	  return false;
      	}
      else
	{
	  size_t len = sizeof(error);
	  if (GETSOCKOPT(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
	    {
	      return false;           /* Solaris pending error */
	    }
	}
    }
  fcntl(sockfd, F_SETFL, flags);  /* restore file status flags */

  if (error)
    {
      // Exceptions on some typical errors?
      // 111 : Connection refused
      errno = error;
    }

  return (error==0);
}

bool Glove::is_connected()
{
  char buf;

  if (!connected)
    return false;

  int res = recv(sockfd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
  if (res<0)
    {
      // Maybe disconnected or maybe not...
      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return true;
      else
	throw GloveException(18, append_errno("Socket error"));
    }
  else if (res==0)
    {
      connected = false;
      return false;
    }
  // We can do it better
  return connected;
}

std::string Glove::getUnspecified(int domain)
{
  switch (domain)
    {
    case AF_INET:
      return "0.0.0.0";
    case AF_INET6:
      return "::";
    default:
      return "";
    }
}

void Glove::listen(const int port, client_callback cb, std::string bind_ip, const unsigned backlog_queue, int domain)
{
  if (bind_ip.empty())
    bind_ip = getUnspecified(domain);

  sockaddr_in address;
  memset(&address, 0, sizeof(address));

  sockfd = SOCKET(domain, SOCK_STREAM, 0);
  if (sockfd == -1)
    throw GloveException(11, append_errno("Cannot create socket: "));

  address.sin_family = domain;
  address.sin_port = htons (port);
  inet_pton(domain, bind_ip.c_str(), &(address.sin_addr));

  if (server_options.server_reuseaddr)
    setsockopt(SO_REUSEADDR, 1);

  if (BIND (sockfd, (struct sockaddr*) &address, sizeof(address))<0)
    {
      CLOSE(sockfd);
      throw GloveException(12, append_errno("Cannot bind to port: "));
    }

  connected = true;
  if (LISTEN(sockfd, backlog_queue) == -1)
    {
      connected = false;
      CLOSE(sockfd);
      throw GloveException(13, append_errno("Cannot perform listen: "));
    }

  accept_clients = true;
  if (server_options.thread_server)
    {
      std::thread([=](client_callback cb)
		  {
		    while (accept_clients) 
		      {
			create_worker(cb);
		      }
		  }, cb).detach();
    }
  else
    {
      while (accept_clients) 
	{
	  create_worker(cb);
	}
    }
}

void Glove::create_worker(Glove::client_callback cb)
{
  sockaddr_in client;
  socklen_t client_len = sizeof(client);
  memset(&client, 0, client_len);

  if (clients_connected.size()>=server_options.max_accepted_clients)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(server_options.accept_wait));
      return;
    }
  int client_sockfd = ACCEPT (sockfd, (struct sockaddr *)&client, &client_len);
  if (client_sockfd<0)
    {
      // Error!! But not big enough to throw an exception
      return;
    }

  std::string hostname, ipaddress;
  if (server_options.resolve_hostnames)
    {
      char _hostname[NI_MAXHOST];

      int error = getnameinfo((sockaddr*) &client, client_len, _hostname, NI_MAXHOST, NULL, 0, 0); 
      if (error == 0)
	  hostname=_hostname;	// Do not throw exception. It can cause the server to close
    }

  char _ipaddress[INET_ADDRSTRLEN];
  // SACAR LA FAMILY DEL client, y poner tambien arriba cuando calculamos la ip
  if ( inet_ntop(AF_INET,  &(client.sin_addr), _ipaddress, INET_ADDRSTRLEN) != NULL)
    ipaddress=_ipaddress;

  Client *c;
  if (server_options.copy_options)
    c = new Client(client_sockfd, ipaddress, hostname, default_values);
  else
    c = new Client(client_sockfd, ipaddress, hostname);

  unsigned thisClient = clientId++;
  clients_connected.insert(std::pair<int, Client*>(thisClient, c));

  // debug clients
  // for (auto i = clients_connected.begin(); i != clients_connected.end(); i++) {
  //   std::cout << "CLIENT ID: *"<<i->first<<"*"<<std::endl;
  // }

  if (server_options.thread_clients)
    {
      std::thread (
		   &Glove::launch_client, this, cb, c, client_sockfd, thisClient
		   ).detach();
    }
  else
    {
      launch_client(cb, c, client_sockfd, thisClient);
    }
}

void Glove::launch_client(client_callback cb, Client *c, int client_sockfd, unsigned client_id)
{
  try
    {
      cb (*c);
    }
  catch (GloveException &e)
    {
      if (_server_error_callback)
	_server_error_callback(*c, client_id, e);
    }

  CLOSE(client_sockfd);
  clients_connected.erase( clients_connected.find(client_id) );
}

void GloveBase::get_address(std::string &ip, int &port, bool noexcp)
{
  ip = std::string();
  port = 0;

  // If we are not connected, getsockname will fail
  // if (!test_connected())
  //   return;

  sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);

  if (getsockname (sockfd, (sockaddr*)&addr, &addrlen)<0)
    {
      if (!noexcp)
	throw GloveException(19, append_errno("Error calling getsockname()"));
      return ;
    }

  ip = inet_ntoa(addr.sin_addr);
  port = ntohs(addr.sin_port);

  return;
}
