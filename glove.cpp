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
*
* To-do:
*  1 - Some more documentation
*  2 - epoll support
*  3 - better is_connected()
*  4 - getsockname() support
*  5 - shutdown() support
*  6 - be able to connect with protocol/service names
*  7 - set_option(...) allowing a variadic template to set every client or server option
* 15 - Winsock support (in the future)
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
#define SHUTDOWN(A)               ::shutdown((A),SHUT_RDWR)
#define SHUTDOWN_R(A)             ::shutdown((A),SHUT_RD)
#define SHUTDOWN_W(A)             ::shutdown((A),SHUT_WR)


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
}

void Glove::disconnect()
{
  if (!test_connected())
    return;

  if (CLOSE(sockfd) != 0)
    throw GloveException(10, append_errno("Socket was not closed successfully: "));
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

  if (n != 0)
    {
      int sres = select(timeout, SELECT_READ | SELECT_WRITE);
      if ( sres == TCP_ERROR )
	throw GloveException(17, append_errno("TCP Error: ")); // Write a proper error
      else if ( sres == TCP_TIMEOUT )
      	{
      	  errno = ETIMEDOUT;
      	  return false;
      	}
    }
  fcntl(sockfd, F_SETFL, flags);  /* restore file status flags */

  if (error) 
    errno = error;

  return (error==0);
}

bool Glove::is_connected()
{
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
