/**
*************************************************************
* @file glove.cpp
* @brief Tiny and standalone TCP socket C++11 wrapper and more
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 07 ago 2014
*
* Notes:
*  - Some ideas borrowed from some projects I've made in the past.
*  - Some code borrowed from r-lyeh's knot ( https://github.com/r-lyeh/knot )
*  - urlencode/urldecode borrowed from knot base on code by Fred Bulback
*  - base64 encode/decode functions by René Nyffenegger (https://github.com/ReneNyffenegger/development_misc/tree/master/base64)
*  - send() and recv() are called just once (well recv() twice), so we can replace these functions
*  - I want to abstract the final user (application programmer) from socket operations but without losing control and information
*
* Changelog:
*  20150503 : - Bug fixing in non-ssl connections trying to call ssl functions
*  20150502 : - Error documentation.
*             - Changed error 100 "Peer shutdown" to error 21
*             - First steps with openSSL connections
*  20150501 : - Connection Info is filled in a separate function, allowing us to get the service name
*              even when resolve_hostnames is false. That's because we may want to guess
*              if the service is secure (by service name)
*             - (this->connected == false) condition when connecting to a server
*             - Fixed resolveHost() to resolve IPv6 and IPv4, whatever it comes to it.
*             - Bug fixing on flag manipulations. Added functions and manipulators for exceptions
*  20150430 : some more more doc for Doxygen (in glove.hpp) (I'd like to comment everything)
*  20150425 : some more doc for Doxygen (in glove.hpp)
*  20150418 : some doc for Doxygen (in glove.hpp)
*  20150404 : urlencode/urldecode/base64 encode/base64 decode helpers
*  20140923 : get_from_uri() - The unmaintainable!
*  20140919 : build_uri(), better test_connected()
*  20140914 : Some bugfixing and Glove constructors
*  20140913 : Created GloveBase, deleted Util namespace and duplicated code
*  20140908 : Now, it can be a server
*  20140807 : Begin this project
*
* To-do:
*  1 - SSL shutdown. Context and handler cleanup
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

/*
 * Some more doc, error! GloveException codes:
 *
 *   1: "Failed to resolve": Can't resolve host
 *       Found on Glove::connect() 
 *                Glove::resolveHost()
 *   2: "Failed to resolve": Can't get IP address, host
 *       Found on Glove::resolveHost()
 *                Glove::fill_connection_info() (only if server_options.resolve_hostnames is true)
 *   3: "Cannot get IP address": Current address structure don't have valid information for current domain
 *      Maybe we have a IPv6 address and try to get as IPv4
 *      Found on Glove::fill_connection_info()
 *               Glove::resolveHost()
 *   4: "Cannot connect to the server" : We've tried but cannot connect
 *      Found on Glove::connect()
 *   5: "Not connected" : We're not connected!!
 *      Found on Glove::test_connected() if we're not connected and EXCEPTION_DISCONNECTED is enabled
 *   6: "Socket error when sending" : send() returns -1 (if secure connection SSL_write() returns -1
 *      Found on GloveBase::_send()
 *   7: "Timed out while receiving data" : We were waiting for data which didn't come after
 *      waiting for [timeout] seconds. 
 *      Found on GloveBase::_receive_fixed() when timeout, exception_on_timeout=true 
 *                                           BUT if we've already received data, timeout_when_data must be true too.
 *   8: "Error while waiting for data" : We were waiting for data, but received an unexpected error.
 *      Found on GloveBase::_receive_fixed()
 *   9: "Error receiving data" : recv() returns -1 (if secure connection SSL_read() returns -1)
 *      Found on GloveBase::_receive_fixed()
 *  10: "Socket was not closed" : Problem closing socket (bad socket? IO Error?)
 *      Found on GloveBase::disconnect()
 *  11: "Cannot create socket"
 *      Found on Glove::listen()
 *               Glove::connect()
 *  12: "Cannot bind to port"
 *      Found on Glove::listen()
 *  13: "Cannot perform listen"
 *      Found on Glove::listen()
 *  14: "Failed to set option on socket" : setsockopt() returns -1
 *      Found on GloveBase::setsockopt()
 *  15: "Failed to get option on socket" : getsockopt() returns -1
 *      Found on GloveBase::getsockopt()
 *  16: "Unrecognised socket option, or it does not accept ints" : socket option not recognised 
 *      (maybe my fault, because not implemented)
 *      Found on GloveBase::get_integer_sockopts_level() used by GloveBase::setsockopt() and GloveBase::getsockopt()
 *  17: "TCP Error" : TCP Error on connection
 *      Found on GloveBase::connect_nonblocking()
 *  18: "Socket error" : error receiving when checking connection
 *      Found on Glove::is_connected()
 *  19: "Error calling getsockname()"
 *      Found on GloveBase::get_address()
 *  20: "Socket was not shutted down" : Error on shutdown()
 *      Found on GloveBase::disconnect()
 *  21: "Peer shutdown" : Peer shutdown when receiving
 *      Found on GloveBase::_receive_fixed()
 *  22: "Couldn't create SSL context" :
 *      Found on Glove::SSLClientHandshake() when connecting TO a server
 *               Glove::SSLServerInitialize() when creating server context
 *  23: "Couldn't create SSL handler
 *      Found on Glove::SSLClientHandshake()
 *  24: "Couldn't assign socket to SSL session"
 *      Found on Glove::SSLClientHandshake()
 *  25: "SSL handshake failure"
 *      Found on Glove::SSLClientHandshake()
 *  26: "Couldn't load CA path" : Can't load certificate authorities!
 *      Found on Glove::SSLClientHandshake() ssl_options.flags must have SSL_FLAG_VERIFY_CA enabled
 *  27: "Couldn't get certificate chain" : Tried to get certificate chain, but couldn't
 *      Found on Glove::SSLGetCertificatesInfo()
 *  28: "Bad 'Not Before' time in certificate"
 *      Found on Glove::SSLGetCertificatesInfo();
 *  29: "Bad 'Not After' time in certificate"
 *      Found on Glove::SSLGetCertificatesInfo();
 *  30: "Certificate chain file XXXX does not exist"
 *      Found on Glove::SSLServerInitialize() when trying to load the certificate chain file
 *  31: "There was a problem reading certificate chain file XXXX."
 *      Found on Glove::SSLServerInitialize() when trying to load the certificate chain file
 *  32: "Certificate key file XXXX does not exist"
 *      Found on Glove::SSLServerInitialize() when trying to load the certificate key file
 *  33: "There was a problem reading certificate key file XXXX."
 *      Found on Glove::SSLServerInitialize() when trying to load the certificate key file
 *  34: "Can't load certificate chain file XXXXX"
 *      Found on Glove::SSLServerInitialize() when trying to load the certificate chain file
 *  35: "Can't load certificate key file XXXXXX"
 *      Found on Glove::SSLServerInitialize() when trying to load the certificate key file
 *  36: "Private key doesn't match the certificate"
 *      Found on Glove::SSLServerInitialize() when certificate and key are loaded
 */

#include "glove.hpp"
#include <cstring> // memset(), strerror()
#include <iostream> // debug only
#include <arpa/inet.h>
#include <netinet/tcp.h> // TCP_NODELAY 
#include <thread>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

/** Initialization (if any), it was intended to be cross-platform, but time
 goes by and I needed to get this lib in a decent point for Linux. So I didn't
 care about Windows.
*/
#define INIT()                    
/**
 * Calls socket()
 */
#define SOCKET(A,B,C)             ::socket((A),(B),(C))
/** Calls accept()  */
#define ACCEPT(A,B,C)             ::accept((A),(B),(C))
/** Calls connect()  */
#define CONNECT(A,B,C)            ::connect((A),(B),(C))
/** Calls close()  */
#define CLOSE(A)                  ::close((A))
/** Calls read()  */
#define READ(A,B,C)               ::read((A),(B),(C))
/** Calls recv()  */
#define RECV(A,B,C,D)             ::recv((A), (void *)(B), (C), (D))
/** Calls select()  */
#define SELECT(A,B,C,D,E)         ::select((A),(B),(C),(D),(E))
/** Calls send()  */
#define SEND(A,B,C,D)             ::send((A), (const char *)(B), (C), (D))
/** Calls write()  */
#define WRITE(A,B,C)              ::write((A),(B),(C))
/** Calls getsockopt()  */
#define GETSOCKOPT(A,B,C,D,E)     ::getsockopt((int)(A),(int)(B),(int)(C),(      void *)(D),(socklen_t *)(E))
/** Calls setsockopt()  */
#define SETSOCKOPT(A,B,C,D,E)     ::setsockopt((int)(A),(int)(B),(int)(C),(const void *)(D),(socklen_t)(E))
/** Calls bind()  */
#define BIND(A,B,C)               ::bind((A),(B),(C))
/** Calls listen()  */
#define LISTEN(A,B)               ::listen((A),(B))
/** Calls shutdown()  */
#define SHUTDOWN(A,B)             ::shutdown((A),(B))

const char* GloveBase::CRLF = "\r\n";

#if ENABLE_OPENSSL
bool Glove::openSSLInitialized = false;
#endif

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
#if ENABLE_OPENSSL
  /**
   * Extract a substring from origin into buffer, updating starting
   * value to call in chain. Used by ASN1_TIME_to_time_t to extract
   * substrings easyly
   *
   * @param buffer  Where to write to
   * @param origin  Original string
   * @param from    Where to start from. 
   *                           Updated to the last position after end.
   * @param size    Characters to extract.
   *
   * @return char* reference to buffer
   */
  char* join(char* buffer, const char* origin, size_t *from, size_t size)
  {
    size_t i=0;
    while (i<size)
      {
	buffer[i++] = origin[(*from)++];
      }
    buffer[i] = '\0';
    return buffer;
  }

  /**
   * Transforms ASN1 time sring to time_t (except milliseconds and time zone)
   * Ideas from: http://stackoverflow.com/questions/10975542/asn1-time-conversion
   *
   * @param time    SSL ASN1_TIME pointer
   * @param tmt     time_t pointer to write to
   *
   * @return int 0 if OK, <0 if anything goes wrong
   */
  int ASN1_TIME_to_time_t(ASN1_TIME* time, time_t *tmt)
  {
    const char* data = (char*)time->data;
    size_t p = 0;
    char buf[5];
    struct tm t;
    memset(&t, 0, sizeof(t));
    size_t datalen = strlen(data);

    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
      /* error checking YYMMDDHH at least */
      if (datalen<8)
	return -1;
      t.tm_year = atoi (join(buf, data, &p, 2));
      if (t.tm_year<70)
	t.tm_year += 100;
      datalen = strlen(data+2);
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
      /* error checking YYYYMMDDHH at least*/
      if (datalen<10)
	return -1;

      t.tm_year = atoi (join(buf, data, &p, 4));
      t.tm_year -= 1900;
      datalen = strlen(data+4);
    }

    /* the year is out of datalen. Now datalen is fixed */

    t.tm_mon = atoi (join(buf, data, &p, 2))-1; /* January is 0 for time_t */
    t.tm_mday= atoi (join(buf, data, &p, 2));
    t.tm_hour= atoi (join(buf, data, &p, 2));

    if (datalen<8)
      return !(*tmt = mktime(&t));
    t.tm_min = atoi (join(buf, data, &p, 2));

    if (datalen<10)
      return !(*tmt = mktime(&t));
    t.tm_sec = atoi (join(buf, data, &p, 2));
    /* Ignore millisecnds and time zone */
    return !(*tmt = mktime(&t));
  }

  /**
   * Test if file exists
   *
   * @param filename File Name in char*
   *
   * @return 1 if file exists, 0 if not, -1 if errors
   */
  short fileExists(const char *filename)
  {
    int fd=open(filename, O_RDONLY);
    if (fd==-1)
      {
	if (errno==2)		/* If errno==2 it means file not found */
	  return 0;		/* otherwise there is another error at */
	else 			/* reading file, for example path not  */
	  return -1;		/* found, no memory, etc */
      }
    close(fd);			/* If we close the file, it exists */
    return 1;
  }

#endif
};

void GloveBase::setsockopt(int level, int optname, void *optval, socklen_t optlen)
{
  if (SETSOCKOPT(conn.sockfd, level, optname, optval, optlen) < 0)
    throw GloveException(14, append_errno("Failed to set option on socket: "));
}

void GloveBase::getsockopt(int level, int optname, void *optval, socklen_t *optlen)
{
  if (GETSOCKOPT(conn.sockfd, level, optname, optval, optlen) < 0)
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
    FD_SET(conn.sockfd, &fds);
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
    int ret = SELECT(conn.sockfd+1, rset, wset, NULL, &tv);

    return ( ret == -1 ? conn.sockfd = -1, TCP_ERROR : ret == 0 ? TCP_TIMEOUT : TCP_OK );
}

void GloveBase::_send(const std::string &data)
{
  std::string out = run_filters(FILTER_OUTPUT, data);

  int bytes_sent;
  do
    {
#if ENABLE_OPENSSL
      /* Sent with SSL or not */
      if (conn.secureConnection == ENABLE_SSL)
	bytes_sent = SSL_write(conn.ssl, out.c_str(), out.size());
      else
#endif
	// msg_nosignal avoid systems signals
	bytes_sent = SEND( conn.sockfd, out.c_str(), out.size(), MSG_NOSIGNAL);

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
#if ENABLE_OPENSSL
  /* openssl has not downloaded all bytes from the buffer */
  size_t pending_bytes=0;
#endif
  if (timeout==-1)
    timeout = default_values.timeout;

  bool read_once = (_read_once == -1)?default_values.read_once:_read_once;

  do
    {
      int error;
#if ENABLE_OPENSSL
      if (!pending_bytes)
#endif
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
      /* Can put this before de do {} */
      int __buffer_size = (size>0)?((requested_size>_buffer_size)?_buffer_size:requested_size):_buffer_size;
      std::string buffer(__buffer_size, '\0');
#if ENABLE_OPENSSL
      if (conn.secureConnection == ENABLE_SSL)
	bytes_received = SSL_read(conn.ssl, &buffer[0], buffer.size()-1);
      else
#endif
	bytes_received = RECV (conn.sockfd, &buffer[0], buffer.size(), 0);

      if (bytes_received < 0)
	throw GloveException(9, append_errno("Error receiving data: "));

      if (bytes_received == 0)
	{
	  if (default_values.exceptions & EXCEPTION_DISCONNECTED)
	    throw GloveException(21, "Peer shutdown");
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
#if ENABLE_OPENSSL
      //      pending_bytes = SSL_pending(conn.ssl);
      if ( (conn.secureConnection) && (pending_bytes = SSL_pending(conn.ssl)) )
	{
	  continue;
	}
#endif
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
      if (CLOSE(conn.sockfd) < 0)
	throw GloveException(10, append_errno("Socket was not closed successfully: "));
    }
  else if (SHUTDOWN(conn.sockfd, how) < 0)
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

      std::string servName = getServByPort(port);
      if (servName.empty())
	throw GloveUriException(1004, "Could'nt find service port");

      res=servName + std::string("://")+user_and_pass(username, password)+host;
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

// ------------- tools ---------------
std::string GloveBase::getServByPort(int port)
{
  servent *srv = getservbyport(ntohs(port), "tcp");
  if (srv != NULL)
    {
      return srv->s_name;
    }

  return "";
}

// borrowed from original knot https://github.com/r-lyeh/knot
// knot had adapted it from code by Fred Bulback
std::string GloveBase::urlencode( const std::string &str ) 
{
  auto to_hex = [](char code) -> char
    {
      static char hex[] = "0123456789abcdef";
      return hex[code & 15];
    };

  std::string out( str.size() * 3, '\0' );
  const char *pstr = str.c_str();
  char *buf = &out[0], *pbuf = buf;
  while (*pstr) 
    {
      if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
	*pbuf++ = *pstr;
      else if (*pstr == ' ')
	*pbuf++ = '+';
      else
	*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
      pstr++;
    }

  return out.substr( 0, pbuf - buf );
}

std::string GloveBase::urldecode( const std::string &str )
{
  auto from_hex = [](char ch) -> char 
    {
      return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
    };

  const char *pstr = str.c_str();
  std::string out( str.size(), '\0' );
  char *buf = &out[0], *pbuf = buf;
  while (*pstr) 
    {
      if (*pstr == '%') 
	{
	  if (pstr[1] && pstr[2]) 
	    {
	      *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
	      pstr += 2;
	    }
	} 
      else if (*pstr == '+') 
	{
	  *pbuf++ = ' ';
	} 
      else 
	{
	  *pbuf++ = *pstr;
	}
      pstr++;
    }

  return out.substr( 0, pbuf - buf );
}

namespace
{
  // Base64 encoder/decoder stuff
  static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


  static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
  }
};

std::string GloveBase::base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) 
{
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) 
    {
      char_array_3[i++] = *(bytes_to_encode++);
      if (i == 3) 
	{
	  char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
	  char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
	  char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
	  char_array_4[3] = char_array_3[2] & 0x3f;

	  for(i = 0; (i <4) ; i++)
	    ret += base64_chars[char_array_4[i]];
	  i = 0;
	}
    }

  if (i)
    {
      for(j = i; j < 3; j++)
	char_array_3[j] = '\0';

      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (j = 0; (j < i + 1); j++)
	ret += base64_chars[char_array_4[j]];

      while((i++ < 3))
	ret += '=';

    }

  return ret;
}

std::string GloveBase::base64_decode(std::string const& encoded_string) 
{
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) 
    {
      char_array_4[i++] = encoded_string[in_]; in_++;
      if (i ==4) 
	{
	  for (i = 0; i <4; i++)
	    char_array_4[i] = base64_chars.find(char_array_4[i]);

	  char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
	  char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
	  char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

	  for (i = 0; (i < 3); i++)
	    ret += char_array_3[i];
	  i = 0;
	}
    }

  if (i) 
    {
      for (j = i; j <4; j++)
	char_array_4[j] = 0;

      for (j = 0; j <4; j++)
	char_array_4[j] = base64_chars.find(char_array_4[j]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

  return ret;
}

// Glove::Glove(): connected(false), _shutdown_on_destroy(false), _resolve_hostnames(false), thread_clients(true), thread_server(true), server_reuseaddr(true), max_accepted_clients(2), _server_error_callback(NULL), accept_clients(false), clientId(0)
Glove::Glove(): connected(false), _shutdown_on_destroy(false), server_options({false, true, true, true, GLOVE_DEFAULT_MAX_CLIENTS, GLOVE_DEFAULT_ACCEPT_WAIT, true}), _server_error_callback(NULL), accept_clients(false), clientId(0)
{
  default_values.buffer_size=GLOVE_DEFAULT_BUFFER_SIZE;
#if ENABLE_OPENSSL
  setSSLDefaultValues();
#endif
}

// Direct server creation
Glove::Glove(int port, client_callback cb, std::string bind_ip, const size_t buffer_size, server_error_callback_t error_callback, const unsigned backlog_queue, int domain): Glove()
{
  default_values.buffer_size=buffer_size;
  server_error_callback(error_callback);
  listen(port, cb, bind_ip, backlog_queue, domain);
}

// Direct client creation
Glove::Glove( const std::string& host, const int port, double timeout, int domain, int secure): Glove()
{
  connect(host, port, timeout, domain, secure);
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

void Glove::fill_connection_info(addrinfo *rp, int port)
{
  if (server_options.resolve_hostnames)
    {
      char hostname[NI_MAXHOST];
      char service[NI_MAXSERV];

      int error = getnameinfo(rp->ai_addr, rp->ai_addrlen, hostname, NI_MAXHOST, service, NI_MAXSERV, 0); 
      if (error != 0)
	throw GloveException(2, append_errno("Failed to resolve: "));
      connectionInfo.host = hostname;
      connectionInfo.service = service;
    }
  else
    {
      /* We won't get the host, but may guess the service name */
      connectionInfo.service = getServByPort(port);
    }
  char ipaddress[INET_ADDRSTRLEN];

  if ( inet_ntop(AF_INET,  &((sockaddr_in *)rp->ai_addr)->sin_addr, ipaddress, INET_ADDRSTRLEN) == NULL)
    throw GloveException(3, "Cannot get IP address");

  connectionInfo.ip_address = ipaddress;
}

void Glove::connect(const std :: string & host, const int port, double timeout, int domain, int secure)
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

  this->connected = false;
  // try to connect the server 
  for (rp = servinfo; rp != NULL, this->connected==false; rp = rp->ai_next) 
    {
      conn.sockfd = SOCKET (rp->ai_family, rp->ai_socktype, rp->ai_protocol);

      if (conn.sockfd == -1 )
	continue;

      if (timeout==0)
	{
	  if (CONNECT(conn.sockfd, rp->ai_addr, rp->ai_addrlen) == 0) 
	    this->connected = true;
	}
      else
	{
	  if ( connect_nonblocking ( rp->ai_addr, rp->ai_addrlen, timeout) ) 
	    this->connected = true;
	}

      if (this->connected)
	fill_connection_info(rp, port);
      else 
	CLOSE(conn.sockfd);
    }

  if (conn.sockfd == -1)
    throw GloveException(11, append_errno("Cannot create socket: "));

  if (!this->connected)
    throw GloveException(4, append_errno("Cannot connect to the server: "));

  freeaddrinfo ( servinfo );

  /* Give an initial value for this */
  conn.secureConnection = DISABLE_SSL;
  /* SSL connection */
# if ENABLE_OPENSSL
  if (secure == AUTODETECT_SSL)
    secure = detectSecureService(connectionInfo.service);

  if (secure)
    {
      bool hndshk = SSLClientHandshake();
      if ( (hndshk) && (ssl_options.flags & SSL_FLAG_GET_CIPHER_INFO) )
	SSLGetCipherInfo();

      if ( (hndshk) && (ssl_options.flags & SSL_FLAG_GET_CERT_INFO) )
	SSLGetCertificatesInfo();
    }
# endif
  errno = 0;			// clear remaining connect_nonblocking error
}

#if ENABLE_OPENSSL
/* All these things will be only in compilations with SSL enabled */

void Glove::setSSLDefaultValues()
{
  ssl_options.ssl_method = SSLv23;
  ssl_options.flags = SSL_FLAG_VERIFY_CA;
  ssl_options.CApath = GLOVE_DEFAULT_SSL_CAPATH;
}

void Glove::initializeOpenSSL()
{
  if (!openSSLInitialized)
    {
      SSL_library_init();
#if GLOVEDEBUG > 0
      SSL_load_error_strings();
#endif
    }
}

void Glove::SSLServerInitialize()
{
  conn.ssl = NULL;

  initializeOpenSSL();

  OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */

  /* We can try SSLv23_server_method() to try several 
   methods, starting from the more secure*/
  conn.ctx = SSL_CTX_new(getSSLClientMethod());
  if (conn.ctx == NULL)
    throw GloveException(22, "Couldn't create SSL context");

  /* This tests can be done by openSSL but won't be separated erros */
  short ex = fileExists(ssl_options.certChain.c_str());
  if (ex == 0)
    throw GloveException(30, "Certificate chain file \""+ssl_options.certChain+"\" does not exist");
  else if (ex == -1)
    throw GloveException(31, "There was a problem reading certificate chain file \""+ssl_options.certChain+"\".");

  ex = fileExists(ssl_options.certKey.c_str());
  if (ex == 0)
    throw GloveException(32, "Certificate key file \""+ssl_options.certKey+"\" does not exist");
  else if (ex == -1)
    throw GloveException(33, "There was a problem reading certificate key file \""+ssl_options.certKey+"\".");

  if (SSL_CTX_use_certificate_chain_file(conn.ctx, ssl_options.certChain.c_str()) < 1)
    throw GloveException(34, "Can't load certificate chain file \""+ssl_options.certChain+"\"");

  if (SSL_CTX_use_PrivateKey_file(conn.ctx, ssl_options.certKey.c_str(), SSL_FILETYPE_PEM) < 1)
    throw GloveException(35, "Can't load certificate key file \""+ssl_options.certKey+"\"");

  if (!SSL_CTX_check_private_key(conn.ctx))
    throw GloveException(36, "Private key doesn't match the certificate");
}

bool Glove::SSLClientHandshake(bool exception_on_handshake_failure)
{
  initializeOpenSSL();
  conn.ctx = SSL_CTX_new(getSSLClientMethod());
  if (conn.ctx == NULL)
    throw GloveException(22, "Couldn't create SSL context");

  if (ssl_options.flags & SSL_FLAG_FAIL_INVALID_CA)
    conn.ctx->verify_mode = 1;

  conn.ssl = SSL_new (conn.ctx);
  if (conn.ssl == NULL)
    throw GloveException(23, "Couldn't create SSL handler");

  if (SSL_set_fd(conn.ssl, conn.sockfd) == 0)
    throw GloveException(24, "Couldn't assign socket to SSL session");

  if (ssl_options.flags & SSL_FLAG_VERIFY_CA)
    {
      if (SSL_CTX_load_verify_locations(conn.ctx, NULL, ssl_options.CApath.c_str()) == 0)
	throw GloveException(26, "Couldn't load CApath");
    }

  if (SSL_connect(conn.ssl) < 1)
    {
      if (exception_on_handshake_failure)
	throw GloveException(25, "SSL handshake failure");

      return false;
    }

  /* Fill verify result */
  conn.cert_verify_result = SSL_get_verify_result (conn.ssl);
  conn.cert_error_string = X509_verify_cert_error_string(conn.cert_verify_result);
  conn.cipher_info_present = false;
  conn.certificates_info_present = false;
  conn.secureConnection = ENABLE_SSL;

  return true;
}

const SSL_METHOD* Glove::getSSLClientMethod()
{
  switch (ssl_options.ssl_method)
    {
    case SSLv23 : return SSLv23_client_method();
    case SSLv3  : return SSLv3_client_method();
    case TLSv1  : return TLSv1_client_method();
    case TLSv1_1: return TLSv1_1_client_method();
    case TLSv1_2: return TLSv1_2_client_method();
    case DTLSv1 : return DTLSv1_client_method();
    }
}

long Glove::getSSLVerifyState()
{
  if (!conn.secureConnection)
    return -1;

  return conn.cert_verify_result;
}

std::string Glove::getSSLVerifyString()
{
  if (!conn.secureConnection)
    return "Not a secure connection";

  return conn.cert_error_string;
}

void Glove::SSLGetCipherInfo()
{
  if (conn.cipher_info_present)
    return;

  if (!conn.secureConnection)
    return;
  /* Verificar que conn.ssl SEA != NULL */
  conn.ssl_version = SSL_get_version(conn.ssl);
  conn.cipher_name = SSL_get_cipher_name(conn.ssl);
  conn.cipher_version = SSL_get_cipher_version(conn.ssl);
  conn.cipher_description.resize(128, '\0');
  SSL_CIPHER_description((SSL_CIPHER*)SSL_get_current_cipher(conn.ssl), &conn.cipher_description[0], 128);
}

void Glove::SSLGetCertificatesInfo()
{
  STACK_OF(X509) *chain = SSL_get_peer_cert_chain(conn.ssl);
  if (!chain)
    throw GloveException(27, "Couldn't get certificate chain");

  for (unsigned i=0; i<sk_X509_num(chain); i++)
    {
      SSL_certificate current;
      current.cert = sk_X509_value(chain, i);
      if (!current.cert)
	continue;

      X509_NAME* certname = X509_get_subject_name(current.cert);
      for (unsigned j=0; j<X509_NAME_entry_count(certname); ++j)
	{
	  X509_NAME_ENTRY* entry = X509_NAME_get_entry(certname, j);
	  if (entry == NULL)
	    continue;

	  int n = OBJ_obj2nid(entry->object);
	  char *s;
	  char buffer[1024];
	  if ((n == NID_undef) || ((s = (char*)OBJ_nid2sn(n)) == NULL)) 
	    {
	      i2t_ASN1_OBJECT(buffer, sizeof(buffer), entry->object);
	      s = buffer;
	    }
	  //	  current.entries[s] = entry->value->data;
	  //	  std::string tmpval = entry->value->data;
	  current.entries.insert({s, (char*)entry->value->data});
	}

      if (ASN1_TIME_to_time_t(X509_get_notBefore(current.cert), &current.notBefore)!=0)
	throw GloveException(28, "Bad 'Not Before' time in certificate");
      if (ASN1_TIME_to_time_t(X509_get_notAfter(current.cert), &current.notAfter)!=0)
	throw GloveException(29, "Bad 'Not After' time in certificate");

      conn.certificates.push_back(current);
    }
  conn.certificates_info_present = true;
}

std::string Glove::getSSLVersion()
{
  if (!conn.secureConnection)
    return "";
  if (!conn.cipher_info_present)
    SSLGetCipherInfo();

  return conn.ssl_version;
}

std::string Glove::getSSLCipherName()
{
  if (!conn.secureConnection)
    return "";
  if (!conn.cipher_info_present)
    SSLGetCipherInfo();

  return conn.cipher_name;
}

std::string Glove::getSSLCipherVersion()
{
  if (!conn.secureConnection)
    return "";
  if (!conn.cipher_info_present)
    SSLGetCipherInfo();

  return conn.cipher_version;
}

std::string Glove::getSSLCipherDescription()
{
  if (!conn.secureConnection)
    return "";
  if (!conn.cipher_info_present)
    SSLGetCipherInfo();

  return conn.cipher_description;
}

std::string Glove::debugCipherInfo()
{
  return "SSL Version: "+getSSLVersion()+"\n" +
    "Cipher name: "+getSSLCipherName()+"\n" +
    "Cipher version: "+getSSLCipherVersion()+"\n" +
    "Cipher description: "+getSSLCipherDescription()+"\n";
}

std::string Glove::debugCertificatesInfo()
{
  std::string out;

  if (!conn.secureConnection)
    return "";
  if (!conn.certificates_info_present)
    SSLGetCertificatesInfo();

  for (auto c : conn.certificates)
    {
      std::tm dt;
      gmtime_r(&c.notBefore, &dt);
      std::string s( 128, '\0' );
      strftime( &s[0], s.size(), "%Y/%m/%d %H:%M", &dt);
      out+="Not Before: "+s+"\n";
      gmtime_r(&c.notAfter, &dt);
      strftime( &s[0], s.size(), "%Y/%m/%d %H:%M", &dt);
      out+="Not After: "+s+"\n";
      for (auto e : c.entries)
	{
	  out+=e.first+": "+e.second+"\n";
	}
      out+="--------------------------------\n";
    }
  return out;
}

void Glove::certChainAndKey(std::string chainFile, std::string keyFile)
{
  if (!chainFile.empty())
    ssl_options.certChain = chainFile;
  if (!keyFile.empty())
    ssl_options.certKey = keyFile;
}

#endif

int Glove::detectSecureService(const std::string& service)
{
  static std::vector<std::string> secureServices = {
    "https",
    "nntps",
    "ldaps",
    "ftps",
    "ftps-data",
    "telnets",
    "imaps",
    "ircs",
    "pop3s",
    "suucp"
  };
  if (std::find(secureServices.begin(), secureServices.end(), service)!=secureServices.end())
    return ENABLE_SSL;
  else
    return DISABLE_SSL;
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
    char ipaddress[INET6_ADDRSTRLEN];

    error = getnameinfo(rp->ai_addr, rp->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0); 
    if (error != 0)
      throw GloveException(2, append_errno("Failed to resolve: "));

    if ( inet_ntop(rp->ai_family,  &((sockaddr_in *)rp->ai_addr)->sin_addr, ipaddress, INET6_ADDRSTRLEN) == NULL)
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

  flags = fcntl(conn.sockfd, F_GETFL, 0);
  fcntl(conn.sockfd, F_SETFL, flags | O_NONBLOCK);

  error = 0;
  if ( (n = CONNECT(conn.sockfd, (struct sockaddr *) saptr, salen)) < 0) 
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
	  if (GETSOCKOPT(conn.sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
	    {
	      return false;           /* Solaris pending error */
	    }
	}
    }
  fcntl(conn.sockfd, F_SETFL, flags);  /* restore file status flags */

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

  int res = RECV(conn.sockfd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
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

void Glove::listen(const int port, client_callback cb, std::string bind_ip, const unsigned backlog_queue, int domain, int secure, std::string certchain, std::string certkey)
{
  if (bind_ip.empty())
    bind_ip = getUnspecified(domain);

  sockaddr_in address;
  memset(&address, 0, sizeof(address));

#if ENABLE_OPENSSL
  certChainAndKey(certchain, certkey);
  conn.secureConnection = DISABLE_SSL;
  if (secure == UNDEFINED_SSL)
    {
      secure = ((!ssl_options.certKey.empty()) && (!ssl_options.certChain.empty()))?ENABLE_OPENSSL:DISABLE_SSL;
    }
  if (secure == AUTODETECT_SSL)
    secure = detectSecureService(getServByPort(port));

  if (secure == ENABLE_SSL)
    {
      /* Finally secure connection! */
      SSLServerInitialize();
      conn.secureConnection = ENABLE_SSL;
    }
#endif
  conn.sockfd = SOCKET(domain, SOCK_STREAM, 0);
  if (conn.sockfd == -1)
    throw GloveException(11, append_errno("Cannot create socket: "));

  address.sin_family = domain;
  address.sin_port = htons (port);
  inet_pton(domain, bind_ip.c_str(), &(address.sin_addr));

  if (server_options.server_reuseaddr)
    setsockopt(SO_REUSEADDR, 1);

  if (BIND (conn.sockfd, (struct sockaddr*) &address, sizeof(address))<0)
    {
      CLOSE(conn.sockfd);
      throw GloveException(12, append_errno("Cannot bind to port: "));
    }

  connected = true;
  if (LISTEN(conn.sockfd, backlog_queue) == -1)
    {
      connected = false;
      CLOSE(conn.sockfd);
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
  Conn_description client_conn;
  client_conn.sockfd = ACCEPT (conn.sockfd, (struct sockaddr *)&client, &client_len);
  if (client_conn.sockfd<0)
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
    c = new Client(client_conn, ipaddress, hostname, default_values);
  else
    c = new Client(client_conn, ipaddress, hostname);

  unsigned thisClient = clientId++;
  clients_connected.insert(std::pair<int, Client*>(thisClient, c));

  // debug clients
  // for (auto i = clients_connected.begin(); i != clients_connected.end(); i++) {
  //   std::cout << "CLIENT ID: *"<<i->first<<"*"<<std::endl;
  // }

  if (server_options.thread_clients)
    {
      std::thread (
		   &Glove::launch_client, this, cb, c, client_conn, thisClient
		   ).detach();
    }
  else
    {
      launch_client(cb, c, client_conn, thisClient);
    }
}

void Glove::launch_client(client_callback cb, Client *c, Conn_description client_conn, unsigned client_id)
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

  CLOSE(client_conn.sockfd);
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

  if (getsockname (conn.sockfd, (sockaddr*)&addr, &addrlen)<0)
    {
      if (!noexcp)
	throw GloveException(19, append_errno("Error calling getsockname()"));
      return ;
    }

  ip = inet_ntoa(addr.sin_addr);
  port = ntohs(addr.sin_port);

  return;
}
