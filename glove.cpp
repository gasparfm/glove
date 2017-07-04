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
* Changelog
*  20170717 : - Fixed local connection detection. Not merged right from another project.
*  20170131 : - OpenSSL initialization is *not* thread safe. Added a little mutex
*  20170127 : - sets tlsext_host_name when connecting with SSL. (SNI support!!)
*  20161016 : - Client objects know if they are local connections
*  20161007 : - bug fixed parsing URI arguments
*  20161004 : - minor bugs to free resources when closing unfinished connections
*           : - getservbyname wrapper with additional services (for now, only ws:// and wss://)
*           : - remove CRLF constants and use it from GloveDef (global constants for all Glove headers)
*  20161003 : - fixed bugs when connecting non-ssl when service is SSL
*  20161002 : - merged SSL server code (I thought it was)
*           : - SSL disconnection algorithm in loop
*  20160928 : - get service and host from uri. To automatically get http(s)://host:port/
*  20160926 : - base64_encode/decode ; urlencode / urldecode moved to GloveCoding namespace
*  20160919 : - Fixed compilation for GCC >=5.2:
*  20160813 : - prevent old openSSL hung in faulty server responses. SSL_read() is ran in other thread, this one
*               has a timeout. If GCC<4.9.0 it will use pthread functions directly as workaround. Older G++
*               versions don't manage timed_mutex.try_lock_for() correctly.
*  20160516 : - fixed some compiling issues for old compilers when SSL_CTX_new() must have a SSL_METHOD* and not
*               a const SSL_METHOD* (merged 20160919)
*  20160420 : - get_from_uri() arguments separated in extract_uri_arguments to make x-www-form-urlencoded
*               easier to parse.
*  20160201 : - select() is now static function too and can handle just one fd, but you can specify.
*             - receive_fixed don't run input filters on timeout anymore when read_once is enabled
*  20160129 : - Allowing or denying connection filters
*  20160128 : - Incoming connection log 
*             - Incoming connection reject message and callback
*             - Connection filters and policies are not ready. 
*               DON'T USE THIS VERSION
*  20160127 : - Deleting closed connections from memory
*  20160126 : - MatchIP matches IP ranges by CIDR (x.x.x.x/y) or by wildcard (x.x.*.*) with option Not Only CIDR
*  20151216 : - Clean SSL context and structure when disconnect()
*  20151212 : - URI struct now know if it's a secure or a non-secure service.
*             - Bug fixed: Segfault when server has port open but isn't accepting connections
*             - connect() now support Glove::uri and string as uri
*             - Glove() constructor now support direct URI connection
*  20151211 : - Automatically get port when getting from URI
*  20151210 : - Bug fixing in non-ssl connections trying to call ssl functions (regression)
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
*  1 - Match IP for IPv6
*  2 - epoll support
*  6 - be able to connect with protocol/service names
*  7 - set_option(...) allowing a variadic template to set every client or server option
*  8 - allowed client list (IPs list with allowed clients)
*  8 - create GloveHTTP behind GloveHTTPServer and GloveHTTPClient
*  9 - logger callback
* 10 - test_connected fussion with is_connected()
* 11 - GloveBase::getServByPort() must check _additional services
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
 *  37: "Given IP Address is not valid"
 *      Found on GloveBase::inet_pton4() when doing inet_pton() and it results 0
 *  38: "Wrong family specified"
 *      Found on GloveBase::inet_pton4() when doing inet_pton() and it results <0
 *  39: "Wrong CIDR input"
 *      Found on GloveBase::getNetworkAndMask() when validating CIDR expression
 *  40: "SSL Timeout. Some kind of bug makes SSL_read() freeze with strange server response on
 *      certain openSSL versions. With this, an additional timeout is applied, and this
 *      timeout has ran out.
 *  41: "SSL Method not specified"
 *      Found on Glove::getSSLClientMethod() and Glove::getSSLServerMethod() when SSL connection
 *      method is not in ssl_options.ssl_method.
 *  42: "Failed setting TLS host name"
 *      Found on Glove::SSLClientHandshake() when setting tlsext_host_name.
 *
 */
#undef _GLIBCXX_USE_CLOCK_MONOTONIC
#include "glove.hpp"
#include "glovecoding.hpp"
#include <cstring> // memset(), strerror()
#include <iostream> // debug only
#include <arpa/inet.h>
#include <netinet/tcp.h> // TCP_NODELAY 
#include <thread>
#include <mutex>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bitset>
#include <iomanip>

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

/* These constants may help developers when handling errors */
/* Number separation is intended to insert more log types when
   using other layer services like http, websockets, etc. These
   services may have CRITICAL or ERROR for this particular layer.*/
const uint16_t LOG_CRITICAL = 0; /* Live or death errors */
const uint16_t LOG_ERROR = 20;		 /* Errors*/
const uint16_t LOG_WARNING = 40;	 /* Warnings*/
const uint16_t LOG_NOTICE = 60;	 /* Notices*/
const uint16_t LOG_PROCESS = 80;	 /* Process exaplaining */

std::map<std::string, uint16_t> GloveBase::_additionalServices = {
	{ "ws",    80  }, 								/* Web Sockets */
	{ "wss",   443 }									/* Web Sockets (secure)*/
};

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

  /* Some bundled functions to make life easier */
  static timeval as_timeval ( double seconds )
  {
    timeval tv;
    tv.tv_sec = (int)(seconds);
    tv.tv_usec = (int)((seconds - (int)(seconds)) * 1000000.0);
    return tv;
  }

	/* std::stod is fast, sprintf is faster, but this is faster
	   and it's just what i want in some cases. */
  char* __itoa(int val, char* buf)
  {
    int i = 10;
    for(; val && i ; --i, val /= 10)
      {
		  buf[i] = "0123456789"[val % 10];
      }

    return &buf[i+1];
  }

  template <typename delimiters_t>
  std::vector< std::string > split(const std::string & str, const delimiters_t & sep, uint32_t maxsplit = 0)
  {
    std::vector< std::string > result;

    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(sep, 0);
    // Find first "non-delimiter".
    std::string::size_type pos     = str.find_first_of(sep, lastPos);

    while (std::string::npos != pos || std::string::npos != lastPos)
      {
        // Found a token, add it to the vector.
        result.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(sep, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(sep, lastPos);
      }

      return result;
  }

  int _serverFilterMatchIp (const Glove* server, std::string ipAddress, std::string hostname, uint16_t remotePort, std::string data0, std::string data1, uint32_t data2, double data3)
  {
    /* data0 stores the CIDR or mask */
    /* data2 is 0 to deny CIDR, any othre value is to accept */
    if (GloveBase::matchIp(ipAddress, data0))
      return (data2)?1:-1;
    else
      return 0;
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

/* Support for older versions of GCC */
#if defined(__GNUC__) && (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ <= 50200 )
  namespace std
  {
    static std::string put_time( const std::tm* tmb, const char* fmt )
    {
      std::string s( 128, '\0' );
      size_t written;
      while( !(written=strftime( &s[0], s.size(), fmt, tmb ) ) )
        s.resize( s.size() + 128 );
      s[written] = '\0';

      return s.c_str();
    }
  }
#endif

namespace
{
  /**
   * Writes formatted time on string
   *
   */
  std::string timeformat(const std::chrono::system_clock::time_point& moment, const std::string &format)
  {
    std::tm tm;
    const time_t tim = std::chrono::system_clock::to_time_t(moment);
    localtime_r(&tim, &tm);
		std::stringstream ss;
		ss << std::put_time(&tm, format.c_str());
		return ss.str();
  }
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

void GloveBase::log(uint8_t type, uint16_t code, std::string message, std::string more)
{
		if (_loggerCallback == nullptr)
			return;
		_loggerCallback(type, code, message, more);	
}

bool GloveBase::is_connected()
{
  char buf;

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
      return false;
    }
	return true;
}

int GloveBase::matchIp(const uint32_t address, const uint32_t network, const uint8_t bits=24)
{
  /* Some inspiration for IPv6:
     https://github.com/symfony/http-foundation/blob/652e8af9d22c16c5b6556048136021db0b8c6640/IpUtils.php
     http://stackoverflow.com/questions/7213995/ip-cidr-match-function

  */
  // from addr4_match() method: http://fxr.watson.org/fxr/source/include/net/xfrm.h?v=linux-2.6#L840
  if (bits == 0)
    return true;

  return !((address ^network) & htonl(0xFFFFFFFFu << (32 - bits)));
}

int GloveBase::matchIp(const std::string address, const std::string cidr, bool notOnlyCIDR, bool noException)
{
  in_addr ipAddress;
  int pton_res;

  pton_res = inet_pton4(address, &ipAddress, noException);
  if (pton_res<=0)
    return -1;
  /* Only IP4 at this moment */
  auto baseIpAndMask = GloveBase::getNetworkAndMask(cidr, notOnlyCIDR, noException);

  return !((ipAddress.s_addr ^ baseIpAndMask.first) & baseIpAndMask.second);
}

int GloveBase::inet_pton4(const std::string addr, in_addr* result, bool noException)
{
  int pton_res = inet_pton(AF_INET, addr.c_str(), result);
  if (!noException)			/* If we want exceptions*/
    {
      if (pton_res == 0)
	{
	  throw GloveException(37, "Given IP Address is not valid");
	}
      else if (pton_res<0)
	{
	  throw GloveException(38, "Wrong family specified.");
	}
    }
  return pton_res;
}

std::pair<uint32_t, uint32_t> GloveBase::getNetworkAndMask(const std::string cidr, bool notOnlyCIDR, bool noException)
{
  uint32_t mask = 0xFFFFFFFFu, finalAddress;
  auto slash = cidr.find('/');

  if (slash != std::string::npos)
    {
      /* Have slash ! */
      auto addressStr = cidr.substr(0, slash);
      auto bitsQty = std::stoi(cidr.substr(slash+1));
      if ( (bitsQty<0) || (bitsQty>32) )
	{
	  if (noException)
	    return std::pair<uint32_t, uint32_t>(0, 0);
	  else
	    throw GloveException(39, "Wrong CIDR input");
	}
      mask = mask << (32 - bitsQty);
      in_addr tempNw;

      /* Return only if noException */
      if (inet_pton4(addressStr, &tempNw, noException)<=0)
	return std::pair<uint32_t, uint32_t>(0, 0);

      finalAddress = tempNw.s_addr;
    }
  else if (notOnlyCIDR)
    {
      auto ipNumbers = split(cidr, ".");
      if (ipNumbers.size()!=4)
	throw GloveException(39, "Wrong CIDR input");
      uint32_t mult=1;
      finalAddress=0;
      mask=~0;
      for (auto n=ipNumbers.rbegin(); n!= ipNumbers.rend(); ++n)
	{
	  if (*n=="*")
	    {
	      mask-=0xff*mult;
	    }
	  else
	    {
	      finalAddress+= std::stoi(*n)*mult;
	    }
	  mult*=256;
	}
      finalAddress = htonl(finalAddress);
      /* Don't have a slash */
    }
  else
    {
      in_addr tempNw;

      if (inet_pton4(cidr, &tempNw, noException)<=0)
	return std::pair<uint32_t, uint32_t>(0, 0);

      finalAddress=tempNw.s_addr;
      mask=(uint32_t)~0;
      /* Only CIDR or simple IP */
    }
  return std::pair<uint32_t, uint32_t>(finalAddress, htonl(mask));
}

void GloveBase::register_dtm()
{
  start_dtm = std::chrono::system_clock::now();
}

std::string GloveBase::append_errno(std::string message)
{
  return message +std::string(strerror(errno));
}

int GloveBase::select(int fd, const double timeout, int test)
{
    // set up the file descriptor set
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
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
    int ret = SELECT(fd+1, rset, wset, NULL, &tv);

    return ( ret == -1 ? fd = -1, TCP_ERROR : ret == 0 ? TCP_TIMEOUT : TCP_OK );
}

int GloveBase::select(const double timeout, int test)
{
  return GloveBase::select(conn.sockfd, timeout, test);
    /* // set up the file descriptor set */
    /* fd_set fds; */
    /* FD_ZERO(&fds); */
    /* FD_SET(conn.sockfd, &fds); */
    /* fd_set *rset=NULL, *wset=NULL; */

    /* // set up the struct timeval for the timeout */
    /* timeval tv = as_timeval( timeout ); */

    /* if (test & SELECT_READ) */
    /*   rset=&fds; */

    /* if (test & SELECT_WRITE) */
    /*   wset=&fds; */

    /* // wait until timeout or data received */
    /* // if  tv = {n,m}, then select() waits up to n.m seconds */
    /* // if  tv = {0,0}, then select() does polling */
    /* // if &tv =  NULL, then select() waits forever */
    /* int ret = SELECT(conn.sockfd+1, rset, wset, NULL, &tv); */

    /* return ( ret == -1 ? conn.sockfd = -1, TCP_ERROR : ret == 0 ? TCP_TIMEOUT : TCP_OK ); */
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
									{
										if (_read_once) /* If we return directly we won't apply filters on timeout */
											return "";
										else
											break;
									}
								//		break;	// Sometimes we don't want to return an exception here.
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
			
/* #if ENABLE_OPENSSL */
/* 			std::cout << "SSL:"<<conn.secureConnection<<"\n"; */
/*       if (conn.secureConnection == ENABLE_SSL) */
/* 				{ */
/* 					std::cout << "SSL ENABLED\n"; */
/* 					if (default_values.ssltimeout) */
/* 						{ */
/* 							std::timed_mutex sslreadmutex; */
/* 							sslreadmutex.lock(); */
/* 							std::thread sslthread([&]() { */
/* 									bytes_received = SSL_read(conn.ssl, &buffer[0], buffer.size()-1); */
/* 									sslreadmutex.unlock(); */
/* 								}); */
/* 							sslthread.detach(); */
/* #  if defined(__GNUC__) && (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ >= 40900 ) */
/* 							if (!sslreadmutex.try_lock_for(std::chrono::milliseconds((unsigned)(timeout*1000)))) */
/* 								{ */
/* #  else */
/* #    warning "Older GCC version, using workaround to get timed locks" */
/* 									struct timespec ttout; */
/* 									clock_gettime(CLOCK_REALTIME, &ttout); */
/* 									ttout.tv_nsec+= (unsigned)(((long double)timeout-floor(timeout))*1000000000L); */
/* 									ttout.tv_sec += (time_t)floor(timeout)+ttout.tv_nsec/1000000000L ; */
/* 									ttout.tv_nsec= ttout.tv_nsec%1000000000L; */
/* 									int pmt = pthread_mutex_timedlock(sslreadmutex.native_handle(), &ttout); */
/* 									if (pmt!=0) */
/* #  endif */
/* 										{ */
/* 											pthread_cancel(sslthread.native_handle()); */
/* 											throw GloveException(40, "Timed out while receiving SSL data"); */
/* 										} */

/* 										sslreadmutex.unlock(); */
/* #  if defined(__GNUC__) && (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ >= 40900 ) */
/* 								} */
/* #  endif */
/* 						} */
/* 					else */
/* 						bytes_received = SSL_read(conn.ssl, &buffer[0], buffer.size()-1); */
/* 				} */
/* 			else */
/* #endif */
#if ENABLE_OPENSSL
      if (conn.secureConnection == ENABLE_SSL)
	{
	  if (default_values.ssltimeout)
	    {
	      std::timed_mutex sslreadmutex;
	      sslreadmutex.lock();
	      std::thread sslthread([&]() {
		  bytes_received = SSL_read(conn.ssl, &buffer[0], buffer.size()-1);
		  sslreadmutex.unlock();
		});
	      sslthread.detach();
#  if defined(__GNUC__) && (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ >= 40900 )
	      if (!sslreadmutex.try_lock_for(std::chrono::milliseconds((unsigned)(timeout*1000))))
		{
#  else
#  warning "Older GCC version, using workaround to get timed locks"
		  struct timespec ttout;
		  clock_gettime(CLOCK_REALTIME, &ttout);
		  ttout.tv_nsec+= (unsigned)(((long double)timeout-floor(timeout))*1000000000L);
		  ttout.tv_sec += (time_t)floor(timeout)+ttout.tv_nsec/1000000000L ;
		  ttout.tv_nsec= ttout.tv_nsec%1000000000L;
		  int pmt = pthread_mutex_timedlock(sslreadmutex.native_handle(), &ttout);
		  if (pmt!=0)
		    {
#  endif
		      pthread_cancel(sslthread.native_handle());
		      throw GloveException(40, "Timed out while receiving SSL data");
		    }
		  else
		    sslreadmutex.unlock();
		}
	      else
		bytes_received = SSL_read(conn.ssl, &buffer[0], buffer.size()-1);
	}
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
					if ( (conn.secureConnection == ENABLE_SSL) && (pending_bytes = SSL_pending(conn.ssl)) )
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
  else 
    {
      if (SHUTDOWN(conn.sockfd, how) < 0)
	throw GloveException(20, append_errno("Socket was not shutted down successfully"));
    }
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
	 if (!service.empty())
		 {
			 uint16_t defport = getServByName(service);
			 if (!defport)
				 throw GloveUriException(1001, "Could'nt find service");

			 res=service + std::string("://")+user_and_pass(username, password)+host;

			 if ( port > 65535 )
				 throw GloveUriException(1002, "Port must be lower than 65536");

			 if ( (port != 0) && (defport != port) )
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

 std::map<std::string, std::string> GloveBase::extract_uri_arguments(std::string& rawArguments, std::string& fragment, bool urldecode)
 {
	 std::map<std::string, std::string> args;

	 auto _slash = rawArguments.find_first_of("&#");
	 std::string::size_type astart = 0;
	
	 auto get_new_key = [] (std::string key, std::string index) {
		 auto pos = key.find("[]");
		 if (pos != std::string::npos)
			 key.replace(pos, 2, "["+index+"]");
		 else
			 key+= "["+index+"]";
		 return key;
	 };
	 auto push_final = [&] (std::string key, std::string val) {
		 auto _key = key;
		 if (_key.find("[]") != std::string::npos)
			 _key.replace(_key.find("[]"), 2, "[");

		 int count = std::count_if(args.begin(), args.end(), [_key](std::pair<std::string, std::string> el) -> bool
		 {
			 return (el.first.find(_key) != std::string::npos);
		 });
		 if (count>0)
			 {
				 auto alone = args.find(key);
				 std::string newKey;
				 if (alone != args.end())
					 {
						 auto alone_copy(*alone);
						 args.erase(alone);
						 args[get_new_key(alone_copy.first,"0")] = alone_copy.second;
					 }
				 args[get_new_key(key, std::to_string(count))] = val;
			 }
		 else
			 args[key] = val;
	 };
	
	 auto push_argument = [&] (/* bool zerostart=false */) {
		 /* if ( (!zerostart) && (astart==0) ) */
		 /* 	 return; */
		 std::string temp2 = rawArguments.substr(astart, _slash-astart);
		 auto _equal = temp2.find('=');
		 if (urldecode)
			 {
				 if (_equal != std::string::npos)
					 push_final(GloveCoding::urldecode(temp2.substr(0,_equal)), GloveCoding::urldecode(temp2.substr(_equal+1)));
				 else
					 push_final(GloveCoding::urldecode(temp2), "");
			 }
		 else
			 {
				 if (_equal != std::string::npos)
					 push_final(temp2.substr(0,_equal), temp2.substr(_equal+1));
				 else
					 push_final(temp2, "");
			 }
	 };

	 do
		 {
			 if (_slash == std::string::npos)
				 {
					 _slash = rawArguments.length();
					 push_argument();
					 break;
				 }
			 if (rawArguments[_slash] == '&')
				 {
					 push_argument(/* true */);
				 }
			 else if (rawArguments[_slash] == '#')
				 {
					 push_argument();
					 fragment = rawArguments.substr(_slash+1);
					 rawArguments = rawArguments.substr(0, _slash);
					 break;
				 }

			 astart = _slash+1;
		 } while (_slash = rawArguments.find_first_of("&#", _slash+1)/* , astart != rawArguments.length() */ );

	 return args;
 }

// Ladies and gentlemen, the unmaintainable !
 GloveBase::uri GloveBase::get_from_uri (const std::string &uristring, bool urldecode, bool resolve, std::string service_separator)
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
		 throw GloveUriException(1005, "Can't find service separator '"+service_separator+"' in provided URI ('"+uristring+"')");

	 _uristring = uristring.substr(_space+service_separator.length());
	 _uri.service=uristring.substr(0, _space);
	 _uri.secure= (Glove::detectSecureService(_uri.service) == ENABLE_SSL);

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
							 _uri.port = 0;
							 auto __port = getServByName(_uri.service);
							 if (__port)
								 _uri.port = __port;

							 _uri.host = temp;
						 }
					 _uri.rawpath = _uristring.substr(_slash);
				 }
			 else if (start+1 != _slash)
				 _uri.path.push_back((urldecode)?GloveCoding::urldecode(temp):temp);
			 if ( (_uristring[_slash] == '?') || (_uristring[_slash] == '#') )
				 {
					 _uri.rawarguments = _uristring.substr(_slash+1);
					 _uri.arguments = extract_uri_arguments(_uri.rawarguments, _uri.fragment, urldecode);
					 break;
				 }

			 start = _slash;

		 } while (_slash = _uristring.find_first_of("/?#", _slash+1), start != _uristring.length() );

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

	/* Test additional services? Maybe one day in the future */
  return "";
}

uint16_t GloveBase::getServByName(std::string name)
{
	servent *srv = getservbyname(name.c_str(), "tcp");
	if (srv == NULL)
		{
			/* We must test some additional services */
			auto has = _additionalServices.find(name);
			return (has != _additionalServices.end())?has->second:0;
		}
	else
		return htons(srv->s_port);
}


// Glove::Glove(): connected(false), _shutdown_on_destroy(false), _resolve_hostnames(false), thread_clients(true), thread_server(true), server_reuseaddr(true), max_accepted_clients(2), _server_error_callback(NULL), accept_clients(false), clientId(0)
Glove::Glove(): connected(false), _shutdown_on_destroy(false), server_options({false, true, true, true, GLOVE_DEFAULT_MAX_CLIENTS, GLOVE_DEFAULT_ACCEPT_WAIT, true, true, false, 0, 1}), _server_error_callback(NULL), accept_clients(false), clientId(0)
{
  default_values.buffer_size=GLOVE_DEFAULT_BUFFER_SIZE;
  maxConnectionsBuffer = GLOVE_DEFAULT_MAX_CONNECTIONS_BUFFER;
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

Glove::Glove(const Glove::uri &uri, double timeout, int domain, int secure)
{
  connect(uri, timeout, domain, secure);
}

Glove::Glove(const std::string& uri, double timeout, int domain, int secure)
{
  connect(uri, timeout, domain, secure);
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
	throw GloveException(2, append_errno("Failed to resolve ("+std::to_string(error)+"): "));
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
	 for (rp = servinfo; rp != NULL && this->connected==false; rp = rp->ai_next) 
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

	 if (secure == ENABLE_SSL)
		 {
			 bool hndshk = SSLClientHandshake(host);
			 
			 if ( (hndshk) && (ssl_options.flags & SSL_FLAG_GET_CIPHER_INFO) )
				 SSLGetCipherInfo();

			 if ( (hndshk) && (ssl_options.flags & SSL_FLAG_GET_CERT_INFO) )
				 SSLGetCertificatesInfo();
		 }
# endif
	 errno = 0;			// clear remaining connect_nonblocking error
 }

 void Glove::connect(GloveBase::uri uri, double timeout, int domain, int secure)
 {
	 if (secure == AUTODETECT_SSL)
    secure = (uri.secure)?ENABLE_SSL:DISABLE_SSL;

  connect(uri.host, uri.port, timeout, domain, secure);
}

void Glove::connect(const std::string uri, double timeout, int domain, int secure)
{
  connect(Glove::get_from_uri(uri, false), timeout, domain, secure);
}

#if ENABLE_OPENSSL
/* All these things will be only in compilations with SSL enabled */

void Glove::setSSLDefaultValues()
{
  ssl_options.ssl_method = SSLv23;
  ssl_options.flags = SSL_FLAG_VERIFY_CA;
  ssl_options.CApath = GLOVE_DEFAULT_SSL_CAPATH;
  default_values.ssltimeout=true;
}

void Glove::initializeOpenSSL()
{
  if (!openSSLInitialized)
    {
			static std::mutex init_mutex;
			std::lock_guard<std::mutex> lock(init_mutex);
			
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
  conn.ctx = SSL_CTX_new(getSSLServerMethod());
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

 bool Glove::SSLClientHandshake(std::string host, bool exception_on_handshake_failure)
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

	if (SSL_set_tlsext_host_name(conn.ssl, host.c_str())!= 1)
		throw GloveException(42, "Failed setting TLS host name");
	
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

const SSL_METHOD* Glove::getSSLServerMethod()
{
  switch (ssl_options.ssl_method)
    {
    case SSLv23 : return SSLv23_server_method();
    case SSLv3  : return SSLv3_server_method();
    case TLSv1  : return TLSv1_server_method();
    case TLSv1_1: return TLSv1_1_server_method();
    case TLSv1_2: return TLSv1_2_server_method();
    case DTLSv1 : return DTLSv1_server_method();
		default:
			throw GloveException(41, "SSL method not specified");
    }
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
		default:
			throw GloveException(41, "SSL method not specified");
    }
}

long Glove::getSSLVerifyState()
{
  if (conn.secureConnection == DISABLE_SSL)
    return -1;

  return conn.cert_verify_result;
}

std::string Glove::getSSLVerifyString()
{
  if (conn.secureConnection == DISABLE_SSL)
    return "Not a secure connection";

  return conn.cert_error_string;
}

void Glove::SSLGetCipherInfo()
{
  if (conn.cipher_info_present)
    return;

  if (conn.secureConnection == DISABLE_SSL)
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
  if (conn.secureConnection == DISABLE_SSL)
    return "";
  if (!conn.cipher_info_present)
			SSLGetCipherInfo();

  return conn.ssl_version;
}

std::string Glove::getSSLCipherName()
{
  if (conn.secureConnection == DISABLE_SSL)
    return "";
  if (!conn.cipher_info_present)
    SSLGetCipherInfo();

  return conn.cipher_name;
}

std::string Glove::getSSLCipherVersion()
{
  if (conn.secureConnection == DISABLE_SSL)
    return "";
  if (!conn.cipher_info_present)
    SSLGetCipherInfo();

  return conn.cipher_version;
}

std::string Glove::getSSLCipherDescription()
{
  if (conn.secureConnection == DISABLE_SSL)
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

  if (conn.secureConnection == DISABLE_SSL)
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
    {
      return ENABLE_SSL;
    }
  else
    {
      return DISABLE_SSL;
    }
}

void Glove::disconnect(int how)
{
  if (!test_connected())
    return;
  /* std::cout << "DISCONNECTING SOCKET\n"; */
#if ENABLE_OPENSSL
  /* If we opened a secure connection we must also close it */
  if ( (how==SHUT_XX) && (conn.secureConnection == ENABLE_SSL) )
    {
      SSL_shutdown(conn.ssl);
      SSL_CTX_free(conn.ctx);
      SSL_free(conn.ssl);
    }
#endif
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

	connected = GloveBase::is_connected();
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

	/* Save it to detect local connections */
	boundIp = bind_ip;
	
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
			conn.cipher_info_present = false;
			conn.certificates_info_present = false;			
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

 bool Glove::isLocal(std::string& ipAddress)
 {
	 /* Only IPv4 now */
	 if (ipAddress.empty())
		 return false;
	 if (ipAddress.length()<7)
		 return false;
	 if (ipAddress.substr(0,3)=="127")
		 return true;
	 if (ipAddress == boundIp)
		 return true;

	 return false;
 }

 
void Glove::serverRejectConnection()
{
  Conn_description client_conn;
  sockaddr_in client;
  socklen_t client_len = sizeof(client);
  std::string ipaddress;

  memset(&client, 0, client_len);

  client_conn.sockfd = ACCEPT (conn.sockfd, (struct sockaddr *)&client, &client_len);

  if (client_conn.sockfd<0)
    {
      logConnection("", "", ACCEPT_ERROR);
      // Error!! But not big enough to throw an exception
      return;
    }
  char _ipaddress[INET_ADDRSTRLEN];

  if ( inet_ntop(AF_INET,  &(client.sin_addr), _ipaddress, INET_ADDRSTRLEN) != NULL)
    ipaddress=_ipaddress;
  logConnection(ipaddress, "", CONNECTION_DENIED_BY_TOO_MANY);

  /* If we have a tmcRejectCb, create a Client to send the message */
  if (tmcRejectCb)
    {
      Client *c;
      c = (server_options.copy_options)?new Client(client_conn, 0, isLocal(ipaddress), ipaddress, "", default_values):new Client(client_conn, 0, isLocal(ipaddress), ipaddress, "");
      c->send(tmcRejectCb(c));
      delete c;
    }
  /* Close connection */
  close(client_conn.sockfd);

}

 bool Glove::create_worker(Glove::client_callback cb)
 {
	 sockaddr_in client;
	 socklen_t client_len = sizeof(sockaddr_in);
	 memset(&client, 0, client_len);

	 if (getTotalConnectedClients()>=server_options.max_accepted_clients)
		 {
			 int selectResult = select(1, SELECT_READ);
			 if (selectResult==TCP_OK)
				 {
					 /* Detect if there is an incomming connection here,
							if so. Accept it and close it inmediately to 
							deny access if it's configured to do so. */
					 if (server_options.reject_connections)
						 {
							 double totalTime=0;
							 while ( (totalTime<server_options.wait_before_reject_connection) && (getTotalConnectedClients()>=server_options.max_accepted_clients) )
								 {
									 totalTime+=0.1;
									 std::this_thread::sleep_for(std::chrono::milliseconds(100));
								 }
							 if (getTotalConnectedClients()>=server_options.max_accepted_clients)
								 {
									 /* If after waiting we still have a lot of connections, reject connection */
									 serverRejectConnection();
									 return false;
								 }
						 }
					 else
						 {
							 /* Sleep a little bit to prevent high CPU load. Just wait for client to timeout */
							 std::this_thread::sleep_for(std::chrono::milliseconds(server_options.accept_wait));
							 return false;
						 }
				 }
			 else
				 {
					 std::this_thread::sleep_for(std::chrono::milliseconds(server_options.accept_wait));
					 return false;
				 }
		 }
	 Conn_description client_conn;
	 /* Disable SSL temporary, before initializing client */
	 client_conn.secureConnection=DISABLE_SSL;

	 client_conn.sockfd = ACCEPT (conn.sockfd, (struct sockaddr *)&client, &client_len);
	 if (client_conn.sockfd<0)
		 {
			 logConnection("", "", ACCEPT_ERROR);
			 // Error!! But not big enough to throw an exception
			 /* No need to shutdown client. invalid socket */
			 return false;
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

	 if ( inet_ntop(AF_INET,  &(client.sin_addr), _ipaddress, INET_ADDRSTRLEN) != NULL)
	 	 ipaddress=_ipaddress;

	 uint8_t accepted=server_options.default_conn_policy;
	 bool logged = false;
	 for (auto f : connection_filters)
	 	 {
	 		 auto fi = f.second;
	 		 auto res = fi.cb(this, ipaddress, hostname, client.sin_port, fi.data0, fi.data1, fi.data2, fi.data3);
	 		 if (res<0)
	 			 {
	 				 accepted = 0;
	 				 logged = true;
	 				 logConnection(ipaddress, hostname, CONNECTION_DENIED_BY_FILTER, f.first);
	 			 }
	 		 else if (res>0)
	 			 accepted = 1;
	 		 /* Nothing to do if res == 0 */
	 	 }
	 if (accepted==0)
	 	 {
	 		 close(client_conn.sockfd);
	 		 if (!logged)
	 			 logConnection(ipaddress, hostname, CONNECTION_DENIED_BY_POLICY);
	 		 /* Connection not accepted by filters */
	 		 return shutdown_client(client_conn);
	 	 }
#if ENABLE_OPENSSL

	 if (conn.secureConnection== ENABLE_SSL)
		 {
			 /*  */
			 client_conn.ctx = conn.ctx;
			 client_conn.ssl = SSL_new(client_conn.ctx);

			 if (client_conn.ssl ==NULL)
				 {
					 logConnection(ipaddress, hostname, SSL_CONNECTION_ERROR);
					 return shutdown_client(client_conn);
				 }
			 /* At this point, if we have an error, must SHUT DOWN SSL
				in the client. */
			 client_conn.secureConnection = conn.secureConnection;

			 if (SSL_set_fd(client_conn.ssl, client_conn.sockfd) == 0)
				 {
					 logConnection(ipaddress, hostname, SSL_CONNECTION_ERROR);
					 return shutdown_client(client_conn);
				 }

			 if (SSL_accept(client_conn.ssl) < 1)
			 	 {
			 		 logConnection(ipaddress, hostname, SSL_ACCEPT_ERROR);
			 		 return shutdown_client(client_conn);
			 	 }
		 }
#endif
	 logConnection(ipaddress, hostname, CONNECTION_ACCEPTED);

	 Client *c;
	 clients_connected_mutex.lock();
	 unsigned thisClient = clientId++;
	 if (server_options.copy_options)
		 c = new Client(client_conn, thisClient, isLocal(ipaddress), ipaddress, hostname, default_values);
	 else
		 c = new Client(client_conn, thisClient, isLocal(ipaddress), ipaddress, hostname);

	 c->loggerCallback(_loggerCallback); /* Inherit logger callback*/

	 clients_connected.insert(std::pair<int, Client*>(thisClient, c));
	 clients_connected_mutex.unlock();

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
	 return true;
 }

 bool Glove::shutdown_client(Conn_description& client_conn)
 {
#if ENABLE_OPENSSL
	 if (client_conn.secureConnection == ENABLE_SSL)
		 {
			 /* openSSL is a bit tricky closing connections.
					Call SSL_shutdown() once to send a shutdown message and
					wait for the other part to allow you to disconnect. */
			 /* Let's wait in intervals of 0.01s, if an error comes
					SSL_shutdow()<0 or a success SSL_shutdown()=1, exit.
			 */
			 /* If there's an error, we will close drastically the connection
					with CLOSE(), if not, the connection will be successfully closed*/
			 int sdr = SSL_shutdown(client_conn.ssl);
			 int times=0;
			 while ( (sdr==0) && (times++<10) )
				 {
					 select(client_conn.sockfd, 0.01);
					 sdr = SSL_shutdown(client_conn.ssl);
				 }
			 SSL_free(client_conn.ssl);
		 }
#endif
	 CLOSE(client_conn.sockfd);
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
	 
	 shutdown_client(client_conn);
	 clients_connected_mutex.lock();
	 clients_connected.erase( clients_connected.find(client_id) );
	 clients_connected_mutex.unlock();
	 delete c;
 }

std::string Glove::debugLoggedConnections()
{
  std::string out ="";
  for (auto c : connections_logged)
    {
      out+="["+timeformat(c.start, "%d/%m/%Y %H:%M:%S")+"] "+c.ipAddress+" ("+c.hostName+") Status: ";
      switch (c.state)
	{
	case CONNECTION_ACCEPTED: 
	  out+="Accepted";
	  break;
	case ACCEPT_ERROR:
	  out+="Error accepting";
	  break;
	case CONNECTION_DENIED_BY_POLICY:
	  out+="Denied by Policy.";
	  break;
	case CONNECTION_DENIED_BY_TOO_MANY:
	  out+="Denied by too many connections";
	  break;
	case CONNECTION_DENIED_BY_FILTER:
	  out+="Denied by Filter: "+std::to_string(c.filter);
	  break;
	case CONNECTION_DENIED_BY_OTHER:
	  out+="Denied by Other.";
	  break;
	default:
	  out+="Unknown status";
	}
      out+="\n";
    }
  return "";
}

void Glove::logConnection(std::string ipAddress, std::string hostName, Glove::ConnectionLogState state, uint32_t filterId)
{
  if (!server_options.incoming_log)
    return;

  connections_logged.push_back ({ipAddress, hostName, std::chrono::system_clock::now(), state, filterId });
  if (connections_logged.size()>maxConnectionsBuffer)
    connections_logged.pop_front();
}

void Glove::tmcRejectMessage(std::string msg)
{
  tmcRejectCb = [msg] (Client* c) { return msg; };
}

void Glove::tmcRejectCallback(std::function <std::string (Client* c)> cb)
{
  tmcRejectCb = cb;
}

void Glove::tmcRejectDisable()
{
  tmcRejectCb = 0;
}

void Glove::addConnectionFilter(Glove::connection_filter_callback cb, std::string data0, std::string data1, uint32_t data2, double data3)
{
  connection_filters.insert({connection_filters.size(), {cb, data0, data1, data2, data3}});
}

void Glove::deleteConnectionFilter(uint32_t filterId)
{
  auto f = connection_filters.find(filterId);
  if (f != connection_filters.end())
    connection_filters.erase(f);
}

void Glove::serverAllowIp(std::string cidr)
{
  addConnectionFilter(_serverFilterMatchIp, cidr, "", 1);
}

void Glove::serverDisallowIp(std::string cidr)
{
  addConnectionFilter(_serverFilterMatchIp, cidr, "", 0);
}

void Glove::serverDisallowFastConnection(double time, uint32_t connections)
{
  addConnectionFilter([&] (const Glove* server, std::string ipaddress, std::string hostname, uint16_t port, std::string d0, std::string d1, uint32_t d2, double d3)
		      {
			/* time is d3 
			   connections is d2 */

			/* If there aren't enough logged connections, the filter
			   won't apply. */
			uint32_t entries = ((Glove*)server)->countLoggedConnections();
			if (entries<d2)
			  return 0;

			Glove::ConnectionLog cl;
			if (!getLoggedConnection(cl, entries-d2))
			  return 0; /* Error getting, but not a hard fail. */

			double timeBetweenConns = std::chrono::duration_cast<std::chrono::duration<double,std::ratio<1>>>(std::chrono::system_clock::now()-cl.start).count();
			std::cout << "time between last "<<d2<<" connections: "<<timeBetweenConns<<std::endl;
			return (timeBetweenConns<d3)?-1:0;
		      }, "", "", connections, time);
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
