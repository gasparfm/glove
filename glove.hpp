/**
*************************************************************
* @file glove.hpp
* @brief Tiny and standalone TCP socket C++11 wrapper and more
*************************************************************/

#ifndef _GLOVE_HPP
#define _GLOVE_HPP 10

/**
 * By default enable openssl. This compiles glove with SSL support
 * More complex but we can make a secure connection transparently
 */
#ifndef ENABLE_OPENSSL
#   define ENABLE_OPENSSL 1
#endif

/**
 * Library debug level.
 *  > 0   :
 *          - Loads SSL error strings
 */
#ifndef GLOVEDEBUG
#   define GLOVEDEBUG 1
#endif

#include "gloveexception.hpp"
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <ctime>
#include <chrono>
#include <map>
#include <deque>
#include <sstream>
#include <iostream>		// debug only
#include <algorithm>
#include <sys/socket.h>
#include <netdb.h>

#if ENABLE_OPENSSL
#    include <openssl/rand.h>
#    include <openssl/ssl.h>
#    include <openssl/err.h>
#endif

/**
   Default timeout (in seconds)for all connections. Maybe you want to increase it a little bit,
   for testing, 1second was enough.
 */
#define GLOVE_DEFAULT_TIMEOUT 1

/**
   Default domain. AF_INET for ipv4, AF_INET6 por ipv6. @see inet_pton() manual 
 */
#define GLOVE_DEFAULT_DOMAIN AF_INET

/**
   Default reception buffer size.
 */
#define GLOVE_DEFAULT_BUFFER_SIZE 2048

/**
   Default max simultaneous clients for server mode
 */
#define GLOVE_DEFAULT_MAX_CLIENTS 10

/**
   If max clients is reached, will change accept() by a sleep
 */
#define GLOVE_DEFAULT_ACCEPT_WAIT 2000

/**
   Default backlog queue for listen()
 */
#define GLOVE_DEFAULT_BACKLOG_QUEUE 10

/**
 * Default CA path for certificate verifying
 */
#define GLOVE_DEFAULT_SSL_CAPATH "/etc/ssl/certs"

/**
 * Default connections buffer size. It is the max. number of historic incomming
 * connections logged. It can give us information about old connections, clients
 * and so on
 */
#define GLOVE_DEFAULT_MAX_CONNECTIONS_BUFFER 100

namespace
{
  // this is the type of std::cout
  typedef std::basic_ostream<char, std::char_traits<char> > ostream_type;
	
  // this is the function signature of std::endl
  typedef ostream_type& (*ostream_manipulator)(ostream_type&);
};

/**
   Glove Base class for clients and servers with, I hope, all the common stuff.
 */
class GloveBase
{
public:
  typedef std::chrono::system_clock::time_point time_point;

  /**
     Controls the behaviour of select()
   */
  enum:int
    {
      /**
       * GloveBase::select() will use read sockets
       */
      SELECT_READ=1,

      /**
       * GloveBase::select() will use write sockets
       */
      SELECT_WRITE=2
    };

  /**
   * shutdown() behaviour control
   */
  enum
    {
      /**
       * Shutdown read
       */
      SHUT_R = SHUT_RD,
      /**
       * Shutdown write
       */
      SHUT_W = SHUT_WR,
      /**
       * Shutdown read-write
       */
      SHUT_RW= SHUT_RDWR,
      /**
       * Don't use shutdown, use close
       */
      SHUT_XX
    };

  /**
   * Exception generation options
   */
  enum:unsigned
    {
      /** Don't generate exceptions  */
      EXCEPTION_NONE = 0,
      /** Generate exception on timeout. 
	  Will be thrown on data receptions  */
      EXCEPTION_TIMEOUT = 1,	     // on reception
      /** Generate exception on peer disconnection.  */
      EXCEPTION_PEERDISCONNECT = 2,  // as client / server
      /** Generate exception on peer disconnection (new). Will
	  be thrown when receiving data*/
      EXCEPTION_DISCONNECTED = 4,    // mostly as client
      /** Generate all exceptions  */
      EXCEPTION_ALL = 65535
    };

  /**
   * Secure connection enable/disable
   */
  enum:int
    {
      /**
       * Use default SSL Setting
       */
      UNDEFINED_SSL = -9,
      /**
       * Autodetect secure setting with the service
       */
      AUTODETECT_SSL = -1,
      /**
       * Service connection/server is secure
       */
      ENABLE_SSL = 1,
      /**
       * Service connection/server is unsecure
       */
      DISABLE_SSL = 2
    };
  /**
   * Filters can be done before sending data of after receiving data
   */
  enum filter_type
    {
      /** Filter before sending data */
      FILTER_INPUT,
      /** Filter after receiving data  */
      FILTER_OUTPUT
    };

  /** 
   * Little structure with host information
   */
  struct hostinfo
  {
    /** Host name  */
    std::string host;
    /** IP address  */
    std::string ip_address;
    /** Service from /etc/services obtained with getservbyname()  */
    std::string service;
  };

  /**
     Uri components
   */
  struct uri
  {
    /** uri string  */
    std::string uri;
    /** host part */
    std::string host;
    /** every frament of the path: service.com/a/b/c => [] = a; [] = b; [] = c */
    std::vector < std::string > path;
    /** Path only => a/b/C  */
    std::string rawpath;
    /** Raw arguments of path: service.com/a/b?arg1=value1&arg2=value2 => arg1=value1&arg2=value2 */
    std::string rawarguments;
    /** arguments map => [arg1] = value1; [arg2] = value2  */
    /** NOT YET: you can choose argument start character (?), argument separator character (;) and argument assign character (=) */
    std::map<std::string, std::string> arguments;
    /** service used  */
    std::string service;
    /** URI fragment: service.com/a/b/c?arg1=value1#fragment  */
    std::string fragment;
    /** Username used  */
    std::string username;
    /** Password used  */
    std::string password;
    /* Secure service? */
    bool secure;
    /** List of hosts resolved by this host  */
    std::vector <GloveBase::hostinfo> ressolvedhosts;
    /** Port  */
    int port;

		std::string servicehost(std::string serv="")
		{
			if (serv.empty())
				serv=service;
			try
				{
					return GloveBase::build_uri(serv, host, port);
				}
			catch (GloveUriException& e)
				{
					return "";
				}
		}
    /**
     * DEBUG Only: used to get information about this URI, to print on
     *       screen/write to a file/etc, but not a suitable format for
     *       end users
     *
     * @return String with all the information
     */
    std::string uridebug()
    {
      std::string out = "URI: "+uri+"\n";
      out+="Host: "+host+"\n";
      out+="Path: "+rawpath+"\n";
      for (auto _pi = path.begin(); _pi != path.end(); ++_pi)
				out+= "   * "+*_pi+"\n";
      out+="Arguments: "+rawarguments+"\n";
      for (auto _pi = arguments.begin(); _pi != arguments.end(); ++_pi)
				out+= "   * "+_pi->first+" = "+_pi->second+"\n";
      out+="Service: "+service+" "+((secure)?"(SECURE)":"")+"\n";
      out+="Fragment: "+fragment+"\n";
      out+="Port: "+std::to_string(port)+"\n";
      out+="Username: "+username+"\n";
      out+="Password: "+password+"\n";

      return out;
    }
  };

	static const uint16_t LOG_CRITICAL;
	static const uint16_t LOG_ERROR;
	static const uint16_t LOG_WARNING;
	static const uint16_t LOG_NOTICE;
	static const uint16_t LOG_PROCESS;
	
  /**
   * Default constructor with the default values:
   *   Timeout = @see GLOVE_DEFAULT_TIMEOUT
   *   Exceptions = @see EXCEPTION_ALL
   *   Timeout when data = false
   *   Read once = false (Do all the neccessary read operations)
   *   Fixed read = 0 (unlimited read with operator <<)
   *   Buffer_size = @see GLOVE_DEFAULT_BUFFER_SIZE
   *   Input filters enabled
   *   Output filters enabled
   */
  GloveBase(): default_values({GLOVE_DEFAULT_TIMEOUT, EXCEPTION_ALL, false, false, 0, GLOVE_DEFAULT_BUFFER_SIZE, true, true}), _loggerCallback(nullptr)
  {
  }

  /** 
   * To-do: Destruction and cleanup
   */
  virtual ~GloveBase()
  {
  }

		  // get info...
  /**
   * Try to guess if the connection is open
   *
   * @return true if it is
   */
  bool is_connected();

	/**
	 * Set logger function
	 */
	void loggerCallback(std::function<void(uint8_t, uint16_t, std::string message, std::string moreData)> callback)
	{
		_loggerCallback = callback;
	}

	void log(uint8_t type, uint16_t code, std::string message, std::string more);
	
  static int matchIp(const uint32_t address, const uint32_t network, const uint8_t bits);
  static int matchIp(const std::string address, const std::string cidr, bool notOnlyCIDR=false, bool noException=true);
  /**
   * Get connected host
   *
   * @return connected host
   */
  std::string get_host()
  {
    return connectionInfo.host;
  }

  /**
   * Get connected service
   *
   * @return connected service
   */
  std::string get_service()
  {
    return connectionInfo.service;
  }

  /**
   * Get connected address
   *
   * @return connected address
   */
  std::string get_address()
  {
    return connectionInfo.ip_address;
  }

  /**
   * Get sock descriptor for manual operations
   *
   * @return sockfd
   */
  int get_sockfd()
  {
    return conn.sockfd;
  }

  /**
   * Macro to auto-generate getters and setters for some settings
   *
   * @param container  Struct where all values are
   * @param type       Data type (int, double, bool)
   * @param option     Option to be set or got
   *
   * @return Current value
   */
#define option_conf(container, type, option) type option(type val)	\
  {									\
    return (container.option=val);					\
  }									\
  									\
  type option()								\
  {									\
    return container.option;						\
  }

  /**
   * Getter and setter for buffer_size
   */
  option_conf(default_values, size_t, buffer_size);

  /**
   * Getter and setter for timeout
   */
  option_conf(default_values, double, timeout);

  /**
   * Getter and setter for timeout_when_data
   */
  option_conf(default_values, bool, timeout_when_data);

  /**
   * Getter and setter for enable_input_filters
   */
  option_conf(default_values, bool, enable_input_filters);

  /**
   * Getter and setter for enable_output_filters
   */
  option_conf(default_values, bool, enable_output_filters);

  /**
   * Getter and setter for exceptions
   */
  option_conf(default_values, unsigned, exceptions);

  /**
   * Enables exceptions. 
   *
   * @param exceptions   Exception or exceptions to enable
   */
  void enable_exceptions(int exceptions)
  {
    default_values.exceptions |=exceptions;
  }

  /** 
   * Disables exceptions
   *
   * @param exceptions   Exception or exceptions to disable
   */
  void remove_exceptions(int exceptions)
  {
    default_values.exceptions&=~exceptions;
  }

  static int select(int fd, const double timeout, int test);
  // socket handling
  /**
   * Performs a select() operation on the opened socket used
   * as read o write descriptor (depending on test value)
   *
   * @param timeout Time as double variable (in seconds)
   * @param test    SELECT_READ or SELECT_WRITE
   *
   * @see SELECT_READ @see SELECT_WRITE
   *
   * @return -1 on error, -2 on timeout, 0 if ok
   */
  int select(const double timeout, int test=SELECT_READ);

  /**
   * Sends data (abstract) may differ for client and server
   *
   * @param data Data to be sent
   */
  virtual void send(const std::string &data) = 0;

  /**
   * Receive data (abstract) differs for client and server
   *
   * @param timeout Timeout (-1 or nothing for default timeout)
   * @param read_once Perform just one read operation. -1 for default behaviour
   *
   * @return Data received as C++ string
   */
  virtual std::string receive(double timeout=-1, short read_once=-1) = 0;

  /**
   * Set socket options. See man setsockopt
   *
   * @param level  SOL_SOCKET and so
   * @param optname SO_ERROR, SO_REUSEADDR, SO_KEEPALIVE... 
   * @param optval Value
   * @param optlen Value size
   */
  void setsockopt(int level, int optname, void *optval, socklen_t optlen);

  /**
   * Get socket options. See man setsockopt
   *
   * @param level  SOL_SOCKET and so
   * @param optname SO_ERROR, SO_REUSEADDR, SO_KEEPALIVE... 
   * @param optval Variable to store value
   * @param optlen Value's variable size
   */
  void getsockopt(int level, int optname, void *optval, socklen_t *optlen);

  // When values are integers
  /**
   * Simple setsockopt for integer values
   *
   * @param optname (Currently supported: SO_KEEPALIVE, SO_REUSEADDR)
   * @param val Integer Value
   */
  void setsockopt(int optname, int val);

  /**
   * Simple getsockopt for integer values
   *
   * @param optname (Currently supported: SO_KEEPALIVE, SO_REUSEADDR)
   * @param val Integer Value
   */
  void getsockopt(int optname, int &val);

  /**
   * Get connected IP address and port
   *
   * @param ip     IP Address by reference
   * @param port   Port by reference
   * @param noexcp Don't throw exception on error
   */
  void get_address(std::string &ip, int &port, bool noexcp=false);

  /**
   * Gets only ip address
   *
   * @param noexcp Don't throw exception on error
   *
   * @return Current IP Address
   */
  std::string get_address(bool noexcp=false)
  {
    int port;
    return get_address(port, noexcp);
  }

  /**
   * Gets IP Address and port in a more comfortable way
   *
   * @param port    Port by ref
   * @param noexcp  Don't throw exception on error
   *
   * @return Current IP address
   */
  std::string get_address(int &port, bool noexcp=false)
  {
    std::string addr;
    get_address(addr, port, noexcp);
    return addr;
  }

#if ENABLE_OPENSSL
  /**
   * Gets current status of SSL Timeout
   */
  bool get_ssltimeout()
  {
    return default_values.ssltimeout;
  }

  /**
   * Sets current status of SSL Timeout
   */
  void set_ssltimeout(bool newTimeout)
  {
    default_values.ssltimeout = newTimeout;
  }
#endif

  /**
   * Gets connected port. It calls get_address() to get all the
   * information. And throw away what's not needed
   *
   * @param noexcp Don't throw exception on error
   *
   * @return Port
   */
  int get_connected_port(bool noexcp=false)
  {
    int port;
    get_address(port, noexcp);

    return port;
  }

  // stream operations and manipulators
  /**
   * Defines the << operator for variable types compatible with streams.
   * Used to send data through the socket.
   */
  template <typename T>
  GloveBase& operator<<(const T& x)
  {
    std::stringstream ss;
    ss<<x;

    this->send(ss.str());

    return *this;
  }

  /**
   * Defines the >> operator to fill a std::string with the information
   * received through the socket.
   */
  GloveBase& operator>>(std::string &out)
  {
    out=this->receive(default_values.timeout, default_values.read_once);

    return *this;
  }

  /**
   * Reception manipulators interface. We can use a GloveManipulator to
   * change the reception behaviour (increase timeout, enable read_once...)
   *
   * @param manipulator Manipulator to run
   *
   * @return current GloveBase instance
   */
  GloveBase& operator>>(GloveBase& (*manipulator)(GloveBase&))
  {
    return manipulator(*this);
  }

  /**
   * Manipulators can have several input types, so let's have a general
   * purpose manipulator. Later we will declare all available manipulators
   * with a macro.
   */
  template <typename T>
  class GloveManipulator
  {
  public:
    /**
     * Manipulator constructor. Let's copy the input value to a internal
     * attribute of the same type.
     *
     * @param val Input value
     */
    GloveManipulator(T val):val(val)
    {
    }

    /**
     * Modify settings of the GloveBase instance out
     *
     * @param out Where to define settings
     *
     * @return GloveBase instance
     */
    virtual GloveBase& operator()(GloveBase& out) = 0;
  protected:
    T val;
  };

  /**
   * Macro to create manipulators. Create struct extending
   * GloveManipulator with a specific value and the right ()
   * operator to apply the operator.
   * Also a friend operator>> that accepts the new born 
   * operator class.
   */
#define newManipulator(_name, _type)				\
  struct set_##_name : public GloveManipulator<_type>		\
  {								\
  public:							\
    set_##_name(_type v):GloveManipulator(v)			\
      {								\
      }								\
    GloveBase& operator()(GloveBase &out)			\
    {								\
      out.default_values._name=val;				\
      return out;						\
    }								\
  };								\
								\
  friend GloveBase& operator>>(GloveBase& out, set_##_name gm)	\
  {								\
    return gm(out);						\
  }								\

  /**
   * Macro to create flag manipulators. Flag manipulators act within
   * an integer variable modifying just one bit, setting or
   * clearing it.
   */
#define newFlagManipulator(_name, _setting, _flag, _type)	\
  struct set_##_name : public GloveManipulator<_type>		\
  {								\
  public:							\
    set_##_name(_type v):GloveManipulator(v)			\
      {								\
      }								\
    GloveBase& operator()(GloveBase &out)			\
    {								\
      if (val)							\
	out.default_values._setting|=_flag;			\
      else							\
	out.default_values._setting&=~_flag;			\
      return out;						\
    }								\
  };								\
								\
  friend GloveBase& operator>>(GloveBase& out, set_##_name gm)	\
  {								\
    return gm(out);						\
  }								\

  /**
   * Manipulator to set read_once value. Read operation MUST be done
   * just once. If false, the read operation will be done until a
   * timeout is received, the connection closed or the number of
   * bytes we want to read reached.
   */
  newManipulator(read_once,bool);

  /**
   * The timeout won't be returned if there is data in the buffer.
   * Instead, the end of the read function will be.
   */
  newManipulator(timeout_when_data, bool);

  /**
   * Enable input filters?
   */
  newManipulator(enable_input_filters, bool);

  /**
   * Enable output filters?
   */
  newManipulator(enable_output_filters, bool);

  /**
   * Sets timeout value in seconds
   */
  newManipulator(timeout, double);

  /**
   * Will there be an exception on timeout ?
   */
  newFlagManipulator(exception_on_timeout, exceptions, EXCEPTION_TIMEOUT, bool);

  /**
   * Will there be an exception on server disconnection ?
   */
  newFlagManipulator(exception_on_disconnection, exceptions, EXCEPTION_DISCONNECTED, bool);

#undef newManipulator
#undef newFlagManipulator
  // Sample manipulator code
  // struct read_once : public GloveManipulator<bool>
  // {
  // public:
  //   read_once(bool v):GloveManipulator(v)
  //   {
  //   }
  //   GloveBase& operator()(GloveBase &out)
  //   {
  // 	out.default_values.read_once=true;
  // 	return out;
  //   }
  // };
  // friend GloveBase& operator>>(GloveBase& out, read_once gm)
  // {
  //   return gm(out);
  // }

  /**
   * operator<< for ostream manipulators, like endl
   *
   * @param manip Ostream manipulator
   *
   * @return A glove class reference will be returned
   */
  // define an operator<< to allow ostream manipulators (e.g. std::endl)
  GloveBase& operator<<(ostream_manipulator manip)
  {
    std::stringstream ss;
    ss<<manip;

    this->send(ss.str());

    return *this;
  }

  /**
   * This is how a filter callback looks like. Just input a string and outputs a string
   */
  using filter_callback = std::function<std::string (std::string &)>;

  /**
   * Adds a filter
   *
   * @param type   FILTER_INPUT or FILTER_OUTPUT. Input filters will be 
   *               done before sending. Output filters will be done after
   *               receiving.
   * @param name   Filter's name. For our control.
   * @param filter Filter function callback
   * @param option Option for inserting filter: 
   *                 "start" : to run this filter the first.
   *                 "before": to run this filter before the filter called XXXX.
   * @param value  If option == "before" this will be the name of the filter
   *               we will postpone.
   */
  void add_filter(filter_type type, std::string name, filter_callback filter, std::string option="", std::string value="");

  /**
   * Removes a filter
   *
   * @param type   Type of the filter (FILTER_INPUT, FILTER_OUTPUT)
   * @param name   Name of the filter to delete
   *
   * @return true if ok, false if not
   */
  bool remove_filter(filter_type type, std::string name);

  /**
   * Gets a list of filters (DEBUG)
   *
   * @param type   Type of filters I want to list
   * 
   * @return List of filters in a vector
   */
  std::vector<std::string> get_filters(filter_type type);

  /**
   * Run filters on an input string. 
   * This method will become protected !!!!
   *
   * @param type   Type of filters to run
   * @param _input Input string to run filters on
   *
   * @return resulting string
   */
  std::string run_filters(filter_type type, const std::string &_input);

  /**
   * Disconnect !!!
   *
   * @param how    Type of shutdown to perform. See SHUT_RD, SHUT_WR, 
   *               SHUT_RDWD, SHUT_XX
   */
  void disconnect(int how=SHUT_XX);

  // other utils

	/**
	 * Gets service by name
	 * Asks the system for a service by name, get the service default port
	 *
	 * @param name    Service name
	 * @return service and port
	 */
	static uint16_t getServByName(std::string name);

  /**
   * Create URI string
   *
   * @param service  Service to access (http, smtp, pop, ftp, etc). See /etc/services
   * @param host     Host
   * @param port     Port. If service is "", will be guessed
   * @param username User name for access restricted URIs
   * @param password Password
   */
  static std::string build_uri (const std::string &service, const std::string &host, int port=0, const std::string &username="", const std::string &password="");

  /**
   * Create URI string, without service param
   *
   * @param host     Host
   * @param port     Port. If service is "", will be guessed
   * @param username User name for access restricted URIs
   * @param password Password
   */
  static std::string build_uri (const std::string &host, int port=0, const std::string &username="", const std::string &password="")
  {
    return build_uri("", host, port, username, password);
  }
  // service separator : "://"
  // 
  static uri get_from_uri (const std::string &uristring, bool urldecode=true, bool resolve=true, std::string service_separator="");
  /* extract uri arguments */
  static std::map<std::string, std::string> extract_uri_arguments(std::string& rawArguments, std::string& fragment, bool urldecode=true);

  // some more tools

  /**
   * GetServByPort wrapper
   *
   * @param port Port
   *
   * @return Service name in string
   */
  static std::string getServByPort(int port);

protected:
#if ENABLE_OPENSSL
  struct SSL_certificate
  {
    /* More stuff in the future! */
    /** Certificate  */
    X509* cert;
    /** Not before as time_t  */
    time_t notBefore;
    /** Not after as time_t  */
    time_t notAfter;
    /** Certificate entries  */
    std::map<std::string, std::string> entries;
  };
#endif

  /**
   * Connection description, used a struct in case of SSL connections,
   * where we have to include some more information.
   */
  struct Conn_description
  {
    /** Socket descriptor  */
    int sockfd;
    int secureConnection;
#if ENABLE_OPENSSL
    /** SSL Handler  */
    SSL* ssl;
    /** SSL Context  */
    SSL_CTX* ctx;
    /** Certificate verification result (client)  */
    long cert_verify_result;
    /** Cipher info is loaded  */
    bool cipher_info_present;
    /** Certificates info loaded  */
    bool certificates_info_present;
    /** Certificate error string  */
    std::string cert_error_string;
    /** SSL Version used  */
    std::string ssl_version;
    /** Cipher name  */
    std::string cipher_name;
    /** Cipher version  */
    std::string cipher_version;
    /** Cipher description  */
    std::string cipher_description;
    /** Certificates information  */
    std::vector<SSL_certificate> certificates;
#endif
  };
  /** socket descriptor  */
  /* int sockfd; */
  /** Connection descriptor  */
  Conn_description conn;
  /** connection start moment  */
  std::chrono::time_point<std::chrono::system_clock> start_dtm;
  /** Current connection info  */
  hostinfo connectionInfo;
	std::function<void(uint8_t, uint16_t, std::string message, std::string moreData)> _loggerCallback;
	
  /**
   * Options for this instance
   */
  struct local_options
  {
    /** timeout for read operations and connections */
    double timeout;
    /**
       Optional exceptions. Sometimes we don't want it to throw some exceptions, e.g: when reading, sometimes
       on time out or peer disconnection, we may just want to return received data. 
       Used *globally*.
    */
    unsigned exceptions;
    /** We may want the exception timeout, but only when there's no data in the read buffer 
       Used on *reception*
    */
    bool timeout_when_data; 
    /** Perform just one read operation. 
       Used on *reception*
     */
    bool read_once;
    /** By default, when using >> operator, perform a fixed read with this number of bytes
       Used on *reception*
    */
    size_t fixed_read;
    /** max. buffer size for read operations
       Used on *reception*
     */
    size_t buffer_size;	
    /** enable input filters (incoming data) 
       Used on *reception*
     */
    bool enable_input_filters;
    /** enable output filters (outgoing data) 
       Used when *sending*
     */
    bool enable_output_filters;

#if ENABLE_OPENSSL
    /** Times out SSL receiving data. Some kind of bug in openSSL can leave SSL_read frozen and no information
     * will come. Leaving the process
     */
    bool ssltimeout;
#endif
  };
  /** Default options  */
  local_options  default_values;

  /**
   * Filter definition
   */
  struct Filter
  {
    /** Filter's name  */
    std::string name;
    /** Filter's callback  */
    filter_callback filter;
  };

  /** Input filters vector  */
  std::vector<Filter> input_filters;
  /** Output filters vector  */
  std::vector<Filter> output_filters;

  /* constructor copying options */
  GloveBase(local_options options):default_values(options)
  {
  }

  /**
   * Send data. You can find params help anywhere else on this page
   * @param data
   */
  void _send(const std::string &data);

  /**
   * Receiving data. You can find params help anywhere else on this page
   * @param size
   * @param timeout
   * @param timeout_when data
   * @param _buffer_size
   * @param _read_once
   * @param exception_on_timeout
   */
  std::string _receive_fixed(const size_t size, double timeout, const bool timeout_when_data, size_t _buffer_size, short _read_once, bool exception_on_timeout);

  /**
   * Automatically gets level param for getsockopt()
   *
   * @param optname Option
   */
  static int get_integer_sockopts_level(int optname);

  /**
   * Fills up start_dtm attribute with current time information
   */
  void register_dtm();

  /**
   * Create a string with the user and password this way: "user:password@"
   * with some little error checking
   *
   * @param user     User
   * @param password Password
   *
   * @return Returned string
   */
  static std::string user_and_pass(const std::string& user, const std::string &password);

  /**
   * Creates a string with the errno appended. Not thread safe! As errno isn't
   */
  static std::string append_errno(std::string message);

	/**
	 *
	 */
	static std::pair<uint32_t, uint32_t> getNetworkAndMask(const std::string cidr, bool notOnlyCIDR, bool noException);

	/**
	 *
	 */
	static int inet_pton4(const std::string addr, in_addr* result, bool noException=true);

	static std::map<std::string, uint16_t> _additionalServices;

};

/**
 * Glove Main Class
 */
class Glove : public GloveBase
{
public:
  /**
   * Glove CONNECTED Client class
   */
  class Client : public GloveBase
  {
  public:
    /**
     * Client constructor.
     *
     * @param sockfd    Socket to use
     * @param clientId  Internal client ID
     * @param ipaddress IP Address of this client
     * @param host      Host
     */
    Client(Conn_description conn, unsigned clientId, bool local, std::string ipaddress, std::string host):clientId(clientId), _local(local)
    {
      this->conn = conn;
      this->connectionInfo.ip_address = ipaddress;
      this->connectionInfo.host = host;
    }

    /**
     * Client constructor
     *
     * @param sockfd    Socket to use
     * @param clientId  Internal client ID
     * @param ipaddress IP Address of this client
     * @param host      Host
     * @param options   Default options for this client
     */
    Client(Conn_description conn, unsigned clientId, bool local, std::string ipaddress, std::string host, local_options options):Client(conn, clientId, local, ipaddress, host)
    {
      default_values = options;
    }

		unsigned id() const
		{
			return clientId;
		}
    /**
     * Send data !!
     *
     * @param data Data to send
     */
    inline void send(const std::string &data)
    {
      this->_send(data);
    }

    // read once = read once then, returns
    /**
     * Receive data from this client
     *
     * @param timeout   Timeout in seconds
     * @param read_once Just perform one read operation
     *
     * @return Received data
     */
    std::string receive(double timeout=-1, short read_once=-1)
    {
      return _receive_fixed(0, timeout, default_values.timeout_when_data, default_values.buffer_size, read_once, default_values.exceptions & EXCEPTION_TIMEOUT);
    }

  	int receive2 (std::string& out, double timeout=-1, short read_once=-1)
		{
			out.clear();
			try
				{
					out = _receive_fixed(0, timeout, default_values.timeout_when_data, default_values.buffer_size, read_once, true);
				}
			catch (GloveException& e)
				{
					return e.code();
				}
			return 0;
		}

    /**
     * Receive a fixed amount of data from this client
     *
     * @param size    The size we want to read
     * @param timeout Timeout in seconds
     *
     * @return Received data
     */
    std::string receive_fixed(const size_t size, double timeout=-1)
    {
      return _receive_fixed(size, timeout, true, default_values.buffer_size, false, default_values.exceptions & EXCEPTION_TIMEOUT);
    }

		bool local()
		{
			return _local;
		}
		
	private:
		unsigned clientId;
		bool _local;
  };

  /**
   * That's the filter function to be executed
   * Possible returns:
   *     > 0 : connection accepted
   *     = 0 : current connection not affected by filter
   *     < 0 : connection denied
   */
  using connection_filter_callback = std::function<int (const Glove* server, std::string ipAddress, std::string hostname, uint16_t remotePort, std::string data0, std::string data1, uint32_t data2, double data3)>;

  /**
   * That's a client callback (what we run when a client connects our server
   * 
   * int clientCallback(Client &c);
   */
  using client_callback = std::function<int (Glove::Client &)>;

  /**
   * SSL Methods available (up to OpenSSL 1.0.1f)
   * Please use SSLv3 only when strictly necessary (I know there are
   * still lot of services that use this version).
   */
  enum ESSL_Methods
    {
      SSLv23,
      SSLv3,		/* Deprecated!*/
      TLSv1,
      TLSv1_1,
      TLSv1_2,
      DTLSv1
    };

  enum:unsigned
    {
      /** Verify CA */
      SSL_FLAG_VERIFY_CA       = 1,
      /** Fail on invalid CA (on client connections)  */
      SSL_FLAG_FAIL_INVALID_CA = 2,
      /** Gets cipher information on connection  */
      SSL_FLAG_GET_CIPHER_INFO = 4,
      /** Gets certificate information on connection  */
      SSL_FLAG_GET_CERT_INFO   = 8,
      /** Enable all flags  */
      SSL_FLAG_ALL             = 65535
    };

  /**
   * Connection Log State. Indicates whether the logged connection
   * was accepted, denied and the reason of denegation
   */
  enum ConnectionLogState
    {
      CONNECTION_ACCEPTED,
      ACCEPT_ERROR,
			SSL_CONNECTION_ERROR,
			SSL_ACCEPT_ERROR,
      /* too many concurrent connections */
      CONNECTION_DENIED_BY_TOO_MANY,
      /* default policy is DENY ALL */
      CONNECTION_DENIED_BY_POLICY,
      /* connection denied by filter */
      CONNECTION_DENIED_BY_FILTER,
      /* unknowen cause. Don't know where to use it */
      CONNECTION_DENIED_BY_OTHER
    };

  /**
   * Stores basic information from the incoming connection.
   * This information is collected before the worker callback
   * is called, so it won't collect SSL negotiation data, or
   * login, or so, just connection.
   */
  struct ConnectionLog
  {
    /** IP Address  */
    std::string ipAddress;
    /** Hostname, if resolution is enabled  */
    std::string hostName;
    /** Start time  */
    time_point start;
    /** Connection state  */
    ConnectionLogState state;
    /** If connection was denied by filter, this is the filter ID  */
    uint32_t filter; 
  };
  /**
   * A server error callback. What we run when there is a problem with a client
   *
   * void problem (Client &c, int clientId, GloveException& e)
   */
  using server_error_callback_t = std::function<void (Glove::Client &, int clientId, GloveException &e)>;

  /**
   * The simplest constructor. We may define some options after creating
   */
  Glove();

  // create server
  /**
   * Creates directly a server to listen to connections
   *
   * @param port           Port
   * @param cb             Client callback.
   * @param bind_ip        The IP (or device) our server will listen to.
   * @param buffer_size    Buffer size (defaults to GLOVE_DEFAULT_BUFFER_SIZE)
   * @param error_callback Our error callback (won't do anything by default)
   * @param backlog_queue  listen()'s backlog queue. The number of connections waiting
   *                       to be accepted.
   * @param domain         Defaults to GLOVE_DEFAULT_DOMAIN or AF_INET
   */
  Glove(int port, client_callback cb, std::string bind_ip, const size_t buffer_size=GLOVE_DEFAULT_BUFFER_SIZE, server_error_callback_t error_callback=nullptr, const unsigned backlog_queue=GLOVE_DEFAULT_BACKLOG_QUEUE, int domain=GLOVE_DEFAULT_DOMAIN);

  // create client
  /**
   * Created directly a client and attempt to connect a server
   *
   * @param host    Host to connect to
   * @param port    Port
   * @param timeout Timeout in seconds (After this time, the connection will be disabled.
   * @param domain  Defaults to GLOVE_DEFAULT_DOMAIN or AF_INET
   * @param secure  Make secure connection using SSL (defaults AUTODETECT_SSL, that is
   *                                                  use secure connection if service is secure).
   */
  Glove( const std::string& host, const int port, double timeout = -1, int domain = GLOVE_DEFAULT_DOMAIN, int secure = AUTODETECT_SSL);

  /**
   * Created directly a client and attempt to connect a server
   *
   * @param uri   Url to connect to
   * @param timeout Timeout in seconds (After this time, the connection will be disabled.
   * @param domain  Defaults to GLOVE_DEFAULT_DOMAIN or AF_INET
   * @param secure  Make secure connection using SSL (defaults AUTODETECT_SSL, that is
   *                                                  use secure connection if service is secure).
   */
  Glove( const Glove::uri &uri, double timeout = -1, int domain = GLOVE_DEFAULT_DOMAIN, int secure = AUTODETECT_SSL);


  /**
   * Created directly a client and attempt to connect a server
   *
   * @param     Url to connect to
   * @param timeout Timeout in seconds (After this time, the connection will be disabled.
   * @param domain  Defaults to GLOVE_DEFAULT_DOMAIN or AF_INET
   * @param secure  Make secure connection using SSL (defaults AUTODETECT_SSL, that is
   *                                                  use secure connection if service is secure).
   */
  Glove( const std::string& uri, double timeout = -1, int domain = GLOVE_DEFAULT_DOMAIN, int secure = AUTODETECT_SSL);


  /**
   * Destruction and cleanup
   */
  virtual ~Glove();

  /**
   * Resolve a host, maybe in several addresses.
   * Resolves IPv4 and IPv6 addresses
   *
   * @param host   Host
   *
   * @return List of hostinfo addresses. 
   */
  static std::vector<hostinfo> resolveHost(const std::string& host);

  /**
   * Detects a secure service BY ITS NAME. The other way may be
   * trying to stablish a secure connection to the server. This is
   * much more accurate, but slower. Maybe in a future version we
   * can make a AUTODETECT_SSL_SLOW argument that tries the secure
   * connection.
   * This method *is present* even if not compiled with the
   * ENABLE_OPENSSL directive.
   *
   * @param service Service to test
   *
   * @return ENABLE_SSL or DISABLE_SSL
   */
  static int detectSecureService(const std::string& service);

  /**
   * Connect to a server (as a client)
   *
   * @param host    Host
   * @param port    Port
   * @param timeout Timeout in seconds
   * @param domain  Domain
   * @param secure  Stablish a secure connection
   */
  void connect(const std::string& host, const int port, double timeout = -1, int domain = GLOVE_DEFAULT_DOMAIN, int secure = AUTODETECT_SSL);

  /**
   * Connect to a server (as a client)
   *
   * @param uri     Direct URI where host and port will be inferred
   * @param timeout Timeout in seconds
   * @param domain  Domain
   * @param secure  Stablish a secure connection
   */
  void connect(GloveBase::uri uri, double timeout=-1, int domain = GLOVE_DEFAULT_DOMAIN, int secure = AUTODETECT_SSL);

  /**
   * Connect to a server (as a client)
   *
   * @param uri     Direct URI where host and port will be inferred
   * @param timeout Timeout in seconds
   * @param domain  Domain
   * @param secure  Stablish a secure connection
   */
  void connect(const std::string uri, double timeout=-1, int domain = GLOVE_DEFAULT_DOMAIN, int secure = AUTODETECT_SSL);

  /**
   * Disconnect
   *
   * @param how  How to disconnect.
   */
  void disconnect (int how=SHUT_XX);

  /**
   * Sends data through socket
   *
   * @param data What to send
   */
  inline void send ( const std::string& data)
  {
    if (!test_connected())
      return;

    _send(data);
  }

  // normal receive 
  /**
   * Receive data
   *
   * @param timeout   Timeout in seconds
   * @param read_once Read just once (not as many times as needed)
   *
   * @return Received data
   */
  std::string receive ( double timeout = -1, short read_once=-1)
  {
    if (!test_connected())
      return "";

    return _receive_fixed(0, timeout, default_values.timeout_when_data, default_values.buffer_size, read_once, default_values.exceptions  & EXCEPTION_TIMEOUT);
  }

  // receive size bytes no matter how many recv() you must call
  /**
   * Receive a fixed amount of data from the socket
   *
   * @param size     Size to receive
   * @param timeout  Timeout in seconds
   *
   * @return Received data
   */
  std::string receive_fixed ( const size_t size, double timeout = -1)
  {
    if (!test_connected())
      return "";

    return _receive_fixed(size, timeout, true, default_values.buffer_size, false, default_values.exceptions & EXCEPTION_TIMEOUT);
  }

  /**
   * Listen for connections (as a server)
   *
   * @param port      Port
   * @param cb        Callback to execute when a client comes
   * @param bind_ip   IP or device to bind to
   * @param backlog   Backlog queue. @see Glove()
   * @param domain    Domain
   * @param secure    Make a secure connection directly
   * @param certchain Certificate chain (overrides default)
   * @param certkey   Certificate key (overrides default)
   */
  void listen(const int port, client_callback cb, std::string bind_ip, const unsigned backlog_queue, int domain = GLOVE_DEFAULT_DOMAIN, int secure=UNDEFINED_SSL, std::string certchain="", std::string certkey="");

  /**
   * Setter for server_error_callback option
   *
   * @param cb   Desired callback
   */
  void server_error_callback(server_error_callback_t cb)
  {
    _server_error_callback = cb;
  }

  // some utils
  /**
   * Gets IP to bind listen() command when it's not specified. Trying to guess
   * it with the domain parameter.
   *
   * @param domain   Domain
   *
   * @return String with the IP to bind to
   */
  std::string getUnspecified(int domain);

  // get info...
  /**
   * Try to guess if the connection is open
   *
   * @return true if it is
   */
  bool is_connected();

  unsigned totalHits()
  {
    return clientId;
  }
  // options getters/setters
  /**
   * Setter for shutdown_on_destroy_option
   *
   * @param val   New value
   *
   * @return new value
   */
  bool shutdown_on_destroy(bool val)
  {
    return (_shutdown_on_destroy=val);
  }

  /**
   * Getter for shutdown_on_destroy_option
   *
   * @return Current value of this setting
   */
  bool shutdown_on_destroy()
  {
    return _shutdown_on_destroy;
  }

  /**
   * Get a list of connected clients.
   *
   * @return Gets a map of connected clients with an 
   * internal ID and a Client pointer (to interact with them)
   */
  std::map <unsigned, Client*> get_connected_clients()
  {
    return clients_connected;
  }

  /**
   * Debug Logged Connections. Extract a string with a list
   * of logged connections with dates, IPs and states
   */
  std::string debugLoggedConnections();

  uint32_t countLoggedConnections()
  {
    return connections_logged.size();
  }

  std::deque<ConnectionLog> getLoggedConnections()
  {
    return connections_logged;
  }

  /* TO DOC */
  bool getLoggedConnection(ConnectionLog& cl, uint32_t id)
  {
    try 
      {
	cl = connections_logged.at(id);
	return true;
      }
    catch (const std::out_of_range& oor) 
      {
	return false;
      }
  }

  /**
   * Too Many Connections Response Message. This will be sent
   * if someone tries to connect when the max_accepted_clients
   * is reached.
   * This will enable reject_connections
   *
   * @param msg Message to return
   */
  void tmcRejectMessage(std::string msg);

  /**
   * Too Many Connections Response Callback. This will be called
   * if someone tries to connect when the max_accepted_clients
   * is reached.
   * This will enable reject_connections
   *
   * @param cb function to call. This function must return a string message
   *           to be sent to the user.
   */
  void tmcRejectCallback(std::function <std::string (Client* c)> cb);

  /**
   * Disables reject message for client connections when there are
   * too many
   */
  void tmcRejectDisable();

  void addConnectionFilter(connection_filter_callback cb, std::string data0="", std::string data1="", uint32_t data2 =0, double data3 =0);

  void deleteConnectionFilter(uint32_t filterId);

  void serverAllowIp(std::string cidr);
  void serverDisallowIp(std::string cidr);

  void serverDisallowFastConnection(double time, uint32_t connections);

  /* Hay que hacer métodos para aceptar y denegar rangos de IP */
  /* Un filtro más para denegar una conexión si viene en menos de X tiempo, para
   eso, el incoming log debe estar activado y se consultarán las últimas conexiones */
  
#if ENABLE_OPENSSL
  /**
   * Get SSL Verify state. But with some things more
   *
   * @return SSL Verify state constant: 
   *     - 0  = OK
   *     - >0 = SSL ERROR (see man verify)
   *     - -1 = Not a secure connection (Glove's own value)
   */
  long getSSLVerifyState();

  /**
   * Get SSL Verify state in string
   *
   * @return SSL Verify state in string (or "Not a secure connection" if so.
   */
  std::string getSSLVerifyString();

  /**
   * Get cipher and connection information and store in connection variables
   */
  void SSLGetCipherInfo();

  /**
   * Gets SSL Version used in this connection
   *
   * @return result
   */
  std::string getSSLVersion();

  /**
   * Gets SSL Cipher name 
   *
   * @return result
   */
  std::string getSSLCipherName();

  /**
   * Gets SSL Cipher Version
   *
   * @return result
   */
  std::string getSSLCipherVersion();

  /**
   * Gets SSL Cipher description
   *
   * @return result
   */
  std::string getSSLCipherDescription();

  /**
   * Returns an string with all the cipher information
   */
  std::string debugCipherInfo();

  /**
   * Gets certificates information
   */
  void SSLGetCertificatesInfo();

  /**
   * Debug certificates info
   */
  std::string debugCertificatesInfo();

#endif
  // server option configuration example
  // bool resolve_hostnames(bool val)
  // {
  //   return (server_options.resolve_hostnames=val);
  // }

  // bool resolve_hostnames()
  // {
  //   return server_options.resolve_hostnames;
  // }

  // declares bool resolve_hostnames([bool])

  /**
   * Getter/Set resolve_hostnames server option
   *
   * bool resolve_hostnames(bool newVal);
   * bool resolve_hostnames();
   */
  option_conf(server_options, bool, resolve_hostnames);

  // declares bool thread_clients([bool])
  /**
   * Getter/Set thread_clients server option
   *
   * bool thread_clients(bool newVal);
   * bool thread_clients();
   */
  option_conf(server_options, bool, thread_clients);

  // declares bool thread_server([bool])
  /**
   * Getter/Set thread_server server option
   *
   * bool thread_server(bool newVal);
   * bool thread_server();
   */
  option_conf(server_options, bool, thread_server);

  // declares bool server_reuseaddr([bool])
  /**
   * Getter/Set server_reuseaddr server option
   *
   * bool server_reuseaddr(bool newVal);
   * bool server_reuseaddr();
   */
  option_conf(server_options, bool, server_reuseaddr);

  // declares unsigned max_accepted_clients([unsigned])
  /**
   * Getter/Set max_accepted_clients server option
   *
   * bool max_accepted_clients(bool newVal);
   * bool max_accepted_clients();
   */
  option_conf(server_options, unsigned, max_accepted_clients);

  // declares unsigned accept_wait([unsigned])
  /**
   * Getter/Set accept_wait server option
   *
   * bool accept_wait(bool newVal);
   * bool accept_wait();
   */
  option_conf(server_options, unsigned, accept_wait);

  // declares bool server_copy_options([bool])
  /**
   * Getter/Set copy_options server option
   *
   * bool copy_options(bool newVal);
   * bool copy_options();
   */
  option_conf(server_options, bool, copy_options);

  // declares bool incoming_log([bool])
  /**
   * Getter/Set incoming_log server option
   *
   * bool incoming_log(bool newVal);
   * bool incoming_log();
   */
  option_conf(server_options, bool, incoming_log);

  // declares bool reject_connections([bool])
  /**
   * Getter/Set reject_connections server option
   *
   * bool reject_connections(bool newVal);
   * bool reject_connections();
   */
  option_conf(server_options, bool, reject_connections);

  // declares bool wait_before_reject_connection([bool])
  /**
   * Getter/Set wait_before_reject_connection server option
   *
   * bool wait_before_reject_connection(bool newVal);
   * bool wait_before_reject_connection();
   */
  option_conf(server_options, double, wait_before_reject_connection);

  // declares uint8_t default_conn_policy([bool])
  /**
   * Getter/Set default_conn_policy server option
   *
   * bool default_conn_policy(bool newVal);
   * bool default_conn_policy();
   */
  option_conf(server_options, uint8_t, default_conn_policy);

#if ENABLE_OPENSSL
  /**
   * Getter and setter for SSL Method
   * ESSL_Methods ssl_method(ESSL_Methods new);
   * ESSL_Methods ssl_method();
   */
  option_conf(ssl_options, ESSL_Methods, ssl_method);

  /**
   * Getter and setter for Certificate key file
   * std::string certKey(std::string new);
   * std::string certKey();
   */
  option_conf(ssl_options, std::string, certKey);

  /**
   * Getter and setter for Certificate chain file
   * std::string certChain(std::string new);
   * std::string certChain();
   */
  option_conf(ssl_options, std::string, certChain);

  /**
   * Setter for SSL Flags
   */
  int SSLFlags(int status)
  {
    ssl_options.flags = status;
    return status;
  }

  /**
   * Getter for SSL Flags
   */
  int SSLFlags()
  {
    return ssl_options.flags;
  }

  void certChainAndKey(std::string chainFile, std::string keyFile);
#endif

protected:
  // static timeval as_timeval ( double seconds );
  bool connect_nonblocking ( const sockaddr *saptr, socklen_t salen, const double timeout);
  bool create_worker(client_callback cb);
	bool shutdown_client(Conn_description& client_conn);
  void launch_client(client_callback cb, Client *c, Conn_description client_conn, unsigned client_id);
  bool test_connected();
  void fill_connection_info(addrinfo* rp, int port);
  /* logs connection in local log and rotates list */
  void logConnection(std::string ipAddress, std::string hostName, ConnectionLogState state, uint32_t filterId=0);
  unsigned getTotalConnectedClients()
  {
    return clients_connected.size();
  }
	bool isLocal(std::string& ipAddress);
  void serverRejectConnection();
#if ENABLE_OPENSSL
  /**
   * Initializes ssl_options with default values
   */
  void setSSLDefaultValues();

  /**
   * Performs SSL client handshake
   * This method is *only present if ENABLE_OPENSSL is defined
   *
	 * @param host host name for SNI
   * @param exception_on_handshake_failure self-explanatory
   *
   * @return true if connected, false if don't (but if the exception is enabled,
   *         it will return always TRUE).
   */
  bool SSLClientHandshake(std::string host, bool exception_on_handshake_failure=true);

  /**
   * Initialize openSSL
   */
  void initializeOpenSSL();

  /**
   * Initializes openSSL, add algorithms, create context
   * and loads certificates. All the dirty work
   */
  void SSLServerInitialize();

  /**
   * Gets desired SSL client Method to connect a server.
   * This can be configured later
   */
  const SSL_METHOD* getSSLServerMethod();

  /**
   * Gets desired SSL client Method to connect a server.
   * This can be configured later
   */
  const SSL_METHOD* getSSLClientMethod();

  struct
  {
    ESSL_Methods ssl_method;
    /* Flags of SSL connection */
    unsigned flags;
    /** Path for CA certificates (as client, for verification) */
    std::string CApath;
    /** Certificate key file (for servers) */
    std::string certKey;
    /** Certificate chain file (for servers)  */
    std::string certChain;
  } ssl_options;
  /**
   * OpenSSL is initialized?
   */
  static bool openSSLInitialized;
#endif
  // status
  bool connected;
	std::string boundIp;
	
  bool _shutdown_on_destroy;
  // server options
  struct
  {
    bool resolve_hostnames;
    // each client will be in a different thread
    bool thread_clients;
    // the server will run on a separate thread, to protect the main process
    bool thread_server;
    // server socket will use SO_REUSEADDR after creatio
    bool server_reuseaddr;
    // max number of clients connected 
    unsigned max_accepted_clients;
    // milliseconds to wait before trying to run accept again
    unsigned accept_wait;
    // copy default options to clients
    bool copy_options;
    // incoming connection log. Defaults to true
    bool incoming_log;
    // reject incoming connections when clients connected are max_accepted_clients. Defaults false
    bool reject_connections;
    // max time to wait before rejecting the connection. Defaults 0
    double wait_before_reject_connection;
    // default connection policy ( 0 - deny, !=0 - accept ). Defaults 1
    uint8_t default_conn_policy;
  } server_options;

  /* We may use variant types but I won't use it anywhere else (now) */
  struct ConnectionFilter
  {
    connection_filter_callback cb;
    std::string data0;
    std::string data1;
    uint32_t data2;
    double data3;
  };
  server_error_callback_t _server_error_callback;

  // multiple clients
  bool accept_clients;
  std::map <unsigned, Client*> clients_connected;
  // this vector stores information about connection times
  std::deque<ConnectionLog> connections_logged;
  unsigned maxConnectionsBuffer;
  /* this map includes filters for incoming connections:
  * client restrictions
  * ip restrictions
  * time restrictions
  * and user defined function for future restrictions */
  std::map <unsigned, ConnectionFilter> connection_filters;
  /**
   * Too many connections reject callback
   */
  std::function <std::string (Client* c)> tmcRejectCb;
  std::mutex clients_connected_mutex;
  unsigned clientId;
};

#undef option_conf
#endif /* _GLOVE_HPP */
