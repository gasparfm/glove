/* @(#)glove.hpp
 */

#ifndef _GLOVE_HPP
#define _GLOVE_HPP 10

#include <exception>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <ctime>
#include <chrono>
#include <map>
#include <sstream>
#include <iostream>		// debug only
#include <algorithm>
#include <sys/socket.h>

#define GLOVE_DEFAULT_TIMEOUT 1
#define GLOVE_DEFAULT_DOMAIN AF_INET
#define GLOVE_DEFAULT_BUFFER_SIZE 2048
#define GLOVE_DEFAULT_MAX_CLIENTS 10
#define GLOVE_DEFAULT_ACCEPT_WAIT 2000
#define GLOVE_DEFAULT_BACKLOG_QUEUE 10

namespace
{
  // this is the type of std::cout
  typedef std::basic_ostream<char, std::char_traits<char> > ostream_type;

  // this is the function signature of std::endl
  typedef ostream_type& (*ostream_manipulator)(ostream_type&);
};

class GloveException : public std::exception
{
public:
  GloveException(const int& code, const std::string &message): _code(code), _message(message)
  {
  }

  virtual ~GloveException() throw ()
  {
  }

  const char* what() const throw()
  {
    return _message.c_str();
  }

  int code() const
  {
    return _code;
  }

protected:
  int _code;
  std::string _message;
};

class GloveUriException : public GloveException
{
public:
  GloveUriException(const int& code, const std::string &message): GloveException(code, message)
  {
  }

  virtual ~GloveUriException() throw ()
  {
  }
};

class GloveBase
{
public:
  enum:int
    {
      SELECT_READ=1,
      SELECT_WRITE=2
    };
  enum
    {
      SHUT_R = SHUT_RD,
      SHUT_W = SHUT_WR,
      SHUT_RW= SHUT_RDWR,
      SHUT_XX
    };
  enum:unsigned
    {
      EXCEPTION_NONE = 0,
      EXCEPTION_TIMEOUT = 1,	     // on reception
      EXCEPTION_PEERDISCONNECT = 2,  // as client / server
      EXCEPTION_DISCONNECTED = 4,    // mostly as client
      EXCEPTION_ALL = 65535
    };

  enum filter_type
    {
      FILTER_INPUT,
      FILTER_OUTPUT
    };
  struct hostinfo
  {
    std::string host;
    std::string ip_address;
    std::string service;
  };

  struct uri
  {
    std::string uri;
    std::string host;
    std::vector < std::string > path;
    std::string rawpath;
    std::string rawarguments;
    std::map<std::string, std::string> arguments; // you can choose argument start character (?), argument separator character (;) and argument assign character (=)
    std::string service;
    std::string fragment;
    std::string username;
    std::string password;
    std::vector <GloveBase::hostinfo> ressolvedhosts;
    int port;

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
      out+="Service: "+service+"\n";
      out+="Fragment: "+fragment+"\n";
      out+="Port: "+std::to_string(port)+"\n";
      out+="Username: "+username+"\n";
      out+="Password: "+password+"\n";

      return out;
    }
  };
  static const char* CRLF;

  GloveBase(): default_values({GLOVE_DEFAULT_TIMEOUT, EXCEPTION_ALL, false, false, 0, GLOVE_DEFAULT_BUFFER_SIZE, true, true})
  {
  }

  virtual ~GloveBase()
  {
  }

  // getters
  std::string get_host()
  {
    return connectionInfo.host;
  }

  std::string get_service()
  {
    return connectionInfo.service;
  }

  std::string get_address()
  {
    return connectionInfo.ip_address;
  }

  int get_sockfd()
  {
    return sockfd;
  }

  // option getters/setters
#define option_conf(container, type, option) type option(type val)	\
  {									\
    return (container.option=val);					\
  }									\
  									\
  type option()								\
  {									\
    return container.option;						\
  }

  option_conf(default_values, size_t, buffer_size);
  option_conf(default_values, double, timeout);
  option_conf(default_values, bool, enable_input_filters);
  option_conf(default_values, bool, enable_output_filters);

  // socket handling
  int select(const double timeout, int test=SELECT_READ);
  virtual void send(const std::string &data) = 0;
  virtual std::string receive(double timeout=-1, short read_once=-1) = 0;

  void setsockopt(int level, int optname, void *optval, socklen_t optlen);
  void getsockopt(int level, int optname, void *optval, socklen_t *optlen);

  // When values are integers
  void setsockopt(int optname, int val);
  void getsockopt(int optname, int &val);

  // getsockname interface
  void get_address(std::string &ip, int &port, bool noexcp=false);

  std::string get_address(bool noexcp=false)
  {
    int port;
    return get_address(port, noexcp);
  }

  std::string get_address(int &port, bool noexcp=false)
  {
    std::string addr;
    get_address(addr, port, noexcp);
    return addr;
  }

  int get_connected_port(bool noexcp=false)
  {
    int port;
    get_address(port, noexcp);

    return port;
  }
  // stream operations and manipulators
  template <typename T>

  // define operator<< for input strings, chars, integer and whatever stringstream accepts
  GloveBase& operator<<(const T& x)
  {
    std::stringstream ss;
    ss<<x;

    this->send(ss.str());

    return *this;
  }

  // define operator>> to receive info
  GloveBase& operator>>(std::string &out)
  {
    out=this->receive(default_values.timeout, default_values.read_once);

    return *this;
  }

  // define reception manipulators
  GloveBase& operator>>(GloveBase& (*manipulator)(GloveBase&))
  {
    return manipulator(*this);
  }

  template <typename T>
  class GloveManipulator
  {
  public:
    GloveManipulator(T val):val(val)
    {
    }

    virtual GloveBase& operator()(GloveBase& out) = 0;
  protected:
    T val;
  };

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
	out.default_values._setting|=(1<<_flag);		\
      else							\
	out.default_values._setting&=~(1<<_flag);		\
      out.default_values._setting=65534;			\
      return out;						\
    }								\
  };								\
								\
  friend GloveBase& operator>>(GloveBase& out, set_##_name gm)	\
  {								\
    return gm(out);						\
  }								\

  newManipulator(read_once,bool);
  newManipulator(timeout_when_data, bool);
  newManipulator(enable_input_filters, bool);
  newManipulator(enable_output_filters, bool);
  newManipulator(timeout, double);
  newFlagManipulator(exception_on_timeout, exceptions, EXCEPTION_TIMEOUT, bool);

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

  // define an operator<< to allow ostream manipulators (e.g. std::endl)
  GloveBase& operator<<(ostream_manipulator manip)
  {
    std::stringstream ss;
    ss<<manip;

    this->send(ss.str());

    return *this;
  }

  // GloveBase& operator<<(GloveBase& (*manipulator)(GloveBase&))
  // {
  //   return manipulator(*this);
  // }


  // filters
  using filter_callback = std::function<std::string (std::string &)>;

  void add_filter(filter_type type, std::string name, filter_callback filter, std::string option="", std::string value="");
  bool remove_filter(filter_type type, std::string name);
  std::vector<std::string> get_filters(filter_type type);
  std::string run_filters(filter_type type, const std::string &_input);

  void disconnect(int how=SHUT_XX);
  // other utils
  static std::string build_uri (const std::string &service, const std::string &host, int port=0, const std::string &username="", const std::string &password="");
  static std::string build_uri (const std::string &host, int port=0, const std::string &username="", const std::string &password="")
  {
    return build_uri("", host, port, username, password);
  }
  // service separator : "://"
  // 
  static uri get_from_uri (const std::string &uristring, bool resolve=true, std::string service_separator="");

  // some more tools
  static std::string urlencode( const std::string &str );
  static std::string urldecode( const std::string &str );
  static std::string base64_encode(unsigned char const* , unsigned int len);
  static std::string base64_decode(std::string const& s);

protected:
  // socket
  int sockfd;
  std::chrono::time_point<std::chrono::system_clock> start_dtm;
  hostinfo connectionInfo;

  // configuration
  struct local_options
  {
    // timeout for read operations and connections
    double timeout;
    // bool exception_on_timeout;     // receive
    // optional exceptions. Sometimes we don't want it to throw some exceptions, e.g: when reading, sometimes
    // on time out or peer disconnection, we may just want to return received data.
    unsigned exceptions;	   // global
    // We may want the exception timeout, but only when there's no data in the read buffer
    bool timeout_when_data;	   // receive
    // Perform just one read operation.
    bool read_once;		   // receive
    // By default, when using << , >> operators, perform a fixed read with this number of bytes
    size_t fixed_read;		   // receive
    // max. buffer size for read operations
    size_t buffer_size;		   // send
    // enable input filters (incoming data)
    bool enable_input_filters;
    // enable output filters (outgoing data)
    bool enable_output_filters;
  };

  local_options  default_values;
  // filters
  struct Filter
  {
    std::string name;
    filter_callback filter;
  };

  std::vector<Filter> input_filters;
  std::vector<Filter> output_filters;

  // constructor copying options
  GloveBase(local_options options):default_values(options)
  {
  }

  // send and receive
  void _send(const std::string &data);
  std::string _receive_fixed(const size_t size, double timeout, const bool timeout_when_data, size_t _buffer_size, short _read_once, bool exception_on_timeout);
  // socket handling
  static int get_integer_sockopts_level(int optname);

  void register_dtm();
  static std::string user_and_pass(const std::string& user, const std::string &password);
  static std::string append_errno(std::string message);
};

class Glove : public GloveBase
{
public:
  class Client : public GloveBase
  {
  public:
    Client(int sockfd, std::string ipaddress, std::string host)
    {
      this->sockfd = sockfd;
      this->connectionInfo.ip_address = ipaddress;
      this->connectionInfo.host = host;
    }

    Client(int sockfd, std::string ipaddress, std::string host, local_options options):Client(sockfd, ipaddress, host)
    {
      default_values = options;
    }

    inline void send(const std::string &data)
    {
      this->_send(data);
    }
    // read once = read once then, returns
    std::string receive(double timeout=-1, short read_once=-1)
    {
      return _receive_fixed(0, timeout, default_values.timeout_when_data, default_values.buffer_size, read_once, default_values.exceptions & EXCEPTION_TIMEOUT);
    }

    std::string receive_fixed(const size_t size, double timeout=-1)
    {
      return _receive_fixed(size, timeout, true, default_values.buffer_size, false, default_values.exceptions & EXCEPTION_TIMEOUT);
    }

  };

  using client_callback = std::function<int (Glove::Client &)>;
  using server_error_callback_t = std::function<void (Glove::Client &, int clientId, GloveException &e)>;

  Glove();

  // create server
  Glove(int port, client_callback cb, std::string bind_ip, const size_t buffer_size=GLOVE_DEFAULT_BUFFER_SIZE, server_error_callback_t error_callback=nullptr, const unsigned backlog_queue=GLOVE_DEFAULT_BACKLOG_QUEUE, int domain=GLOVE_DEFAULT_DOMAIN);
  // create client
  Glove( const std::string& host, const int port, double timeout = -1, int domain = GLOVE_DEFAULT_DOMAIN);

  virtual ~Glove();

  static std::vector<hostinfo> resolveHost(const std::string& host);

  void connect ( const std::string& host, const int port, double timeout = -1, int domain = GLOVE_DEFAULT_DOMAIN);
  void disconnect (int how=SHUT_XX);
  inline void send ( const std::string& data)
  {
    if (!test_connected())
      return;

    _send(data);
  }
  // normal receive 
  std::string receive ( double timeout = -1, short read_once=-1)
  {
    if (!test_connected())
      return "";

    return _receive_fixed(0, timeout, default_values.timeout_when_data, default_values.buffer_size, read_once, default_values.exceptions  & EXCEPTION_TIMEOUT);
  }

  // receive size bytes no matter how many recv() you must call
  std::string receive_fixed ( const size_t size, double timeout = -1)
  {
    if (!test_connected())
      return "";

    return _receive_fixed(size, timeout, true, default_values.buffer_size, false, default_values.exceptions & EXCEPTION_TIMEOUT);
  }

  void listen(const int port, client_callback cb, std::string bind_ip, const unsigned backlog_queue, int domain = GLOVE_DEFAULT_DOMAIN);

  void server_error_callback(server_error_callback_t cb)
  {
    _server_error_callback = cb;
  }

  // some utils
  std::string getUnspecified(int domain);

  // get info...
  bool is_connected();

  // options getters/setters
  bool shutdown_on_destroy(bool val)
  {
    return (_shutdown_on_destroy=val);
  }

  bool shutdown_on_destroy()
  {
    return _shutdown_on_destroy;
  }

  std::map <unsigned, Client*> get_connected_clients()
  {
    return clients_connected;
  }
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
  option_conf(server_options, bool, resolve_hostnames);
  // declares bool thread_clients([bool])
  option_conf(server_options, bool, thread_clients);
  // declares bool thread_server([bool])
  option_conf(server_options, bool, thread_server);
  // declares bool server_reuseaddr([bool])
  option_conf(server_options, bool, server_reuseaddr);
  // declares unsigned max_accepted_clients([unsigned])
  option_conf(server_options, unsigned, max_accepted_clients);
  // declares unsigned accept_wait([unsigned])
  option_conf(server_options, unsigned, accept_wait);
  // declares bool server_copy_options([bool])
  option_conf(server_options, bool, copy_options);

protected:
  // static timeval as_timeval ( double seconds );
  bool connect_nonblocking ( const sockaddr *saptr, socklen_t salen, const double timeout);
  void create_worker(client_callback cb);
  void launch_client(client_callback cb, Client *c, int client_sockfd, unsigned client_id);
  bool test_connected();

  // status
  bool connected;

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
  } server_options;

  server_error_callback_t _server_error_callback;

  // multiple clients
  bool accept_clients;
  std::map <unsigned, Client*> clients_connected;
  unsigned clientId;
};

#undef option_conf
#endif /* _GLOVE_HPP */
