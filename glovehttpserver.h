/* @(#)glovehttpserver.h
 */

#ifndef _GLOVEHTTPSERVER_H
#define _GLOVEHTTPSERVER_H 1

#include "glove.hpp"
#include <string>
#include <vector>
#include <sstream>

class GloveHttpRequest
{
 public:
  GloveHttpRequest(Glove::Client *c, int error, std::string method, std::string raw_location, std::string data, std::map<std::string, std::string> httpheaders, int serverPort);
  GloveHttpRequest(bool r) {}
  ~GloveHttpRequest();

  Glove::Client* getClient() const;
  int getError() const;
  std::string getMethod() const;
  std::string getLocation() const;
  std::string getRawLocation() const;
  std::string getData() const;
  std::map<std::string, std::string> getHeaders() const;
  std::string getHeader(std::string h) const;
  GloveBase::uri getUri() const;

  /* Special arguments */
  std::map<std::string, std::string> special;
 private:
  Glove::Client *c;
  GloveBase::uri uri;
  int error;
  std::string method;
  std::string raw_location, location;
  std::string data;
  std::map<std::string, std::string> headers;

  std::string getAuthData();
};

namespace
{
  // this is the type of std::cout
  typedef std::basic_ostream<char, std::char_traits<char> > ostream_type;

  // this is the function signature of std::endl
  typedef ostream_type& (*ostream_manipulator)(ostream_type&);
};

class GloveHttpResponse
{
 public:
  GloveHttpResponse(std::string contentType);
  ~GloveHttpResponse();

  void send(Glove::Client &client);

  template <typename T>
  GloveHttpResponse& operator<<(const T& x)
    {
      output << x;

      return *this;
    }
  /* 1XX */
  static const int CONTINUE;
  static const int SWITCH_PROTOCOLS;
  static const int PROCESSING;
  /* 2XX */
  static const int OK;
  static const int CREATED;
  static const int ACCEPTED;
  static const int NON_AUTHORITATIVE;
  static const int NO_CONTENT;
  static const int RESET_CONTENT;
  static const int PARTIAL_CONTENT;
  static const int MULTI_STATUS;
  static const int ALREADY_REPORTED;
  static const int IM_USED;
  /* 3XX */
  static const int MULTIPLE_CHOICES;
  static const int MOVED_PERMANENTLY;
  static const int FOUND;
  static const int SEE_OTHER;
  static const int NOT_MODIFIED;
  static const int USE_PROXY;
  static const int SWITCH_PROXY;
  static const int TEMPORARY_REDIRECT;
  static const int PERMANENT_REDIRECT;
  /* 4XX */
  static const int BAD_REQUEST;
  static const int UNAUTHORIZED;
  static const int PAYMENT_REQUIRED;
  static const int FORBIDDEN;
  static const int NOT_FOUND;
  static const int BAD_METHOD;
  static const int NOT_ACCEPTABLE;
  static const int PROXY_AUTH_REQ;
  static const int REQUEST_TIMEOUT;
  static const int CONFLICT;
  static const int GONE;
  static const int LENGTH_REQUIRED;
  static const int PRECOND_FAILED;
  static const int REQUEST_TOO_LARGE;
  static const int URI_TOO_LONG;
  static const int UNSUPPORTED_MEDIA;
  static const int RANGE_NOT_SATISF;
  static const int EXPECTATION_FAILED;
  static const int IM_A_TEAPOT;
  static const int AUTH_TIMEOUT;
  static const int UNPROC_ENTITY;
  static const int LOCKED;
  static const int FAILED_DEPEND;
  static const int UPGRADE_REQUIRED;
  static const int PRECOND_REQUIRED;
  static const int TOO_MANY_REQUESTS;
  static const int HEADER_TOO_LARGE;
  static const int LOGIN_TIMEOUT;
  static const int NO_RESPONSE;
  static const int RETRY_WITH;
  static const int BLOCKED_PARENTAL;
  static const int UNAVAILABLE_LEGAL;
  /* 5XX */
  static const int INTERNAL_ERROR;
  static const int NOT_IMPLEMENTED;
  static const int BAD_GATEWAY;
  static const int SERVICE_UNAVAIL;
  static const int GATEWAY_TIMEOUT;
  static const int VERSION_NOT_SUP;
  static const int VAR_ALSO_NEGOT;
  static const int INSUFF_STORAGE;
  static const int LOOP_DETECTED;
  static const int BW_LIMIT_EXCEED;
  static const int NOT_EXTENDED;
  static const int NW_AUTH_REQ;

 private:
  std::stringstream output;
  int returnCode;
  std::string contentType;
  struct ResponseCode
  {
    std::string message;
    std::string description;
  };
  static const std::map<int, ResponseCode> responseCodes;
};

using _url_callback = std::function<void(GloveHttpRequest&, GloveHttpResponse&)>;

class GloveHttpUri
{
 public:
  GloveHttpUri(std::string route, _url_callback ucb, int maxArgs, std::vector<std::string> methods);
  ~GloveHttpUri();

  bool match(std::string method, GloveBase::uri uri, std::map<std::string, std::string> &special);
  void callAction(GloveHttpRequest& request, GloveHttpResponse& response);
 protected:
  int explodeArgs();
 private:
  std::string route;
  int minArgs, maxArgs;
  std::vector<std::string> arguments;
  std::vector<std::string> allowedMethods;
  _url_callback callback;
};

class GloveHttpServer
{
 public:
  typedef _url_callback url_callback;
  static const std::vector<std::string> StandardMethods;

  GloveHttpServer(int listenPort, std::string bind_ip="", const size_t buffer_size=GLOVE_DEFAULT_BUFFER_SIZE, const unsigned backlog_queue=GLOVE_DEFAULT_BACKLOG_QUEUE, int domain=GLOVE_DEFAULT_DOMAIN);
  virtual ~GloveHttpServer();

  void addRoute(std::string route, url_callback callback, int maxArgs=-1, std::vector<std::string> allowedMethods = StandardMethods);
  void addErrorResponse(int errorCode, url_callback callback);

  /* Common callbacks */
  static void fileServer(GloveHttpRequest &request, GloveHttpResponse& response);
  /* Errors */

  /* Timeout when receiving data from client */
  const int ERROR_TIMED_OUT = 30;

  /* Server request is not a valid HTTP/1.1 request */
  const int ERROR_BAD_PROTOCOL = 45;

 protected:
  Glove *server = NULL;
  std::string defaultContentType;
  std::vector<GloveHttpUri> routes;
  int port;

  bool findRoute(std::string method, GloveBase::uri uri, GloveHttpUri* &guri, std::map<std::string, std::string> &special);
  int clientConnection(Glove::Client &client);
  void gloveError(Glove::Client &client, int clientId, GloveException &e);
};

#endif /* _GLOVEHTTPSERVER_H */

