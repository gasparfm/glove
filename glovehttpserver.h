/* @(#)glovehttpserver.h
 */

#ifndef _GLOVEHTTPSERVER_H
#define _GLOVEHTTPSERVER_H 1

#include "glove.hpp"
#include <string>
#include <vector>
#include <sstream>

#define GHS_VERSION 0001001
#define GHS_VERSION_STR "0.1.1"

class GloveHttpServer;

class GloveHttpRequest
{
 public:
  GloveHttpRequest(GloveHttpServer* server, Glove::Client *c, int error, std::string method, std::string raw_location, std::string data, std::map<std::string, std::string> httpheaders, int serverPort);
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
  
  inline GloveHttpServer* server() const
  {
    return srv;
  }

  std::string getMessage(std::string _template);

  /* Special arguments */
  std::map<std::string, std::string> special;
 private:
  GloveHttpServer* srv;
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

  void clear();
  void send(Glove::Client &client);

  short code(short rc=0);

  static std::string responseMessage(short responseCode);
  inline std::string responseMessage()
    {
      return responseMessage(_responseCode);
    }

  template <typename T>
  GloveHttpResponse& operator<<(const T& x)
    {
      output << x;

      return *this;
    }

  /* Support for endl ostream manipulator */
  GloveHttpResponse& operator<<(ostream_manipulator manip)
  {
    output<<manip;
    return *this;
  }

  /* Some more manipulators */

  template <typename T>
  class GloveHttpResponseManipulator
  {
  public:
    GloveHttpResponseManipulator(T val):val(val)
    {
    }

    virtual GloveHttpResponse& operator()(GloveHttpResponse& out) = 0;
  protected:
    T val;
  };

  struct setCode : public GloveHttpResponseManipulator<short>
  {
  public:
  setCode(short val):GloveHttpResponseManipulator(val)
    {
    }

    GloveHttpResponse& operator()(GloveHttpResponse& out)
    {
      out.code(val);
      return out;
    }
  };

  friend GloveHttpResponse& operator>>(GloveHttpResponse& out, setCode mn)
  {
    return mn(out);
  }
  /* Response codes! */

  /* 1XX */
  static const short CONTINUE;
  static const short SWITCH_PROTOCOLS;
  static const short PROCESSING;
  /* 2XX */
  static const short OK;
  static const short CREATED;
  static const short ACCEPTED;
  static const short NON_AUTHORITATIVE;
  static const short NO_CONTENT;
  static const short RESET_CONTENT;
  static const short PARTIAL_CONTENT;
  static const short MULTI_STATUS;
  static const short ALREADY_REPORTED;
  static const short IM_USED;
  /* 3XX */
  static const short MULTIPLE_CHOICES;
  static const short MOVED_PERMANENTLY;
  static const short FOUND;
  static const short SEE_OTHER;
  static const short NOT_MODIFIED;
  static const short USE_PROXY;
  static const short SWITCH_PROXY;
  static const short TEMPORARY_REDIRECT;
  static const short PERMANENT_REDIRECT;
  /* 4XX */
  static const short BAD_REQUEST;
  static const short UNAUTHORIZED;
  static const short PAYMENT_REQUIRED;
  static const short FORBIDDEN;
  static const short NOT_FOUND;
  static const short BAD_METHOD;
  static const short NOT_ACCEPTABLE;
  static const short PROXY_AUTH_REQ;
  static const short REQUEST_TIMEOUT;
  static const short CONFLICT;
  static const short GONE;
  static const short LENGTH_REQUIRED;
  static const short PRECOND_FAILED;
  static const short REQUEST_TOO_LARGE;
  static const short URI_TOO_LONG;
  static const short UNSUPPORTED_MEDIA;
  static const short RANGE_NOT_SATISF;
  static const short EXPECTATION_FAILED;
  static const short IM_A_TEAPOT;
  static const short AUTH_TIMEOUT;
  static const short UNPROC_ENTITY;
  static const short LOCKED;
  static const short FAILED_DEPEND;
  static const short UPGRADE_REQUIRED;
  static const short PRECOND_REQUIRED;
  static const short TOO_MANY_REQUESTS;
  static const short HEADER_TOO_LARGE;
  static const short LOGIN_TIMEOUT;
  static const short NO_RESPONSE;
  static const short RETRY_WITH;
  static const short BLOCKED_PARENTAL;
  static const short UNAVAILABLE_LEGAL;
  /* 5XX */
  static const short INTERNAL_ERROR;
  static const short NOT_IMPLEMENTED;
  static const short BAD_GATEWAY;
  static const short SERVICE_UNAVAIL;
  static const short GATEWAY_TIMEOUT;
  static const short VERSION_NOT_SUP;
  static const short VAR_ALSO_NEGOT;
  static const short INSUFF_STORAGE;
  static const short LOOP_DETECTED;
  static const short BW_LIMIT_EXCEED;
  static const short NOT_EXTENDED;
  static const short NW_AUTH_REQ;

  /* Response templates */
  static const std::string defaultResponseTemplate;

 private:
  std::stringstream output;
  short _responseCode;
  std::string contentType;
  struct ResponseCode
  {
    std::string message;
    std::string description;
  };
  static const std::map<short, ResponseCode> responseCodes;
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

  /* Server configuration */
  GloveHttpServer(int listenPort, std::string bind_ip="", const size_t buffer_size=GLOVE_DEFAULT_BUFFER_SIZE, const unsigned backlog_queue=GLOVE_DEFAULT_BACKLOG_QUEUE, int domain=GLOVE_DEFAULT_DOMAIN);
  virtual ~GloveHttpServer();

  std::string serverSignature(std::string newSig);
  std::string serverSignature(GloveHttpRequest& req);
  /* rename: responseTemplates */
  std::string autoResponses(short responseId);
  void addAutoResponse(short id, std::string response);

  void addRoute(std::string route, url_callback callback, int maxArgs=-1, std::vector<std::string> allowedMethods = StandardMethods);
  /* Note, it will add it on any errorCode, right or wrong.
   Use with caution */
  void addResponseProcessor(short errorCode, url_callback callback);
  void addResponseGenericProcessor(short errorCode, url_callback callback);

  /* Information */
  /* get version number, get version */
  /* get stats */

  /* Common callbacks */
  static void fileServer(GloveHttpRequest &request, GloveHttpResponse& response);

  /* Default response processord */
  static void response404Processor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void response5XXProcessor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void responseGenericError(GloveHttpRequest& request, GloveHttpResponse& response);

  /* Errors */

  /* Request line is too short to have needed information */
  static const int ERROR_SHORT_REQUEST = 20;
  /* Request has not URI: There's no space after the METHOD */
  static const int ERROR_NO_URI = 21;
  /* Malformed request string */
  static const int ERROR_MALFORMED_REQUEST = 22;
  /* Timeout when receiving data from client */
  static const int ERROR_TIMED_OUT = 30;

  /* Server request is not a valid HTTP/1.1 request */
  static const int ERROR_BAD_PROTOCOL = 45;

  /* Response messages */
  std::string responseMsg(short id, std::string msg="");
  /* Message IDs */
  static const short int MESSAGE_NOTFOUND;

  /* Response IDs */
  static const short int RESPONSE_ERROR;

 protected:
  Glove *server = NULL;
  std::string defaultContentType;
  std::vector<GloveHttpUri> routes;
  std::map<short, url_callback> responseProcessors;
  std::map<short, std::string> _autoResponses;
  std::map<short, std::string> messages;
  static const std::map<short, std::string> _defaultMessages;
  int port;
  std::string _serverSignature; 

  bool findRoute(std::string method, GloveBase::uri uri, GloveHttpUri* &guri, std::map<std::string, std::string> &special);
  int clientConnection(Glove::Client &client);
  void gloveError(Glove::Client &client, int clientId, GloveException &e);
};

#endif /* _GLOVEHTTPSERVER_H */

