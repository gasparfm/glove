/* @(#)glovehttpserver.h
 */

#ifndef _GLOVEHTTPSERVER_H
#define _GLOVEHTTPSERVER_H 1

#include "glove.hpp"
#include <string>
#include <vector>
#include <sstream>

/** Glove Http Server Version (numeric)  */
#define GHS_VERSION 0001005
/** Glove Http Server Version (string)  */
#define GHS_VERSION_STR "0.1.5"

class GloveHttpServer;

/** Glove Http Errors  */
class GloveHttpErrors
{
 public:
  /** No error  */
  static const short ALL_OK;

  /* Response errors GloveHttpResponse */
  /* action error codes */
  /**
     Cannot read file. Caused by GloveHttpResponse
   */
  static const short FILE_CANNOT_READ;

  /* Vhost errors */

  /** The specified host is not valid. Not for clients. */
  static const short BAD_HOST_NAME;
  /** When you try to create a new alias */
  static const short BAD_ALIAS_NAME;
  /** When you try to retrieve host information */
  static const short CANT_FIND_HOST;
  /** When you try to create an existing vhost */
  static const short HOST_ALREADY_FOUND;

  /* Url retrieving errors GloveHttpServer */
  /** Request line is too short to have needed information */
  static const short ERROR_SHORT_REQUEST;
  /** Request has not URI: There's no space after the METHOD */
  static const short ERROR_NO_URI;
  /** Malformed request string */
  static const short ERROR_MALFORMED_REQUEST;
  /** Timeout when receiving data from client */
  static const short ERROR_TIMED_OUT;
  /** Server request is not a valid HTTP/1.1 request */
  static const short ERROR_BAD_PROTOCOL;

};

/** Glove Http Request  */
class GloveHttpRequest
{
 public:
  /**
   * A Http Request has been generated
   *
   * @param server       Server to connect to
   * @param c            Client who requested
   * @param error        Error
   * @param method       Method
   * @param raw_location Raw location string
   * @param data         Input data
   * @param httpheaders  HTTP headers
   * @param serverPort   Port where the server is.
   */
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
  std::string getVhost();
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

/** Glove Http Response  */
class GloveHttpResponse
{
 public:
  GloveHttpResponse(std::string contentType);
  ~GloveHttpResponse();

  void clear();
  void send(GloveHttpRequest &request, Glove::Client &client);
  short file(std::string filename, bool addheaders=true, std::string contentType="");
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

  friend GloveHttpResponse& operator<<(GloveHttpResponse& out, setCode mn)
  {
    return mn(out);
  }

  struct setContentType : public GloveHttpResponseManipulator<std::string>
  {
  public:
  setContentType(std::string val):GloveHttpResponseManipulator(val)
    {
    }

    GloveHttpResponse& operator()(GloveHttpResponse& out)
    {
      out._contentType = val;
      return out;
    }
  };

  friend GloveHttpResponse& operator<<(GloveHttpResponse& out, setContentType mn)
  {
    return mn(out);
  }

  inline std::string responseVar(std::string key, std::string value)
  {
    this->responseVars[key] = value;
    return this->responseVars[key];
  }

  inline std::string responseVar(std::string key)
  {
    return this->responseVars[key];
  }

  inline std::string responseVar(std::map<std::string, std::string> keyvalmap)
  {
    for (auto x : keyvalmap)
      {
	this->responseVars[x.first] = x.second;
      }
    return "";
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
  std::string _contentType;
  struct ResponseCode
  {
    std::string message;
    std::string description;
  };
  static const std::map<short, ResponseCode> responseCodes;
  /* You can use this key-value storage to pass data between through responses/templates or
     even response processors. */
  std::map<std::string, std::string> responseVars;
  std::string getHeaderVary();
};

using _url_callback = std::function<void(GloveHttpRequest&, GloveHttpResponse&)>;

/** Glove HTTP Uri: Uri control, verify if a request matches a given URL format  */
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

/** Glove HTTP Server  */
class GloveHttpServer
{
 public:
  typedef _url_callback url_callback;
  static const std::vector<std::string> StandardMethods;

  /* Server configuration */
  GloveHttpServer(int listenPort, std::string bind_ip="", const size_t buffer_size=GLOVE_DEFAULT_BUFFER_SIZE, const unsigned backlog_queue=GLOVE_DEFAULT_BACKLOG_QUEUE, int domain=GLOVE_DEFAULT_DOMAIN);
  virtual ~GloveHttpServer();
  std::string defaultContentType(std::string dct="");

  std::string serverSignature(std::string newSig);
  std::string serverSignature(GloveHttpRequest& req);
  void simpleSignature(std::string newSig);
  std::string simpleSignature();
  /* Get vhost name */
  short addVhost(std::string name, std::vector<std::string> aliases={});
  short addVhostAlias(std::string name, std::string alias);
  short addVhostAlias(std::string name, std::vector<std::string> aliases);
  std::string getVhostName(std::string vh);

  /* rename: responseTemplates */
  std::string autoResponses(short responseId);
  void addAutoResponse(short id, std::string response);
  std::string autoResponses(std::string vhost, short responseId);
  void addAutoResponse(std::string vhost, short id, std::string response);

  void addRoute(std::string route, url_callback callback, std::string vhost=defaultVhostName, int maxArgs=-1, std::vector<std::string> allowedMethods = StandardMethods);
  /* Note, it will add it on any errorCode, right or wrong.
   Use with caution */
  void addResponseProcessor(short errorCode, url_callback callback);
  void addResponseGenericProcessor(short errorCode, url_callback callback);
  void addResponseProcessor(std::string vhost, short errorCode, url_callback callback);
  void addResponseGenericProcessor(std::string vhost, short errorCode, url_callback callback);

  /* Information */
  unsigned version();
  std::string versionString();
  /* get stats */

  static std::string unknownMimeType(std::string nmt ="");
  static void addMimeType(std::string extension, std::string mimeType);
  static std::string getMimeType(std::string extension);

  /* Common callbacks */
  static void fileServer(GloveHttpRequest &request, GloveHttpResponse& response);
  static void fileServerExt(GloveHttpRequest &request, GloveHttpResponse& response, std::string localPath);

  /* Default response processord */
  static void response404Processor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void response4XXProcessor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void response5XXProcessor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void responseGenericError(GloveHttpRequest& request, GloveHttpResponse& response);

  /* Response messages */
  std::string responseMsg(short id, std::string msg="");
  /* Message IDs */
  static const short int MESSAGE_NOTFOUND;
  /* Response IDs */
  static const short int RESPONSE_ERROR;


  /* Mime types */
  /* Who would want different MIME Types in different instances
   of the server? */
 protected:
  /* We could make this by method in the future... */
  struct Httpmetrics
  {
    unsigned hits;
    double totalQueryTime;
    double totalProcessingTime;
    double totalResponseTime;
  };

  struct VirtualHost
  {
    std::string name;

    std::vector<GloveHttpUri> routes;
    std::map<short, url_callback> responseProcessors;
    std::map<short, std::string> _autoResponses;
    std::map<short, std::string> messages;
  };

  Glove *server = NULL;
  std::string _defaultContentType;
  std::map<std::string, VirtualHost> vhosts;
  /* The alias and the name will be here, when a request come,
     the host will be searched here. */
  std::map<std::string, std::string> vhosts_aliases;
  std::vector<GloveHttpUri> routes;
  std::map<short, url_callback> responseProcessors;
  std::map<short, std::string> _autoResponses;
  std::map<short, std::string> messages;
  static const std::map<short, std::string> _defaultMessages;
  static const std::string defaultVhostName;

  int port;
  std::string _serverSignature; 
  std::string _simpleSignature;
  static std::map<std::string, std::string> _mimeTypes;
  static std::string _unknownMimeType;
  Httpmetrics metrics;

  void initializeMetrics();
  bool findRoute(VirtualHost& vhost, std::string method, GloveBase::uri uri, GloveHttpUri* &guri, std::map<std::string, std::string> &special);
  int clientConnection(Glove::Client &client);
  void gloveError(Glove::Client &client, int clientId, GloveException &e);
  VirtualHost* getVHost(std::string name);
  void addMetrics(GloveHttpRequest& request, double queryTime, double processingTime, double responseTime);
};

#endif /* _GLOVEHTTPSERVER_H */

