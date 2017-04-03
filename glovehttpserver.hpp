/* @(#)glovehttpserver.h
 */

#ifndef _GLOVEHTTPSERVER_H
#define _GLOVEHTTPSERVER_H 1

#include "glove.hpp"
#include "utils.hpp"
#include "glovehttpcommon.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <functional>

/** Glove Http Server Version (numeric)  */
#define GHS_VERSION 0003001
/** Glove Http Server Version (string)  */
#define GHS_VERSION_STR "0.3.3"

#define GLOVEHTTP_KEEPALIVE_DEFAULT_TIMEOUT 5

#ifndef DEFAULT_SESSION_TIMEOUT
#   define DEFAULT_SESSION_TIMEOUT 86400
#endif

#ifndef DEFAULT_SESSION_ENTRIES
#   define DEFAULT_SESSION_ENTRIES 1000
#endif

/**
 * By default enable openssl. This compiles glove with SSL support
 * More complex but we can make a secure connection transparently
 */
#ifndef ENABLE_COMPRESSION
#   define ENABLE_COMPRESSION 1
#endif

#ifndef ENABLE_WEBSOCKETS
#   define ENABLE_WEBSOCKETS 1
#endif

#if ENABLE_WEBSOCKETS
#   include "glovewebsockets.hpp"
#endif

class GloveHttpServer;
class GloveHttpResponse;

/* Manages key-values to handle session or user information */
class GloveSessionRepository
{
public:
	GloveSessionRepository();
	virtual ~GloveSessionRepository();
	
	void insert(const std::string key, const std::string& value, time_t timeout=0);
	bool remove(const std::string& key);
	bool get(const std::string& key, std::string& value);
	bool pop(const std::string& key, std::string& value);
	
	uint64_t maxEntries(uint64_t val);
	uint64_t maxEntries();

	time_t defaultTimeout(time_t val);
	time_t defaultTimeout();

	void debug();
protected:
	void clearTimeouts();
	void clearOldEntries(uint64_t howmany);
	
private:
	struct sessionInfo_t
	{
		time_t creation, timeout;
		std::string data;
	};
	std::map<std::string, sessionInfo_t> storage;
	uint64_t _maxEntries;
	time_t _defaultTimeout;
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
  std::string& getData() const;
  std::string getData(std::string el, bool exact=true) const;
  std::vector<std::pair<std::string, std::string> > getDataCol(std::string el, bool exact=true) const;
  std::vector<std::pair<std::string, std::string> > getDataCol() const;
  std::string getContentType() const;
  std::string getEncoding() const;
  std::map<std::string, std::string>& getHeaders() const;
  std::string getHeader(std::string h) const;
	std::string getAuthType() const;
	std::string getAuthUser() const;
	bool connectionIs(std::string what);
  std::string getVhost();
  GloveBase::uri getUri() const;
	bool auth(GloveHttpResponse& response, std::function<int(GloveHttpRequest&, GloveHttpResponse&)> authFunc, const std::string& authTypes, const std::string& realm="Access denied");
	bool checkPassword(const std::string& password);
	
  inline GloveHttpServer* server() const
  {
    return srv;
  }

  std::string getMessage(std::string _template);

	std::string extra(std::string key)
	{
		return gloveData[key];
	}
	
	std::string extra(std::string key, std::string value)
	{
		gloveData[key] = value;
		return value;
	}
	
  /* Special arguments */
  std::map<std::string, std::string> special;
private:
  GloveHttpServer* srv;
  Glove::Client *c;
  GloveBase::uri uri;
  int error;
  std::string contentType;	/* Only if Content-Type is present */
  std::string encoding;		/* Only if Content-Type is present */
  std::string method;
  std::string raw_location, location;
  std::string data;
	std::string authType;
	std::vector<std::string> connectionHeader;
	std::map<std::string, std::string> gloveData;
  std::map<std::string, std::string> headers;
  std::map<std::string, std::string> urlencoded_data;
  void parseContentType(const std::string& method);
  std::string getAuthData(const std::string& raw_location);
	bool checkPasswordBasicAuth(const std::string& password);
	bool checkPasswordDigestAuth(const std::string& password);
	static bool checkDigestAuth(std::string& address, std::string& path, std::map<std::string, std::string>& data, std::string& username);
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

  void clear(bool clearHeaders=true);
  void send(GloveHttpRequest &request, Glove::Client &client);
	int applyCompression(GloveHttpRequest &request, std::vector<std::string>& compression);
  short file(std::string filename, bool addheaders=true, std::string contentType="");
  short code(short rc=0);
  std::string contentType(std::string newContentType);
  std::string contentType();

  inline std::string responseMessage()
	{
		return GloveHttpResponseCode::responseMessage(_responseCode);
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

	std::string header(std::string name);
	std::string header(std::string name, std::string value);
	bool hasHeader(std::string name);

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

  /* Disable response processors. Useful when we have errors directly and don't want to run glovehttpserver methods to generate responses */
  inline bool disableProcessor()
  {
    return _disableProcessor;
  }

  inline void disableProcessor(bool disable)
  {
    _disableProcessor = disable;
  }

  /* Response templates */
  static const std::string defaultResponseTemplate;
private:
  bool _disableProcessor=false;
  std::stringstream output;
  short _responseCode;
  std::string _contentType;
	bool compression;
	
	std::string getFinalOutput(std::vector<std::string>& compression,
														 std::map<std::string, std::string>& headers);
	bool compressionPossible(std::map<std::string, std::string>& headers, std::string& compressionMethod);
  /* You can use this key-value storage to pass data between through responses/templates or
     even response processors. */
  std::map<std::string, std::string> responseVars;
	std::map<std::string, std::string> headers;
  std::string getHeaderVary();
};

using _url_callback = std::function<void(GloveHttpRequest&, GloveHttpResponse&)>;
#if ENABLE_WEBSOCKETS
using _ws_accept_callback = std::function<void(GloveHttpRequest& data, GloveWebSocketHandler& ws)>;
using _ws_receive_callback = std::function<void(GloveWebSocketData& data, GloveWebSocketHandler& ws)>;
using _ws_maintenance_callback = std::function<bool (GloveWebSocketHandler& ws)>;
#endif

class GloveUriService
{
public:
	GloveUriService()
	{
	}

	virtual std::string name() const = 0;
private:
};

class GloveUriHttpService : public GloveUriService
{
public:
	GloveUriHttpService()
	{
	}

	std::string name() const
	{
		return "http";
	}
};

#if ENABLE_WEBSOCKETS
class GloveUriWebSocketService : public GloveUriService
{
public:
	GloveUriWebSocketService(_ws_accept_callback accept, _ws_receive_callback receive, _ws_maintenance_callback maintenance, _ws_maintenance_callback close, uint64_t interval, uint64_t intervalsMaintenance, uint64_t fragmentation):_accept(accept), _receive(receive), _maintenance(maintenance), _close(close), _interval(interval), _intervalsMaintenance(intervalsMaintenance), _fragmentation(fragmentation)
	{
	}

	std::string name() const
	{
		return "websocket";
	}

	/* We can use const frame */
	void accept(GloveHttpRequest& request, GloveWebSocketHandler& ws)
	{
		if (_accept != nullptr)
			_accept(request, ws);
	}

	/* We can use const frame */
	void receive(GloveWebSocketData& data, GloveWebSocketHandler& ws)
	{
		if (_receive != nullptr)
			_receive(data, ws);
	}
	
	bool maintenance(GloveWebSocketHandler& ws)
	{
		if (_maintenance != nullptr)
			return _maintenance(ws);

		return false;
	}

	void close(GloveWebSocketHandler& ws)
	{
		if (_close != nullptr)
			_close(ws);
	}

	uint64_t interval()
	{
		return _interval;
	}

	uint64_t intervalsMaintenance()
	{
		return _intervalsMaintenance;
	}

	uint64_t fragmentation()
	{
		return _fragmentation;
	}
	
private:
	_ws_receive_callback _receive;
	_ws_accept_callback _accept;
	_ws_maintenance_callback _maintenance;
	_ws_maintenance_callback _close;
	uint64_t _interval;
	uint64_t _intervalsMaintenance;
	uint64_t _fragmentation;
};
#endif

/** Glove HTTP Uri: Uri control, verify if a request matches a given URL format  */
class GloveHttpUri
{
public:
  GloveHttpUri(std::string route, _url_callback ucb, int maxArgs, int minArgs, std::vector<std::string> methods, bool partialMatch);
  GloveHttpUri(std::string route, _url_callback ucb, int maxArgs, int minArgs, std::vector<std::string> methods, bool partialMatch, GloveUriService& mission);

  ~GloveHttpUri();

  bool match(std::string method, GloveBase::uri uri, std::map<std::string, std::string> &special);
  void callAction(GloveHttpRequest& request, GloveHttpResponse& response);
	GloveUriService& mission()
	{
		return _mission;
	}
protected:
  int explodeArgs();
private:
  std::string route;
	GloveUriService& _mission;
  int minArgs, maxArgs;
  std::vector<std::string> arguments;
  std::vector<std::string> allowedMethods;
  _url_callback callback;
  bool partialMatch;
};

/** Glove HTTP Server  */
class GloveHttpServer : public GloveHttpCommon
{
public:
  typedef _url_callback url_callback;
	#if ENABLE_WEBSOCKETS
  typedef _ws_receive_callback ws_receive_callback;
  typedef _ws_accept_callback ws_accept_callback;
	typedef _ws_maintenance_callback ws_maintenance_callback;
	#endif
  static const std::vector<std::string> StandardMethods;

  /* Server configuration */
  GloveHttpServer();
  GloveHttpServer(int listenPort, std::string bind_ip="", const size_t buffer_size=GLOVE_DEFAULT_BUFFER_SIZE, const unsigned backlog_queue=GLOVE_DEFAULT_BACKLOG_QUEUE, int domain=GLOVE_DEFAULT_DOMAIN, unsigned max_accepted_clients=GLOVE_DEFAULT_MAX_CLIENTS, double timeout=GLOVE_DEFAULT_TIMEOUT, double keepalive_timeout=GLOVEHTTP_KEEPALIVE_DEFAULT_TIMEOUT, int secure=Glove::UNDEFINED_SSL, std::string certchain="", std::string certkey="");
  virtual ~GloveHttpServer();

  void listen(int listenPort, std::string bind_ip="", const size_t buffer_size=GLOVE_DEFAULT_BUFFER_SIZE, const unsigned backlog_queue=GLOVE_DEFAULT_BACKLOG_QUEUE, int domain=GLOVE_DEFAULT_DOMAIN, unsigned max_accepted_clients=GLOVE_DEFAULT_MAX_CLIENTS, double timeout=GLOVE_DEFAULT_TIMEOUT, double keepalive_timeout=GLOVEHTTP_KEEPALIVE_DEFAULT_TIMEOUT, int secure=Glove::UNDEFINED_SSL, std::string certchain="", std::string certkey="");
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

	/* routes */
  void addRoute(std::string route, url_callback callback, std::string vhost=defaultVhostName, int maxArgs=-1, int minArgs=-1, std::vector<std::string> allowedMethods = StandardMethods, bool partialMatch=false);
  void addRoute(std::string route, url_callback callback, int maxArgs, int minArgs=-1, std::vector<std::string> allowedMethods = StandardMethods);
  #if ENABLE_WEBSOCKETS
  void addWebSocket(std::string route, url_callback callback, ws_accept_callback acceptCallback, ws_receive_callback receiveCallback, ws_maintenance_callback maintenanceCallback=nullptr, ws_maintenance_callback closeCallback=nullptr,  std::string host=defaultVhostName, int maxArgs=-1, int minArgs=-1, bool partialMatch=false, url_callback normalhttp = nullptr);
  void addWebSocket(std::string route, url_callback callback, int maxArgs, ws_accept_callback acceptCallback, ws_receive_callback receiveCallback, ws_maintenance_callback maintenanceCallback=nullptr, ws_maintenance_callback closeCallback=nullptr, int minArgs=-1, bool partialMatch = false, url_callback normalhttp = nullptr);
	#endif
  void addRest(std::string route, std::string host, int minArgs, url_callback get, url_callback post=nullptr, url_callback put=nullptr, url_callback patch=nullptr, url_callback delet=nullptr, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall=nullptr);
  void addRest(std::string route, int minArgs, url_callback get, url_callback post=nullptr, url_callback put=nullptr, url_callback patch=nullptr, url_callback delet=nullptr, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall=nullptr);
  void addRest(std::string route, std::string host, int minArgs, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall, url_callback get, url_callback post=nullptr, url_callback put=nullptr, url_callback patch=nullptr, url_callback delet=nullptr);
  void addRest(std::string route, int minArgs, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall, url_callback get, url_callback post=nullptr, url_callback put=nullptr, url_callback patch=nullptr, url_callback delet=nullptr);
  /* Note, it will add it on any errorCode, right or wrong.
		 Use with caution */
  void addResponseProcessor(short errorCode, url_callback callback);
  void addResponseGenericProcessor(short errorCode, url_callback callback);
  void addResponseProcessor(std::string vhost, short errorCode, url_callback callback);
  void addResponseGenericProcessor(std::string vhost, short errorCode, url_callback callback);

  /* Information */
  unsigned version();
  std::string versionString();
  static std::string getDefaultVhostName()
	{
		return defaultVhostName;
	}

	/* Reject on too many connections */
	void tmcReject(bool enabled);
	void tmcReject(bool enabled, double time, std::string message);
	void tmcReject(double time, std::string message);
  /* get stats */
  /* Gets number of connections */
  unsigned connectionHits()
  {
    return server->totalHits();
  }

  std::map <unsigned, Glove::Client*> get_connected_clients()
  {
    return server->get_connected_clients();
  }

  uint32_t countLoggedConnections()
  {
    return server->countLoggedConnections();
  }

  std::deque<Glove::ConnectionLog> getLoggedConnections()
  {
    return server->getLoggedConnections();
  }

  static std::string unknownMimeType(std::string nmt ="");
  static void addMimeType(std::string extension, std::string mimeType);
  static std::string getMimeType(std::string extension);

  /* Common callbacks */
  static void fileServer(GloveHttpRequest &request, GloveHttpResponse& response);
  static void fileServerExt(GloveHttpRequest &request, GloveHttpResponse& response, std::string localPath);
  static void fileServerFixed(GloveHttpRequest &request, GloveHttpResponse& response, std::string path);
	
  /* Default response processord */
  static void response404Processor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void response4XXProcessor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void response5XXProcessor(GloveHttpRequest& request, GloveHttpResponse& response);
  static void responseGenericError(GloveHttpRequest& request, GloveHttpResponse& response);

	static void defaultApiErrorCall(GloveHttpRequest &request, GloveHttpResponse& response, int errorCode, std::string errorMessage);
	static void jsonApiErrorCall(GloveHttpRequest &request, GloveHttpResponse& response, int errorCode, std::string errorMessage);
  /* Response messages */
  std::string responseMsg(short id, std::string msg="");
  /* Message IDs */
  static const short int MESSAGE_NOTFOUND;
  /* Response IDs */
  static const short int RESPONSE_ERROR;

  /* configuration */
  inline double timeout(double value)
  {
    return this->server->timeout(value);
  }

  inline double timeout()
  {
    return this->server->timeout();
  }

  inline double max_accepted_clients(double value)
  {
    return this->server->max_accepted_clients(value);
  }

  inline double max_accepted_clients()
  {
    return this->server->max_accepted_clients();
  }

  /**
   * Macro to auto-generate getters and setters for some settings.
   * From glove.hpp
   *
   * @param container  Struct where all values are
   * @param type       Data type (int, double, bool)
   * @param option     Option to be set or got
   *
   * @return Current value
   */
#define option_conf(container, type, option) type option(type val)	\
  {																																	\
    return (container.option=val);																	\
  }																																	\
																																		\
  type option()																											\
  {																																	\
    return container.option;																				\
  }

  option_conf(ghoptions, double, keepalive_timeout);
#undef option_conf

	std::string compression(std::string methods)
	{
		ghoptions.compression.clear();
		ghoptions.compression = tokenize(methods, ",", defaultTrim);
		return compression();
	}

	std::vector<std::string>& compressionMethods()
	{
		return ghoptions.compression;
	}
	
	std::string compression()
	{
		std::string out;
		for (auto cm=ghoptions.compression.begin(); cm != ghoptions.compression.end(); ++cm)
			{
				if (cm != ghoptions.compression.begin())
					out+=", ";
				
				out+=*cm;
			}
		return out;
	}

	uint64_t webSocketsMaintenanceInterval(uint64_t val)
	{
		wsMaintenanceInterval = val;
		return wsMaintenanceInterval;
	}

	uint64_t webSocketsMaintenanceInterval()
	{
		return wsMaintenanceInterval;		
	}

	uint64_t webSocketsInterval(uint64_t val)
	{
		wsInterval = val;
		return wsInterval;
	}

	uint64_t webSocketsInterval()
	{
		return wsInterval;
	}

	uint64_t webSocketsFragmentation(uint64_t val)
	{
		wsFragmentation = val;
		return wsFragmentation;
	}

	uint64_t webSocketsFragmentation()
	{
		return wsFragmentation;
	}

  /* Mime types */
  /* Who would want different MIME Types in different instances
		 of the server? */
protected:
  struct
  {
    double keepalive_timeout;	/* if 0, keepalive is disabled */
		std::vector<std::string> compression;	/* compression method enabled */
  } ghoptions;
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

	/* Web Sockets intervals for maintenance callbacks */
	uint64_t wsMaintenanceInterval;
	/* Web Sockets ms for interval */
	uint64_t wsInterval;
	/* Web Sockets message fragmentation size */
	uint64_t wsFragmentation;
  int port;
  std::string _serverSignature; 
  std::string _simpleSignature;
  static std::map<std::string, std::string> _mimeTypes;
  static std::string _unknownMimeType;
  Httpmetrics metrics;

  bool listening;
	void applyProcessors(VirtualHost* vhost, GloveHttpRequest& request, GloveHttpResponse& response, int code);
  void baseInitialization();
  void initializeMetrics();
  bool hasServer()
  {
    return (server!=NULL);
  }
  bool findRoute(VirtualHost& vhost, std::string method, GloveBase::uri uri, GloveHttpUri* &guri, std::map<std::string, std::string> &special);
  int clientConnection(Glove::Client &client);
#if ENABLE_WEBSOCKETS
	bool webSocketHandshake(Glove::Client& client, GloveHttpRequest& req);
	/* Handshake for version 13 */
	bool webSocket13Handshake(Glove::Client& client, GloveHttpRequest& req);
	int doWebSockets(Glove::Client& client, GloveHttpUri* guri, GloveHttpRequest& request, GloveHttpResponse& response);
#endif
  int _receiveData(Glove::Client& client, std::map<std::string, std::string> &httpheaders, std::string &data, std::string &request_method, std::string &raw_location, double timeout=0);

  void gloveError(Glove::Client &client, int clientId, GloveException &e);
  VirtualHost* getVHost(std::string name);
  void addMetrics(GloveHttpRequest& request, double queryTime, double processingTime, double responseTime);
};

#endif /* _GLOVEHTTPSERVER_H */

