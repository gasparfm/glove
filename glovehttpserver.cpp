/**
*************************************************************
* @file glovehttpserver.cpp
* @brief Tiny http C++11 server using glove with routing and
*        come cool stuff
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 03 apr 2015
*
* Notes:
*  - Based on ideas taken on some PHP Frameworks, Java Servlets 
*    and more. Not intended to use it on big or public websites.
*    Just to use it in an internal and controlled way.
*
* Changelog:
*  20160928 : addRest and overloads to get easy RESTful Api.
*           : Error handler and exception (GloveApiException) for Api.
*  20160916 : addRoute has one more argument (minArgs).
*             addRoute overloaded with simpler access.
*  20160919 : More options to get data from requests GetData(), GetDatacol()
*  20160421 : some server info extracted
*  20160420 : application/x-www-form-urlencoded arguments parse
*  20160418 : Response processors can be disabled
*  20160116 : Base constructor
*  20151009 : Bug fixing, max_clients and timeout added to the constructor
*             GloveHttpServer. You also have getters and setters for that.
*  20151009 : Added keep-alive support, with configurable keepalive_timeout
*  20151008 : Create fileServerExt to include local file paths
*  20151007 : 5 more MIME Types
*  20150430 : Some documentation for Doxygen in the .h
*  20150411 : Basic virtualHost support
*  20150410 : Errors separated to GloveHttpErrors
*  20150410 : Some bug fixing
*  20150404 : Added HTTP Response data
*  20150403 : Begin this project
* 
* To-do:
*   - Error checking for addResponseProcessor() and addResponseGenericProcessor()
*   - Error checking for addAutoResponse() and autoResponses()
*   - Error checking for addRoute()
*   - Metrics into virtualhosts
*   - Documentation !!
*   - Loooots of things more and RFCs compliances
*   - Max. size of strings
*   - Size test of strings
*   - Be able to process FastCGI requests to use with Apache/NGinx and more
*   - Compression
*   - Cache managing
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

#include "glovehttpserver.hpp"
#include "utils.hpp"
#include "glovecoding.hpp"
#include <thread>
#include <map>
#include <string>
#include <algorithm>

const std::vector < std::string> GloveHttpServer::StandardMethods ={ "GET", "POST" };

/* Like Apache error responses */
const std::string GloveHttpResponse::defaultResponseTemplate = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
																																																																				"<html>\n"
	"  <head>\n"
	"    <title>{:title}</title>\n"
	"  </head>\n"
	"<body>\n"
	"  <h1>{:header}</h1>\n"
	"  <p>{:message}</p>\n"
	"  <hr>\n"
	"  <address>{:signature}</address>\n"
	"</body>\n"
	"</html>";

const short GloveHttpServer::RESPONSE_ERROR = 404;
const short GloveHttpServer::MESSAGE_NOTFOUND = 666;

std::string GloveHttpServer::_unknownMimeType = "application/octet-stream";
std::map<std::string, std::string> GloveHttpServer::_mimeTypes = {
  /* page parts */
  {"html", "text/html"},
  {"json", "application/json"},
  {"php", "text/html"},
  {"css", "text/css"},
  {"js", "text/javascript"},
  {"woff", "application/font-woff"},
  /* Images */
  {"jpg", "image/jpeg"}, 
  {"png", "image/png"},
  {"gif", "image/gif"}
};

const std::map<short, std::string> GloveHttpServer::_defaultMessages = {
  { MESSAGE_NOTFOUND, "The requested URL {:urlcut} was not found on this server" }
};

// Default vhost name (internal setting)
const std::string GloveHttpServer::defaultVhostName = "%";

GloveHttpRequest::GloveHttpRequest(GloveHttpServer* server, Glove::Client *c, int error, std::string method, std::string raw_location, std::string data, std::map<std::string, std::string> httpheaders, int serverPort):
  srv(server), c(c), error(error), raw_location(raw_location), method(method), data(data), headers(httpheaders)
{
  /* location = Glove::urldecode(raw_location); */
  // More services soon !!
  std::string service = "http://";

  std::string thishost = headers["Host"];
  if (thishost.empty())
    thishost = c->get_address(true)+":"+std::to_string(serverPort);

  std::string auth = getAuthData();
  uri = GloveBase::get_from_uri(service+((auth.empty())?"":auth+"@")+thishost+raw_location);
  parseContentType(method);

  location = uri.rawpath;
  // uri = GloveBase::get_from_uri
}

GloveHttpRequest::~GloveHttpRequest()
{
}

Glove::Client* GloveHttpRequest::getClient() const
{
  return c;
}

int GloveHttpRequest::getError() const
{
  return error;
}

std::string GloveHttpRequest::getMethod() const
{
  return method;
}

std::string GloveHttpRequest::getLocation() const
{
  return location;
}

std::string GloveHttpRequest::getRawLocation() const
{
  return raw_location;
}

std::string GloveHttpRequest::getContentType() const
{
  return contentType;
}

std::string GloveHttpRequest::getEncoding() const
{
  return encoding;
}
std::string GloveHttpRequest::getData(std::string elem, bool exact) const
{
  if (contentType=="application/x-www-form-urlencoded")
    {
      if (exact)
				{
					auto ud = urlencoded_data.find(elem);
					if (ud != urlencoded_data.end())
						return ud->second;
				}
      else
				{
					auto ud = std::find_if(urlencoded_data.begin(), urlencoded_data.end(), [elem](std::pair<std::string, std::string> el)->bool
																 {
																	 if (el.first.find(elem)!=std::string::npos)
																		 return true;
																 });
					if (ud != urlencoded_data.end())
						return ud->second;
				}
    }
	else if (contentType.substr(0,11)=="application")
		{
			return "";								/* Use getData for that. */
		}

  return "";
}

std::vector<std::pair<std::string, std::string> > GloveHttpRequest::getDataCol(std::string el, bool exact) const
{
  std::vector<std::pair<std::string, std::string> > res;

  if (contentType=="application/x-www-form-urlencoded")
    {
      if (exact)
				{
					for (auto elem : urlencoded_data)
						{
							if (elem.first == el)
								res.push_back(elem);
						}
				}
      else
				{
					/* Replace [] with [ to save brackets.
						 We can use regex in the future when
						 fully supported */
					auto brackets = el.find("[]");
					if (brackets != std::string::npos)
						el.replace(brackets, 2, "[");

					for (auto elem : urlencoded_data)
						{
							if (elem.first.find(el) != std::string::npos)
								res.push_back(elem);
						}
				}
    }
  return res;
}

std::string GloveHttpRequest::getData() const
{
  return data;
}

std::map<std::string, std::string> GloveHttpRequest::getHeaders() const
{
  return headers;
}

std::string GloveHttpRequest::getHeader(std::string h) const
{
  auto el = headers.find(h);
  if ( el != headers.end())
    return el->second;

  return "";
}

std::string GloveHttpRequest::getVhost()
{
  auto headervhost = getHeader("Host");
  return srv->getVhostName(headervhost);
}

GloveBase::uri GloveHttpRequest::getUri() const
{
  return uri;
}

void GloveHttpRequest::parseContentType(const std::string& method)
{
  /* Only when one of these methods is present */
  if ( (method=="POST") || (method=="PUT") )
    {
      auto ctype = getHeader("Content-Type");
      if (ctype.empty())
				return;
      auto semicolon = ctype.find(';');
      /* if the ; is the last character found */
      if ( (semicolon != std::string::npos) && (semicolon<ctype.length()) )
				{
					contentType = trim(ctype.substr(0, semicolon));
					auto _encoding = trim(ctype.substr(semicolon+1));
					auto _encodingEq = _encoding.find('=');
					if ( (_encodingEq != std::string::npos) && (_encoding.substr(0,_encodingEq)=="charset") && (_encodingEq < _encoding.length() ) )
						{
							encoding = _encoding.substr(_encodingEq+1);
						}
				}
      else
				contentType = trim(ctype);
      if (contentType=="application/x-www-form-urlencoded")
				{
					std::string fragment;
					urlencoded_data=Glove::extract_uri_arguments(data, fragment, true);
				}
    }
}

std::string GloveHttpRequest::getAuthData()
{
  auto auth = headers.find("Authorization");
  if (auth == headers.end())
    return "";

  std::string authtype = auth->second.substr(0,auth->second.find(' '));
  if (authtype=="Basic")
    {
      return GloveCoding::base64_decode(auth->second.substr(auth->second.find(' ')+1));
    }
  else				// Not implemented
    return "";
}

std::string GloveHttpRequest::getMessage(std::string _template)
{
  return string_replace(_template, 
												{
													{"{:url}", location},
													{"{:urlcut}", location.substr(0, 50) },
													{"{:method}", method }
												});
  
}

GloveHttpResponse::GloveHttpResponse(std::string contentType):_contentType(contentType),_responseCode(GloveHttpResponseCode::OK)
{

}

GloveHttpResponse::~GloveHttpResponse()
{
}

std::string GloveHttpResponse::contentType(std::string newContentType)
{
  this->_contentType = newContentType;
  return this->_contentType;
}

std::string GloveHttpResponse::contentType()
{
  return this->_contentType;
}

short GloveHttpResponse::code(short rc)
{
  if (rc>0)
    _responseCode = rc;

  return _responseCode;
}

void GloveHttpResponse::send(GloveHttpRequest &request, Glove::Client &client)
{
  std::string outputStr = output.str();
  client << "HTTP/1.1 "<<std::to_string(code())<<" "<<responseMessage()<<Glove::CRLF;
  client << "Date: "<<rfc1123date()<<Glove::CRLF;

  // Server Signature
  std::string serverSig = request.server()->simpleSignature();
  if (!serverSig.empty())
    client << "Server: "<<serverSig<<Glove::CRLF;

  client << getHeaderVary();
  client << "Content-Length: "<<outputStr.size()<<Glove::CRLF;
  client << "Content-Type: "<<_contentType<<Glove::CRLF;
  client << Glove::CRLF;
  client << outputStr;
}

short GloveHttpResponse::file(std::string filename, bool addheaders, std::string contentType)
{
  std::string extension = fileExtension(filename);
  std::string fileContents = extractFile(filename.c_str());
  if (fileContents.empty())
    {
      this->code(GloveHttpResponseCode::NOT_FOUND);
      return GloveHttpErrors::FILE_CANNOT_READ;
    }

  *this << setContentType((contentType.empty())?GloveHttpServer::getMimeType(extension):contentType);
  *this << fileContents;
  return GloveHttpErrors::ALL_OK;
}

void GloveHttpResponse::clear()
{
  output.clear();
}

std::string GloveHttpResponse::getHeaderVary()
{
  return "Vary: Accept-Encoding" + std::string(Glove::CRLF);
}

GloveHttpUri::GloveHttpUri(std::string route, _url_callback ucb, int maxArgs, int minArgs, std::vector<std::string> methods, bool partialMatch):
  route(route),
  callback(ucb),
  maxArgs(maxArgs), 
  allowedMethods(methods),
  partialMatch(partialMatch)
{
  if (route.front() != '/')
    route='/'+route;

	int totalargs = explodeArgs();
  this->minArgs = (minArgs==-1)?totalargs:minArgs;
  if (this->maxArgs<0)
    this->maxArgs=totalargs;
	if (this->maxArgs != this->minArgs)
		this->partialMatch = true;
}

int GloveHttpUri::explodeArgs()
{
  std::string::size_type offset=1;
  std::string::size_type last_offset=1;

  while ( (offset = route.find("/", offset+1) ) != std::string::npos )
    {
      arguments.push_back(route.substr(last_offset, offset-last_offset));
      last_offset = offset+1;
    }

  if (route.length()-last_offset>0)
    arguments.push_back(route.substr(last_offset, route.length()-last_offset));

  return arguments.size();
}

GloveHttpUri::~GloveHttpUri()
{
}

bool GloveHttpUri::match(std::string method, GloveBase::uri uri, std::map<std::string, std::string> &special)
{
  auto index = std::find(allowedMethods.begin(), allowedMethods.end(), method);
  if (index == allowedMethods.end())
    return false;
  // Arguments count out of range
  int args = uri.path.size();
  if ( (args<minArgs) || (args>maxArgs) )
    return false;

  auto uria = uri.path.begin();
  for (auto a : arguments)
    {
      /* If partialMatch is true, the url will match too */
      if (uria == uri.path.end())
				{
					return partialMatch;
				}

      if (a.front() == '$')
				{
					// arguments beginning with $ are keywords
					special.insert({a.substr(1), *uria});
				}
      else
				if (*uria != a)
					return false;

      uria++;
    }
  return true;
}

void GloveHttpUri::callAction(GloveHttpRequest& request, GloveHttpResponse& response)
{
  callback(request, response);
}

std::string GloveHttpServer::serverSignature(std::string newSig)
{
  _serverSignature = newSig;
}

std::string GloveHttpServer::serverSignature(GloveHttpRequest& req)
{
  return string_replace(_serverSignature,
												{
													{"{:serverHost}", req.getUri().host},
														{"{:serverPort}", std::to_string(port)}
												});
}

void GloveHttpServer::simpleSignature(std::string newSig)
{
  _simpleSignature = newSig;
}

std::string GloveHttpServer::simpleSignature()
{
  return _simpleSignature;
}

short GloveHttpServer::addVhost(std::string name, std::vector<std::string> aliases)
{
  if ( (!validHost(name)) && (name != defaultVhostName) )
    return GloveHttpErrors::BAD_HOST_NAME;

  // If vhost is found, can't be repeated
  if (vhosts.find(name) != vhosts.end())
    return GloveHttpErrors::HOST_ALREADY_FOUND;

  for (auto al : aliases)
    {
      if (!validHost(al))
				return GloveHttpErrors::BAD_ALIAS_NAME;
    }

  vhosts.insert({name, VirtualHost()});
  vhosts_aliases.insert({name, "@"});

  for (auto al : aliases)
    vhosts_aliases.insert({name, al});

  addResponseProcessor(name, GloveHttpResponseCode::NOT_FOUND, GloveHttpServer::response404Processor);
  // Errors 5XX
  addResponseGenericProcessor(name, GloveHttpResponseCode::INTERNAL_ERROR, GloveHttpServer::response5XXProcessor);
  // Errors 4XX
  addResponseGenericProcessor(name, GloveHttpResponseCode::BAD_REQUEST, GloveHttpServer::response4XXProcessor);

  addAutoResponse(name, RESPONSE_ERROR, GloveHttpResponse::defaultResponseTemplate);
  messages = _defaultMessages;

  return GloveHttpErrors::ALL_OK;
}

short GloveHttpServer::addVhostAlias(std::string name, std::string alias)
{
  if (vhosts.find(name) == vhosts.end())
    return GloveHttpErrors::CANT_FIND_HOST;

  if (!validHost(alias))
    return GloveHttpErrors::BAD_ALIAS_NAME;

  vhosts_aliases.insert({name, alias});
}

short GloveHttpServer::addVhostAlias(std::string name, std::vector<std::string> aliases)
{
  if (vhosts.find(name) == vhosts.end())
    return GloveHttpErrors::CANT_FIND_HOST;

  for (auto al : aliases)
    {
      if (!validHost(al))
				return GloveHttpErrors::BAD_ALIAS_NAME;
    }

  for (auto al : aliases)
    vhosts_aliases.insert({name, al});

  return GloveHttpErrors::ALL_OK;
}

std::string GloveHttpServer::getVhostName(std::string vh)
{
  // Ignore port in Host header
  if (vh.find(":") != std::string::npos)
    vh = vh.substr(0, vh.find(":"));

  // If empty name, return default vhost
  if (vh.empty())
    return defaultVhostName;

  // If host is invalid, return default
  if (!validHost(vh))
    return defaultVhostName;

  for (auto valiases : vhosts_aliases)
    {
      if (valiases.first == vh)
				{
					return (valiases.second == "@")?valiases.first:valiases.second;
				}
    }

  // If host not found, return default vhost
  return defaultVhostName;
}

GloveHttpServer::VirtualHost* GloveHttpServer::getVHost(std::string name)
{
  auto h = vhosts.find(name);
  if (h != vhosts.end())
    return &h->second;

  return NULL;
}

void GloveHttpServer::baseInitialization()
{
  listening=false;
  _serverSignature = "Glove Http Server/" GHS_VERSION_STR " at {:serverHost} Port {:serverPort}";
  _simpleSignature = "Glove Http Server/" GHS_VERSION_STR;
  _defaultContentType = "text/html; charset=UTF-8";

  if (addVhost("%") != GloveHttpErrors::ALL_OK)
    return;			/* Exception here? */

  initializeMetrics();
}

GloveHttpServer::GloveHttpServer()
{
  baseInitialization();
}

void GloveHttpServer::listen(int listenPort, std::string bind_ip, const size_t buffer_size, const unsigned backlog_queue, int domain, unsigned max_accepted_clients, double timeout, double keepalive_timeout)
{
  port = listenPort;
  namespace ph = std::placeholders;

  ghoptions.keepalive_timeout = keepalive_timeout;


  // addResponseProcessor(GloveHttpResponse::NOT_FOUND, GloveHttpServer::response404Processor);
  // // Errors 5XX
  // addResponseGenericProcessor(GloveHttpResponse::INTERNAL_ERROR, GloveHttpServer::response5XXProcessor);
  // // Errors 4XX
  // addResponseGenericProcessor(GloveHttpResponse::BAD_REQUEST, GloveHttpServer::response4XXProcessor);

  // addAutoResponse(RESPONSE_ERROR, GloveHttpResponse::defaultResponseTemplate);
  // messages = _defaultMessages;

  server = new Glove(listenPort, 
										 std::bind(&GloveHttpServer::clientConnection, this, ph::_1),
										 bind_ip,
										 buffer_size, 
										 std::bind(&GloveHttpServer::gloveError, this, ph::_1, ph::_2, ph::_3),
										 backlog_queue,
										 domain);
  server->max_accepted_clients(max_accepted_clients);
  server->timeout(timeout);
}

GloveHttpServer::GloveHttpServer(int listenPort, std::string bind_ip, const size_t buffer_size, const unsigned backlog_queue, int domain, unsigned max_accepted_clients, double timeout, double keepalive_timeout)
{
  baseInitialization();
  listen(listenPort, bind_ip, buffer_size, backlog_queue, domain, max_accepted_clients, timeout, keepalive_timeout);
}

GloveHttpServer::~GloveHttpServer()
{
  if (server != NULL)
    {
      // Clean up server
    }
}

std::string GloveHttpServer::defaultContentType(std::string dct)
{
  if (!dct.empty())
    _defaultContentType = dct;

  return _defaultContentType;
}

void GloveHttpServer::addRoute(std::string route, url_callback callback, std::string host, int maxArgs, int minArgs, std::vector<std::string> allowedMethods, bool partialMatch)
{
  auto vhost = getVHost(host);
  vhost->routes.push_back(GloveHttpUri(route, callback, maxArgs, minArgs, allowedMethods, partialMatch));
}

void GloveHttpServer::addRoute(std::string route, url_callback callback, int maxArgs, int minArgs, std::vector<std::string> allowedMethods)
{
  auto vhost = getVHost(defaultVhostName);
  vhost->routes.push_back(GloveHttpUri(route, callback, maxArgs, minArgs, allowedMethods, false));
}

void GloveHttpServer::addRest(std::string route, std::string host, int minArgs, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall, url_callback get, url_callback post, url_callback put, url_callback patch, url_callback delet)
{
	addRest(route, host, minArgs, get, post, put, patch, delet, errorCall);		
}

void GloveHttpServer::addRest(std::string route, int minArgs, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall, url_callback get, url_callback post, url_callback put, url_callback patch, url_callback delet)
{
	addRest(route, defaultVhostName, minArgs, get, post, put, patch, delet, errorCall);
}

void GloveHttpServer::addRest(std::string route, int minArgs, url_callback get, url_callback post, url_callback put, url_callback patch, url_callback delet, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall)
{
	addRest(route, defaultVhostName, minArgs, get, post, put, patch, delet, errorCall);
}

void GloveHttpServer::addRest(std::string route, std::string host, int minArgs, url_callback get, url_callback post, url_callback put, url_callback patch, url_callback delet, std::function<void(GloveHttpRequest &request, GloveHttpResponse& response, int, std::string)> errorCall)
{
	std::vector<std::string> allowedMethods;
	if (get != nullptr)
		allowedMethods.push_back("GET");
	if (post != nullptr)
		allowedMethods.push_back("POST");
	if (put != nullptr)
		allowedMethods.push_back("PUT");
	if (patch != nullptr)
		allowedMethods.push_back("PATCH");
	if (delet != nullptr)
		allowedMethods.push_back("DELETE");
	if (errorCall == nullptr)
		errorCall = &GloveHttpServer::defaultApiErrorCall;
	
	auto vhost = getVHost(host);
	auto restProcessor = [get,post,put,patch,delet,errorCall] (GloveHttpRequest& request, GloveHttpResponse& response)
		{
			try
				{
					auto method = request.getMethod();
					/* If we don't have the function declared, it won't pass here */
					if (method=="GET")
						get(request, response);
					else if (method=="POST")
						post(request, response);
					else if (method=="PUT")
						put(request, response);
					else if (method=="PATCH")
						patch(request, response);
					else if (method=="DELETE")
						delet(request, response);
				}
			catch (GloveApiException &e)
				{
					errorCall(request, response, e.code(), e.what());
				}
			catch (GloveException &e)
				{
					#ifdef DEBUG
					errorCall(request, response, e.code(), e.what());
					#else
					errorCall(request, response, 0, "Internal error");
					#endif
				}
			catch (std::exception &e)
				{
					#ifdef DEBUG
					errorCall(request, response, -1, e.what());
					#else
					errorCall(request, response, 0, "Internal error");
					#endif
				}			 
		};
  vhost->routes.push_back(GloveHttpUri(route, restProcessor, -1, minArgs, allowedMethods, true));

}

void GloveHttpServer::jsonApiErrorCall(GloveHttpRequest &request, GloveHttpResponse& response, int errorCode, std::string errorMessage)
{
	response.clear();
	response.contentType("application/json");
	response << "{ \"error\": \""+errorMessage+"\",\n"
		" \"code\" : \""+std::to_string(errorCode)+"\" }";
}

void GloveHttpServer::defaultApiErrorCall(GloveHttpRequest &request, GloveHttpResponse& response, int errorCode, std::string errorMessage)
{
	response.clear();
	response.contentType("text/plain");
	response << "Error ("+std::to_string(errorCode)+"): "+errorMessage;
}

void GloveHttpServer::addResponseProcessor(short errorCode, url_callback callback)
{
  // Single vhost old line
  // responseProcessors[errorCode] = callback;

  auto vhost = getVHost(defaultVhostName);
  vhost->responseProcessors[errorCode] = callback;
}

void GloveHttpServer::addResponseGenericProcessor(short errorCode, url_callback callback)
{
  // Single vhost old line
  // responseProcessors[-errorCode/100] = callback;

  auto vhost = getVHost(defaultVhostName);
  vhost->responseProcessors[-errorCode/100] = callback;
}

void GloveHttpServer::addResponseProcessor(std::string host, short errorCode, url_callback callback)
{
  auto vhost = getVHost(host);
  vhost->responseProcessors[errorCode] = callback;
}

void GloveHttpServer::addResponseGenericProcessor(std::string host, short errorCode, url_callback callback)
{
  auto vhost = getVHost(host);
  vhost->responseProcessors[-errorCode/100] = callback;
}

void GloveHttpServer::initializeMetrics()
{
  
}

bool GloveHttpServer::findRoute(VirtualHost& vhost, std::string method, GloveBase::uri uri, GloveHttpUri* &guri, std::map<std::string, std::string> &special)
{
  for (auto r = vhost.routes.begin(); r!=vhost.routes.end(); ++r)
    {
      special.clear();
      if (r->match(method, uri, special))
				{
					guri=&(*r);
					return true;
				}
    }
  return false;
}

int GloveHttpServer::_receiveData(Glove::Client& client, std::map<std::string, std::string> &httpheaders, std::string &data, std::string &request_method, std::string &raw_location, double timeout)
{
  long content_length = -1;
  long payload_received = 0;
  long total_received = 0;
  int error = 0;
  std::string::size_type first_crlf;
  bool receiving = true;
  std::string input;
  double currentTimeout;

  if (timeout)			/* Maybe higher timeout when keepalive is on */
    {
      client.timeout(timeout);
      client.timeout();
    }

  while (receiving)
    {
      std::string recv;
      client >> recv;
      if (timeout)
				{
					client.timeout(currentTimeout);
					timeout=0;
				}

      int bytes_received = recv.length();

      if (bytes_received == 0)
				{
					break;
				}

      total_received += bytes_received;

      if (content_length > -1)
				{
					// Receiving payload
					payload_received += bytes_received;
					data += recv;
				}
      else
				{
					input += recv;
					// Receiving headers
				}

      if (request_method.empty())
				{
					// Don't have enough information
					// CRLF not yet received
					if ( (first_crlf = input.find(Glove::CRLF) ) == std::string::npos)
						continue;

					if ( first_crlf < 9 )
						{
							error = GloveHttpErrors::ERROR_SHORT_REQUEST;
							break;
						}

					std::string::size_type space_pos;
					space_pos = input.find(' ');
					if (space_pos == std::string::npos)
						{
							error = GloveHttpErrors::ERROR_NO_URI;
							break;
						}

					request_method = input.substr(0, ( ( space_pos = input.find(' ') ) != std::string::npos )? space_pos : 0  );

					// Test protocol.
					// We can improve it adding some more support, but it's enough for
					// a tiny web service
					if( input.substr( first_crlf - 8, 8) != "HTTP/1.1" )
						{
							error = GloveHttpErrors::ERROR_BAD_PROTOCOL;
							break;
						}

					if (first_crlf-8-space_pos<=0)
						{
							error = GloveHttpErrors::ERROR_MALFORMED_REQUEST;
							break;
						}

					raw_location = trim(input.substr(space_pos, first_crlf-8-space_pos) );
				}

      // try to find the first CRLFCRLF which indicates the end of headers and
      // find out if we have payload, only if "Content-length" header is set.
      // it's possible to have payload without Content-length, but we won't have
      // this case.
      std::string::size_type crlf_2 = input.find("\r\n\r\n");
      if( crlf_2 != std::string::npos && content_length == -1 )
				{
					extract_headers(input, httpheaders, first_crlf+2);
					if ( !httpheaders["Content-Length"].empty() )
						{
							// We have Content-Length
							content_length = atoi( httpheaders["Content-Length"].c_str() );
							payload_received = input.length() - crlf_2;
							data = input.substr(crlf_2+4);
							input.erase(crlf_2);
						}
					else
						receiving = false;
				}

      if (content_length > -1 && payload_received >= content_length)
				receiving = false;
    }

  if ( (!error) && (receiving) )
    error = GloveHttpErrors::ERROR_TIMED_OUT;

  return error;
}

// Some code borrowed from knot:
//   - https://github.com/gasparfm/knot
// Original knot:
//   - https://github.com/r-lyeh/knot
int GloveHttpServer::clientConnection(Glove::Client &client)
{
  std::cout << "IP: "<<client.get_address(true)<<std::endl;

  bool finished = false;
  unsigned totalRequests = 0;
  client >> Glove::Client::set_read_once(true);
  client >> Glove::Client::set_exception_on_timeout(false);
  auto startTime = std::chrono::steady_clock::now();
  do
    {
      std::string data, request_method, raw_location;
      std::map<std::string, std::string> httpheaders;
      int error = 0;
      error = _receiveData(client, httpheaders, data, request_method, raw_location, (totalRequests)?ghoptions.keepalive_timeout:0);
      if (error == GloveHttpErrors::ERROR_TIMED_OUT)
				return 0;

      if ( (ghoptions.keepalive_timeout<=0) || (httpheaders["Connection"] != "keep-alive") ) 
				finished = true;
      auto requestTime = std::chrono::steady_clock::now();
      GloveHttpRequest request(this, &client, error, request_method, raw_location, data, httpheaders, this->port);
      /* new request */
      GloveHttpResponse response(_defaultContentType);
      std::cout << "Request: "<<raw_location<<std::endl;
      auto vhost = getVHost(request.getVhost());
      if (error)
				{
					switch (error)
						{
						case GloveHttpErrors::ERROR_SHORT_REQUEST:
						case GloveHttpErrors::ERROR_NO_URI:
							response<<GloveHttpResponse::setCode(GloveHttpResponseCode::BAD_REQUEST);
							break;
						case GloveHttpErrors::ERROR_BAD_PROTOCOL:
							response<<GloveHttpResponse::setCode(GloveHttpResponseCode::VERSION_NOT_SUP);
							break;
						default:
							response<<GloveHttpResponse::setCode(GloveHttpResponseCode::INTERNAL_ERROR);
						}
				}
      else
				{
					GloveHttpUri *guri;
					if (findRoute(*vhost, request_method, request.getUri(), guri, request.special))
						{
							guri->callAction(request, response);
						}
					else
						{
							response<<GloveHttpResponse::setCode(GloveHttpResponseCode::NOT_FOUND);
							// Test for error responses...
						}
				}
      if (!response.disableProcessor())
				{
					auto resproc = vhost->responseProcessors.find(response.code());
					if (resproc != vhost->responseProcessors.end())
						resproc->second(request, response);
					else
						{
							// Generic processors
							resproc = vhost->responseProcessors.find(-response.code()/100);
							if (resproc != vhost->responseProcessors.end())
								{
									resproc->second(request, response);
								}
						}
				}
      // request chrono, processing chrono..
      auto processingTime = std::chrono::steady_clock::now();
      response.send(request, client);
      auto responseTime = std::chrono::steady_clock::now();
      addMetrics(request, (double) std::chrono::duration_cast<std::chrono::milliseconds>(requestTime - startTime).count() / 1000,
								 (double) std::chrono::duration_cast<std::chrono::milliseconds>(processingTime - requestTime).count() / 1000,
								 (double) std::chrono::duration_cast<std::chrono::milliseconds>(responseTime - requestTime).count() / 1000
			);
      ++totalRequests;
      /* Maybe we can store this measure too */
      startTime = std::chrono::steady_clock::now();
    } while (!finished);
}

void GloveHttpServer::gloveError(Glove::Client &client, int clientId, GloveException &e)
{

}

unsigned GloveHttpServer::version()
{
  return GHS_VERSION;
}

std::string GloveHttpServer::versionString()
{
  return GHS_VERSION_STR;
}

std::string GloveHttpServer::unknownMimeType(std::string nmt)
{
  if (!nmt.empty())
    GloveHttpServer::_unknownMimeType = nmt;

  return GloveHttpServer::_unknownMimeType;
}

void GloveHttpServer::addMimeType(std::string extension, std::string mimeType)
{
  GloveHttpServer::_mimeTypes.insert({extension, mimeType});
}


void GloveHttpServer::fileServer(GloveHttpRequest &request, GloveHttpResponse& response)
{
  response.file(request.special["filename"]);
}

void GloveHttpServer::fileServerExt(GloveHttpRequest &request, GloveHttpResponse& response, std::string localPath)
{
  if (localPath.empty())
    response.file(request.special["filename"]); /* just as fileServer*/
  else
    response.file(localPath+request.special["filename"]);
}

std::string GloveHttpServer::getMimeType(std::string extension)
{
  auto f = GloveHttpServer::_mimeTypes.find(extension);
  if (f != GloveHttpServer::_mimeTypes.end())
    return f->second;

  return GloveHttpServer::GloveHttpServer::_unknownMimeType;
}

void GloveHttpServer::responseGenericError(GloveHttpRequest& request, GloveHttpResponse& response)
{
  response.clear();
  std::string msg = response.responseVar("errorMessage");
  if (msg.empty())
    msg = request.server()->responseMsg(MESSAGE_NOTFOUND);
  response << string_replace(request.server()->autoResponses(request.getVhost(), GloveHttpServer::RESPONSE_ERROR),
														 {
															 {"{:title}", std::to_string(response.code())+" "+response.responseMessage()},
																 {"{:header}", response.responseMessage()},
																	 {"{:message}", request.getMessage(msg)},
																		 {"{:signature}",request.server()->serverSignature(request)}
														 });
}

void GloveHttpServer::response5XXProcessor(GloveHttpRequest& request, GloveHttpResponse& response)
{
  responseGenericError(request, response);
}

void GloveHttpServer::response4XXProcessor(GloveHttpRequest& request, GloveHttpResponse& response)
{
  responseGenericError(request, response);
}

void GloveHttpServer::response404Processor(GloveHttpRequest& request, GloveHttpResponse& response)
{
  response.clear();
  response << string_replace(request.server()->autoResponses(request.getVhost(), GloveHttpServer::RESPONSE_ERROR),
														 {
															 {"{:title}", "404 Not Found"},
															 {"{:header}", "Not Found"},
															 {"{:message}", request.getMessage(request.server()->responseMsg(MESSAGE_NOTFOUND))},
															 {"{:signature}",request.server()->serverSignature(request)}
														 });
}

void GloveHttpServer::addAutoResponse(std::string host, short id, std::string response)
{
  auto vhost = getVHost(host);
  vhost->_autoResponses[id] = response;
}

std::string GloveHttpServer::autoResponses(std::string host, short responseId)
{
  auto vhost = getVHost(host);

  auto rit = vhost->_autoResponses.find(responseId);
  if (rit!=vhost->_autoResponses.end())
    return rit->second;

  return "";
}

void GloveHttpServer::addAutoResponse(short id, std::string response)
{
  addAutoResponse(defaultVhostName, id, response);
}

std::string GloveHttpServer::autoResponses(short responseId)
{
  return autoResponses(defaultVhostName, responseId);
}

std::string GloveHttpServer::responseMsg(short id, std::string msg)
{
  if (msg.empty())
    {
      auto _msg = messages.find(id);
      if (_msg != messages.end())
				return _msg->second;
    }
  else
    messages[id] = msg;

  return msg;
}

void GloveHttpServer::addMetrics(GloveHttpRequest& request, double queryTime, double processingTime, double responseTime)
{
  ++metrics.hits;
  metrics.totalQueryTime+=queryTime;
  metrics.totalProcessingTime+=processingTime;
  metrics.totalResponseTime+=responseTime;

  /* std::cout << "Request: "<<queryTime<<"s. T:"<<metrics.totalQueryTime<<"."<<std::endl; */
  /* std::cout << "Processing: "<<processingTime<<"s. T:"<<metrics.totalProcessingTime<<"."<<std::endl; */
  /* std::cout << "Answer: "<<responseTime<<"s. T:"<<metrics.totalResponseTime<<"."<<std::endl; */
}
