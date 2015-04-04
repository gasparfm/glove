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
*  - Based on ideas taken on some PHP Frameworks, Java Servlets and more
*
* Changelog:
*  20150403 : Begin this project
*  20140404 : Added HTTP Response data
*
* To-do:
*   - Loooots of things
*   - Be able to process FastCGI requests to use with Apache/NGinx and more
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

#include "glovehttpserver.h"
#include <chrono>
#include <thread>
#include <map>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>

const std::vector < std::string> GloveHttpServer::StandardMethods ={ "GET", "POST" };

#define AddGloveHttpResponse(response, text, description)	\
  {response, {text, description} }

const int GloveHttpResponse::CONTINUE = 100;
const int GloveHttpResponse::SWITCH_PROTOCOLS = 101;
const int GloveHttpResponse::PROCESSING = 102;      // WebDAV
/* 2XX success */
const int GloveHttpResponse::OK = 200;
const int GloveHttpResponse::CREATED = 201;
const int GloveHttpResponse::ACCEPTED = 202;
const int GloveHttpResponse::NON_AUTHORITATIVE = 203; 
const int GloveHttpResponse::NO_CONTENT = 204;
const int GloveHttpResponse::RESET_CONTENT = 205;
const int GloveHttpResponse::PARTIAL_CONTENT = 206;
const int GloveHttpResponse::MULTI_STATUS = 207;     // WebDAV
const int GloveHttpResponse::ALREADY_REPORTED = 208; // WebDAV
const int GloveHttpResponse::IM_USED = 209;
/* 3XX redirection */
const int GloveHttpResponse::MULTIPLE_CHOICES = 300;
const int GloveHttpResponse::MOVED_PERMANENTLY = 301;
const int GloveHttpResponse::FOUND = 302;
const int GloveHttpResponse::SEE_OTHER = 303;
const int GloveHttpResponse::NOT_MODIFIED = 304;
const int GloveHttpResponse::USE_PROXY = 305;
const int GloveHttpResponse::SWITCH_PROXY = 306;
const int GloveHttpResponse::TEMPORARY_REDIRECT = 307;
const int GloveHttpResponse::PERMANENT_REDIRECT = 308;
/* 4XX client error  */
const int GloveHttpResponse::BAD_REQUEST = 400;
const int GloveHttpResponse::UNAUTHORIZED = 401;
const int GloveHttpResponse::PAYMENT_REQUIRED = 402;
const int GloveHttpResponse::FORBIDDEN = 403;
const int GloveHttpResponse::NOT_FOUND = 404;
const int GloveHttpResponse::BAD_METHOD = 405;
const int GloveHttpResponse::NOT_ACCEPTABLE = 406;
const int GloveHttpResponse::PROXY_AUTH_REQ = 407;
const int GloveHttpResponse::REQUEST_TIMEOUT = 408;
const int GloveHttpResponse::CONFLICT = 409;
const int GloveHttpResponse::GONE = 410;
const int GloveHttpResponse::LENGTH_REQUIRED = 411;
const int GloveHttpResponse::PRECOND_FAILED = 412;
const int GloveHttpResponse::REQUEST_TOO_LARGE = 413;
const int GloveHttpResponse::URI_TOO_LONG = 414;
const int GloveHttpResponse::UNSUPPORTED_MEDIA = 415;
const int GloveHttpResponse::RANGE_NOT_SATISF = 416;
const int GloveHttpResponse::EXPECTATION_FAILED = 417;
const int GloveHttpResponse::IM_A_TEAPOT = 418;
const int GloveHttpResponse::AUTH_TIMEOUT = 419; // Not standard
/* 420 (Method Failure - Spring Framework)
   Not part of the HTTP standard, but defined by Spring in the HttpStatus 
   class to be used when a method failed. This status code is deprecated 
   by Spring. */
/* 420 (Emhance Your Calm - Twitter)
   Not part of the HTTP standard, but returned by version 1 of the Twitter 
   Search and Trends API when the client is being rate limited.[16] Other 
   services may wish to implement the 429 Too Many Requests response code instead. */
/* 421 (Unused) */
const int GloveHttpResponse::UNPROC_ENTITY = 422;   // WebDAV
const int GloveHttpResponse::LOCKED = 423;	    // WebDAV
const int GloveHttpResponse::FAILED_DEPEND = 424;   // WebDAV
/* 425 (Unused) */
const int GloveHttpResponse::UPGRADE_REQUIRED = 426;
/* 427 (Unused) */
const int GloveHttpResponse::PRECOND_REQUIRED = 428;
const int GloveHttpResponse::TOO_MANY_REQUESTS = 429;
/* 430 (Unused) */
const int GloveHttpResponse::HEADER_TOO_LARGE = 431;
/* From 432 there are no used codes. 
   But some of them are used by certain servers (not as part of the standard) */
const int GloveHttpResponse::LOGIN_TIMEOUT = 440;     // Microsoft
const int GloveHttpResponse::NO_RESPONSE = 444;	      // Nginx
const int GloveHttpResponse::RETRY_WITH = 449;	      // Microsoft
const int GloveHttpResponse::BLOCKED_PARENTAL = 450;  // Microsoft
const int GloveHttpResponse::UNAVAILABLE_LEGAL = 451; // Draft: http://tools.ietf.org/html/draft-tbray-http-legally-restricted-status-04

/* 5XX server's fault */
const int GloveHttpResponse::INTERNAL_ERROR = 500;
const int GloveHttpResponse::NOT_IMPLEMENTED = 501;
const int GloveHttpResponse::BAD_GATEWAY = 502;
const int GloveHttpResponse::SERVICE_UNAVAIL = 503;
const int GloveHttpResponse::GATEWAY_TIMEOUT = 504;
const int GloveHttpResponse::VERSION_NOT_SUP = 505;
const int GloveHttpResponse::VAR_ALSO_NEGOT = 506;
const int GloveHttpResponse::INSUFF_STORAGE = 507; // WebDAV
const int GloveHttpResponse::LOOP_DETECTED = 508;  // WebDAV
const int GloveHttpResponse::BW_LIMIT_EXCEED = 509; // Apache extension
const int GloveHttpResponse::NOT_EXTENDED = 510;
const int GloveHttpResponse::NW_AUTH_REQ = 511;

const std::map <int, GloveHttpResponse::ResponseCode> GloveHttpResponse::responseCodes = 
  {
    // List of http status codes (http://en.wikipedia.org/wiki/List_of_HTTP_status_codes)
    /* 1XX informational */
    AddGloveHttpResponse(CONTINUE,          "Continue",             		"The client can continue sending the request body"),
    AddGloveHttpResponse(SWITCH_PROTOCOLS,  "Switching Protocols",  		"Client requested to switch protocols and the server will do so"),
    // WebDAV
    AddGloveHttpResponse(PROCESSING,        "Processing",           		"The request is processing but there's no answer yet (WebDAV; RFC 2518)"),
    /* 2XX success */
    AddGloveHttpResponse(OK,                "OK",                   		"The request completed successfully."),
    AddGloveHttpResponse(CREATED,           "Created",              		"The request has been fulfilled and resulted in a new resource being created."),
    AddGloveHttpResponse(ACCEPTED,          "Accepted",             		"The request has been accepted for processing, but the processing has not been completed."),
    AddGloveHttpResponse(NON_AUTHORITATIVE, "Non-Authoritative Information", 	"The server successfully processed the request, but is returning information that may be from another source."),
    AddGloveHttpResponse(NO_CONTENT, 	    "No Content",                       "The server successfully processed the request, but is not returning any content. Usually used as a response to a successful delete request."),
    AddGloveHttpResponse(RESET_CONTENT,	    "Reset Content",			"The server successfully processed the request, but is not returning any content. Unlike a 204 response, this response requires that the requester reset the document view."),
    AddGloveHttpResponse(PARTIAL_CONTENT,   "Partial Content", 			"The server is delivering only part of the resource (byte serving) due to a range header sent by the client. The range header is used by tools like wget to enable resuming of interrupted downloads, or split a download into multiple simultaneous streams."),
    // WebDAV
    AddGloveHttpResponse(MULTI_STATUS,      "Multi-Status", 			"The message body that follows is an XML message and can contain a number of separate response codes, depending on how many sub-requests were made."),
    // WebDAV
    AddGloveHttpResponse(ALREADY_REPORTED,  "Already Reported",			"The members of a DAV binding have already been enumerated in a previous reply to this request, and are not being included again."),
    AddGloveHttpResponse(IM_USED,           "IM Used", 				"The server has fulfilled a request for the resource, and the response is a representation of the result of one or more instance-manipulations applied to the current instance."),
    /* 3XX redirection */
    AddGloveHttpResponse(MULTIPLE_CHOICES,  "Multiple Choices", 		"Indicates multiple options for the resource that the client may follow. It, for instance, could be used to present different format options for video, list files with different extensions, or word sense disambiguation."),
    AddGloveHttpResponse(MOVED_PERMANENTLY, "Moved Permanently", 		"This and all future requests should be directed to the given URI."),
    AddGloveHttpResponse(FOUND,             "Found", 				"Temporary Redirect on HTTP/1.0"),
    AddGloveHttpResponse(SEE_OTHER,         "See Other", 			"The response to the request can be found under another URI using a GET method. When received in response to a POST (or PUT/DELETE), it should be assumed that the server has received the data and the redirect should be issued with a separate GET message."),
    AddGloveHttpResponse(NOT_MODIFIED,      "Not Modified",			"Indicates that the resource has not been modified since the version specified by the request headers If-Modified-Since or If-None-Match. This means that there is no need to retransmit the resource, since the client still has a previously-downloaded copy."),
    AddGloveHttpResponse(USE_PROXY, 	    "Use Proxy", 		    	"The requested resource is only available through a proxy, whose address is provided in the response"),
    AddGloveHttpResponse(SWITCH_PROXY,      "Switch Proxy",			"No longer used. Originally meant \"Subsequent requests should use the specified proxy.\""),
    AddGloveHttpResponse(TEMPORARY_REDIRECT,"Temprorary Redirect", 		"In this case, the request should be repeated with another URI; however, future requests should still use the original URI."),
    AddGloveHttpResponse(PERMANENT_REDIRECT,"Permanent Redirect", 		"The request, and all future requests should be repeated using another URI."),
    /* 4XX client error */
    AddGloveHttpResponse(BAD_REQUEST,	    "Bad Request", 	       		"The server cannot or will not process the request due to something that is perceived to be a client error"),
    AddGloveHttpResponse(UNAUTHORIZED, 	    "Unauthorized", 			"Similar to 403 Forbidden, but specifically for use when authentication is required and has failed or has not yet been provided. The response must include a WWW-Authenticate header field containing a challenge applicable to the requested resource."),
    AddGloveHttpResponse(PAYMENT_REQUIRED,  "Payment Required", 		"Reserved for future use."),
    AddGloveHttpResponse(FORBIDDEN, 	    "Forbidden", 			"The request was a valid request, but the server is refusing to respond to it. "),
    AddGloveHttpResponse(NOT_FOUND,         "Not Found",			"The requested resource could not be found but may be available again in the future. Subsequent requests by the client are permissible."),
    AddGloveHttpResponse(BAD_METHOD,	    "Method Not Allowed", 		"A request was made of a resource using a request method not supported by that resource."),
    AddGloveHttpResponse(NOT_ACCEPTABLE,    "Not Acceptable",                   "The requested resource is only capable of generating content not acceptable according to the Accept headers sent in the request."),
    AddGloveHttpResponse(PROXY_AUTH_REQ,    "Proxy Authentication Required",	"The client must first authenticate itself with the proxy."),
    AddGloveHttpResponse(REQUEST_TIMEOUT,   "Request Timeout", 			"The server timed out waiting for the request. According to HTTP specifications: \"The client did not produce a request within the time that the server was prepared to wait. The client MAY repeat the request without modifications at any later time.\""),
    AddGloveHttpResponse(CONFLICT, 	    "Conflict", 			"Indicates that the request could not be processed because of conflict in the request, such as an edit conflict in the case of multiple updates."),
    AddGloveHttpResponse(GONE, 		    "Gone", 				"Indicates that the resource requested is no longer available and will not be available again."),
    AddGloveHttpResponse(LENGTH_REQUIRED,   "Length Required", 			"The request did not specify the length of its content, which is required by the requested resource."),
    AddGloveHttpResponse(PRECOND_FAILED,    "Precondition Failed", 		"The server does not meet one of the preconditions that the requester put on the request."),
    AddGloveHttpResponse(REQUEST_TOO_LARGE, "Request Entity Too Large",         "The request is larger than the server is willing or able to process."),
    AddGloveHttpResponse(URI_TOO_LONG,      "Request-URI Too Long",		"The URI provided was too long for the server to process. Often the result of too much data being encoded as a query-string of a GET request, in which case it should be converted to a POST request."),
    AddGloveHttpResponse(UNSUPPORTED_MEDIA, "Unsupported Media Type",		"The request entity has a media type which the server or resource does not support. For example, the client uploads an image as image/svg+xml, but the server requires that images use a different format."),
    AddGloveHttpResponse(RANGE_NOT_SATISF,  "Requested Range Not Satisfiable",  "The client has asked for a portion of the file (byte serving), but the server cannot supply that portion. For example, if the client asked for a part of the file that lies beyond the end of the file."),
    AddGloveHttpResponse(EXPECTATION_FAILED,"Expectation Failed", 		"The server cannot meet the requirements of the Expect request-header field."),
    // Why not? :)
    AddGloveHttpResponse(IM_A_TEAPOT,       "I'm a teapot", 			"This code was defined in 1998 as one of the traditional IETF April Fools' jokes, in RFC 2324"),
    // Not part of the standard
    AddGloveHttpResponse(AUTH_TIMEOUT,      "Authentication Timeout", 		"Previously Authentication has expired"),
    // WebDAV
    AddGloveHttpResponse(UNPROC_ENTITY,     "Unprocessable Entity", 		"The request was well-formed but was unable to be followed due to semantic errors."),
    // WebDAV
    AddGloveHttpResponse(LOCKED, 	    "Locked", 				"The resource that is being accessed is locked."),
    // WebDAV
    AddGloveHttpResponse(FAILED_DEPEND,     "Failed Dependency", 		"The request failed due to failure of a previous request"),
    AddGloveHttpResponse(UPGRADE_REQUIRED,  "Upgrade Required", 		"The client should switch to a different protocol such as TLS/1.0"),
    AddGloveHttpResponse(PRECOND_REQUIRED,  "Precondition Required", 		"The origin server requires the request to be conditional"),
    AddGloveHttpResponse(TOO_MANY_REQUESTS, "Too Many Requests", 		"The user has sent too many requests in a given amount of time. Intended for use with rate limiting schemes."),
    AddGloveHttpResponse(HEADER_TOO_LARGE,  "Request Header Fields Too Large",  "The server is unwilling to process the request because either an individual header field, or all the header fields collectively, are too large."),
    AddGloveHttpResponse(LOGIN_TIMEOUT,     "Login Timeout", 			"A Microsoft extension. Indicates that your session has expired"),
    AddGloveHttpResponse(NO_RESPONSE, 	    "No Response", 			"Used in Nginx logs to indicate that the server has returned no information to the client and closed the connection (useful as a deterrent for malware)."),
    AddGloveHttpResponse(RETRY_WITH, 	    "Retry With", 			"A Microsoft extension. The request should be retried after performing the appropriate action."),
    AddGloveHttpResponse(BLOCKED_PARENTAL,  "Blocked by Windows Parental Controls", "A Microsoft extension. This error is given when Windows Parental Controls are turned on and are blocking access to the given webpage."),
    AddGloveHttpResponse(UNAVAILABLE_LEGAL, "Unavailable For Legal Reasons",    "Intended to be used when resource access is denied for legal reasons, e.g. censorship or government-mandated blocked access."),
    /* 5XX server's fault  */
    AddGloveHttpResponse(INTERNAL_ERROR,    "Internal Server Error", 		"A generic error message, given when an unexpected condition was encountered and no more specific message is suitable."),
    AddGloveHttpResponse(NOT_IMPLEMENTED,   "Not Implemented", 			"The server either does not recognize the request method, or it lacks the ability to fulfil the request. Usually this implies future availability."),
    AddGloveHttpResponse(BAD_GATEWAY,       "Bad Gateway", 			"The server was acting as a gateway or proxy and received an invalid response from the upstream server."),
    AddGloveHttpResponse(SERVICE_UNAVAIL,   "Service Unavailable", 		"The server is currently unavailable (because it is overloaded or down for maintenance). Generally, this is a temporary state."),
    AddGloveHttpResponse(GATEWAY_TIMEOUT,   "Gateway Timeout", 			"The server was acting as a gateway or proxy and did not receive a timely response from the upstream server."),
    AddGloveHttpResponse(VERSION_NOT_SUP,   "HTTP Version Not Supported", 	"The server does not support the HTTP protocol version used in the request."),
    AddGloveHttpResponse(VAR_ALSO_NEGOT,    "Variant Also Negotiates", 		"Transparent content negotiation for the request results in a circular reference"),
    AddGloveHttpResponse(INSUFF_STORAGE,    "Insufficient Storage", 		"The server is unable to store the representation needed to complete the request."),
    AddGloveHttpResponse(LOOP_DETECTED,     "Loop Detected", 			"The server detected an infinite loop while processing the request."),
    AddGloveHttpResponse(BW_LIMIT_EXCEED,   "Bandwidth Limit Exceeded", 	"This status code is not specified in any RFCs. Its use is unknown."),
    AddGloveHttpResponse(NOT_EXTENDED,      "Not Extended", 			"Further extensions to the request are required for the server to fulfil it."),
    AddGloveHttpResponse(NW_AUTH_REQ, 	    "Netwok Authentication Required",   "The client needs to authenticate to gain network access.")
  };
namespace
{
  const std::string white_spaces( " \f\n\r\t\v" );

  std::string trim( std::string str, const std::string& trimChars = white_spaces )
  {
    std::string::size_type pos_end = str.find_last_not_of( trimChars );
    std::string::size_type pos_start = str.find_first_not_of( trimChars );

    return str.substr( pos_start, pos_end - pos_start + 1 );
  }

  void extract_headers( std::string input, std::map<std::string, std::string> &headers, int start)
  {
    std::string::size_type colon;
    std::string::size_type crlf;

    if ( ( colon = input.find(':', start) ) != std::string::npos && 
	 ( ( crlf = input.find(Glove::CRLF, start) ) != std::string::npos ) )
      {
	headers.insert( std::pair<std::string, std::string>( trim( input.substr(start, colon - start) ),
							     trim( input.substr(colon+1, crlf - colon -1 ) ) )
			);

	extract_headers(input, headers, crlf+2);
      }
  }
};

namespace
{
  /** Extract a whole file into a string */
  static std::string extractFile(const char *filename, size_t bufferSize=512)
  {
    int fd = open(filename, O_RDONLY);
    std::string output;

    if (fd==-1)
      return "";		/* error opening */

    char *buffer = (char*)malloc(bufferSize);
    if (buffer==NULL)
      return "";		/* Can't allocate memory */

    int datalength;
    while ((datalength = read(fd, buffer, bufferSize)) > 0)
      output.append(buffer, datalength);

    close(fd);
    return output;
  }
};

GloveHttpRequest::GloveHttpRequest(Glove::Client *c, int error, std::string method, std::string raw_location, std::string data, std::map<std::string, std::string> httpheaders, int serverPort):
  c(c), error(error), raw_location(raw_location), method(method), data(data), headers(httpheaders)
{
  location = Glove::urldecode(raw_location);

  // More services soon !!
  std::string service = "http://";

  std::string thishost = headers["Host"];
  if (thishost.empty())
    thishost = c->get_address(true)+":"+std::to_string(serverPort);

  std::string auth = getAuthData();
  uri = GloveBase::get_from_uri(service+((auth.empty())?"":auth+"@")+thishost+location);
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

GloveBase::uri GloveHttpRequest::getUri() const
{
  return uri;
}

std::string GloveHttpRequest::getAuthData()
{
  auto auth = headers.find("Authorization");
  if (auth == headers.end())
    return "";

  std::string authtype = auth->second.substr(0,auth->second.find(' '));
  if (authtype=="Basic")
    {
      return Glove::base64_decode(auth->second.substr(auth->second.find(' ')+1));
    }
  else				// Not implemented
    return "";
}

GloveHttpResponse::GloveHttpResponse(std::string contentType):contentType(contentType),returnCode(GloveHttpResponse::OK)
{

}

GloveHttpResponse::~GloveHttpResponse()
{
}

void GloveHttpResponse::send(Glove::Client &client)
{
  client << "HTTP/1.1 200 OK"<<Glove::CRLF<<Glove::CRLF;
  client << output.str();
}

GloveHttpUri::GloveHttpUri(std::string route, _url_callback ucb, int maxArgs, std::vector<std::string> methods):
  route(route),
  callback(ucb),
  maxArgs(maxArgs), 
  allowedMethods(methods)
{
  if (route.front() != '/')
    route='/'+route;

  this->minArgs = explodeArgs();
  if (this->maxArgs<0)
    this->maxArgs=this->minArgs;
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
  std::cout << "args: "<<args<<std::endl;
  std::cout << "Min: "<<minArgs<<"; Max="<<maxArgs<<std::endl;
  if ( (args<minArgs) || (args>maxArgs) )
    return false;

  auto uria = uri.path.begin();

  for (auto a : arguments)
    {
      if (uria == uri.path.end())
	return false;

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
  std::cout << "LO VOY A LLAMAR"<<std::endl;
  callback(request, response);
}

GloveHttpServer::GloveHttpServer(int listenPort, std::string bind_ip, const size_t buffer_size, const unsigned backlog_queue, int domain):port(listenPort)
{
  server = new Glove(listenPort, 
  		     std::bind(&GloveHttpServer::clientConnection, this, std::placeholders::_1),
  		     bind_ip,
  		     buffer_size, 
  		     std::bind(&GloveHttpServer::gloveError, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
  		     backlog_queue,
  		     domain);
  server->max_accepted_clients(2);
  server->timeout(4);
}

GloveHttpServer::~GloveHttpServer()
{
  if (server != NULL)
    {
      // Clean up server
    }
}

void GloveHttpServer::addRoute(std::string route, url_callback callback, int maxArgs, std::vector<std::string> allowedMethods)
{
  routes.push_back(GloveHttpUri(route, callback, maxArgs, allowedMethods));
}

bool GloveHttpServer::findRoute(std::string method, GloveBase::uri uri, GloveHttpUri* &guri, std::map<std::string, std::string> &special)
{
  for (auto r = routes.begin(); r!=routes.end(); ++r)
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

// Some code borrowed from knot:
//   - https://github.com/gasparfm/knot
// Original knot:
//   - https://github.com/r-lyeh/knot
int GloveHttpServer::clientConnection(Glove::Client &client)
{
  std::cout << "Tengo un nuevo cliente" <<std::endl;
  std::cout << "IP: "<<client.get_address(true)<<std::endl;
  std::cout << "HOST: "<<client.get_host()<<std::endl;
  std::cout << "SERVICE: "<<client.get_service()<<std::endl;

  std::string input, data, request_method, raw_location;
  std::map<std::string, std::string> httpheaders;
  int error = 0;
  bool receiving = true;
  long content_length = -1;
  long payload_received = 0;
  long total_received = 0;
  std::string::size_type first_crlf;

  client >> Glove::Client::set_read_once(true);
  client >> Glove::Client::set_exception_on_timeout(false);
  while (receiving)
    {
      std::string recv;
      client >> recv;
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
	  if (input.find(Glove::CRLF) == std::string::npos)
	    continue;

	  std::string::size_type space_pos;
	  request_method = input.substr(0, ( ( space_pos = input.find(' ') ) != std::string::npos )? space_pos : 0  );

	  // Test protocol.
	  // We can improve it adding some more support, but it's enough for
	  // a tiny web service
	  if( input.substr( ( first_crlf = input.find(Glove::CRLF) ) - 8, 8) != "HTTP/1.1" )
	    {
	      error = ERROR_BAD_PROTOCOL;
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
  if (receiving)
    error = ERROR_TIMED_OUT;

  GloveHttpRequest request(&client, error, request_method, raw_location, data, httpheaders, this->port);
  GloveHttpResponse response(defaultContentType);
  GloveHttpUri *guri;

  if (findRoute(request_method, request.getUri(), guri, request.special))
    {
      guri->callAction(request, response);
    }
  else
    {
      // Test for error responses...
    }
  response.send(client);
}

void GloveHttpServer::gloveError(Glove::Client &client, int clientId, GloveException &e)
{

}

void GloveHttpServer::fileServer(GloveHttpRequest &request, GloveHttpResponse& response)
{
  response<<extractFile(request.special["filename"].c_str());
}
