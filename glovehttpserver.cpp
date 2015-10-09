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
*   - Keepalive
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

#include "glovehttpserver.h"
#include <thread>
#include <map>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>

const std::vector < std::string> GloveHttpServer::StandardMethods ={ "GET", "POST" };

#define AddGloveHttpResponse(response, text, description)	\
  {response, {text, description} }

const short GloveHttpResponse::CONTINUE = 100;
const short GloveHttpResponse::SWITCH_PROTOCOLS = 101;
const short GloveHttpResponse::PROCESSING = 102;      // WebDAV
/* 2XX success */
const short GloveHttpResponse::OK = 200;
const short GloveHttpResponse::CREATED = 201;
const short GloveHttpResponse::ACCEPTED = 202;
const short GloveHttpResponse::NON_AUTHORITATIVE = 203; 
const short GloveHttpResponse::NO_CONTENT = 204;
const short GloveHttpResponse::RESET_CONTENT = 205;
const short GloveHttpResponse::PARTIAL_CONTENT = 206;
const short GloveHttpResponse::MULTI_STATUS = 207;     // WebDAV
const short GloveHttpResponse::ALREADY_REPORTED = 208; // WebDAV
const short GloveHttpResponse::IM_USED = 209;
/* 3XX redirection */
const short GloveHttpResponse::MULTIPLE_CHOICES = 300;
const short GloveHttpResponse::MOVED_PERMANENTLY = 301;
const short GloveHttpResponse::FOUND = 302;
const short GloveHttpResponse::SEE_OTHER = 303;
const short GloveHttpResponse::NOT_MODIFIED = 304;
const short GloveHttpResponse::USE_PROXY = 305;
const short GloveHttpResponse::SWITCH_PROXY = 306;
const short GloveHttpResponse::TEMPORARY_REDIRECT = 307;
const short GloveHttpResponse::PERMANENT_REDIRECT = 308;
/* 4XX client error  */
const short GloveHttpResponse::BAD_REQUEST = 400;
const short GloveHttpResponse::UNAUTHORIZED = 401;
const short GloveHttpResponse::PAYMENT_REQUIRED = 402;
const short GloveHttpResponse::FORBIDDEN = 403;
const short GloveHttpResponse::NOT_FOUND = 404;
const short GloveHttpResponse::BAD_METHOD = 405;
const short GloveHttpResponse::NOT_ACCEPTABLE = 406;
const short GloveHttpResponse::PROXY_AUTH_REQ = 407;
const short GloveHttpResponse::REQUEST_TIMEOUT = 408;
const short GloveHttpResponse::CONFLICT = 409;
const short GloveHttpResponse::GONE = 410;
const short GloveHttpResponse::LENGTH_REQUIRED = 411;
const short GloveHttpResponse::PRECOND_FAILED = 412;
const short GloveHttpResponse::REQUEST_TOO_LARGE = 413;
const short GloveHttpResponse::URI_TOO_LONG = 414;
const short GloveHttpResponse::UNSUPPORTED_MEDIA = 415;
const short GloveHttpResponse::RANGE_NOT_SATISF = 416;
const short GloveHttpResponse::EXPECTATION_FAILED = 417;
const short GloveHttpResponse::IM_A_TEAPOT = 418;
const short GloveHttpResponse::AUTH_TIMEOUT = 419; // Not standard
/* 420 (Method Failure - Spring Framework)
   Not part of the HTTP standard, but defined by Spring in the HttpStatus 
   class to be used when a method failed. This status code is deprecated 
   by Spring. */
/* 420 (Emhance Your Calm - Twitter)
   Not part of the HTTP standard, but returned by version 1 of the Twitter 
   Search and Trends API when the client is being rate limited.[16] Other 
   services may wish to implement the 429 Too Many Requests response code instead. */
/* 421 (Unused) */
const short GloveHttpResponse::UNPROC_ENTITY = 422;   // WebDAV
const short GloveHttpResponse::LOCKED = 423;	    // WebDAV
const short GloveHttpResponse::FAILED_DEPEND = 424;   // WebDAV
/* 425 (Unused) */
const short GloveHttpResponse::UPGRADE_REQUIRED = 426;
/* 427 (Unused) */
const short GloveHttpResponse::PRECOND_REQUIRED = 428;
const short GloveHttpResponse::TOO_MANY_REQUESTS = 429;
/* 430 (Unused) */
const short GloveHttpResponse::HEADER_TOO_LARGE = 431;
/* From 432 there are no used codes. 
   But some of them are used by certain servers (not as part of the standard) */
const short GloveHttpResponse::LOGIN_TIMEOUT = 440;     // Microsoft
const short GloveHttpResponse::NO_RESPONSE = 444;	      // Nginx
const short GloveHttpResponse::RETRY_WITH = 449;	      // Microsoft
const short GloveHttpResponse::BLOCKED_PARENTAL = 450;  // Microsoft
const short GloveHttpResponse::UNAVAILABLE_LEGAL = 451; // Draft: http://tools.ietf.org/html/draft-tbray-http-legally-restricted-status-04

/* 5XX server's fault */
const short GloveHttpResponse::INTERNAL_ERROR = 500;
const short GloveHttpResponse::NOT_IMPLEMENTED = 501;
const short GloveHttpResponse::BAD_GATEWAY = 502;
const short GloveHttpResponse::SERVICE_UNAVAIL = 503;
const short GloveHttpResponse::GATEWAY_TIMEOUT = 504;
const short GloveHttpResponse::VERSION_NOT_SUP = 505;
const short GloveHttpResponse::VAR_ALSO_NEGOT = 506;
const short GloveHttpResponse::INSUFF_STORAGE = 507; // WebDAV
const short GloveHttpResponse::LOOP_DETECTED = 508;  // WebDAV
const short GloveHttpResponse::BW_LIMIT_EXCEED = 509; // Apache extension
const short GloveHttpResponse::NOT_EXTENDED = 510;
const short GloveHttpResponse::NW_AUTH_REQ = 511;

const std::map <short, GloveHttpResponse::ResponseCode> GloveHttpResponse::responseCodes = 
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

const short GloveHttpErrors::ALL_OK = 0;
// file() could not read the file. 404 returned if addheaders=true
const short GloveHttpErrors::FILE_CANNOT_READ = 1;
const short GloveHttpErrors::BAD_HOST_NAME = 10;
const short GloveHttpErrors::BAD_ALIAS_NAME = 11;
const short GloveHttpErrors::CANT_FIND_HOST = 12;
const short GloveHttpErrors::HOST_ALREADY_FOUND = 13;
const short GloveHttpErrors::ERROR_SHORT_REQUEST = 20;
const short GloveHttpErrors::ERROR_NO_URI = 21;
const short GloveHttpErrors::ERROR_MALFORMED_REQUEST = 22;
const short GloveHttpErrors::ERROR_TIMED_OUT = 30;
const short GloveHttpErrors::ERROR_BAD_PROTOCOL = 45;


const short GloveHttpServer::RESPONSE_ERROR = 404;
const short GloveHttpServer::MESSAGE_NOTFOUND = 666;

std::string GloveHttpServer::_unknownMimeType = "application/octet-stream";
std::map<std::string, std::string> GloveHttpServer::_mimeTypes = {
  /* page parts */
  {"html", "text/html"},
  {"php", "text/html"},
  {"css", "text/css"},
  {"js", "text/javascript"},
  {"woff", "application/font-woff"},
  /* Images */
  {"jpg", "image/jpeg"}, 
  {"png", "image/png"}
};

const std::map<short, std::string> GloveHttpServer::_defaultMessages = {
  { MESSAGE_NOTFOUND, "The requested URL {:urlcut} was not found on this server" }
};

// Default vhost name (internal setting)
const std::string GloveHttpServer::defaultVhostName = "%";

namespace
{
  const std::string white_spaces( " \f\n\r\t\v" );

  std::string trim( std::string str, const std::string& trimChars = white_spaces )
  {
    std::string::size_type pos_end = str.find_last_not_of( trimChars );
    std::string::size_type pos_start = str.find_first_not_of( trimChars );

    return str.substr( pos_start, pos_end - pos_start + 1 );
  }

  // We could use regex but gcc 4.8 still hasn't implemented them.
  // gcc 4.9 finally can use regex, but I MUST do it compatible with 4.8
  std::string string_replace(std::string source, std::map<std::string,std::string>strMap, int offset=0, int times=0)
  {
    int total = 0;
    std::string::size_type pos=offset;
    std::string::size_type newPos;
    std::string::size_type lowerPos;

    do
      {
	std::string rep;
	for (auto i=strMap.begin(); i!=strMap.end(); ++i)
	  {
	    std::string fromStr = i->first;

	    newPos = source.find(fromStr, pos);
	    if ( (i==strMap.begin()) || (newPos<lowerPos) )
	      {
		rep = fromStr;
		lowerPos = newPos;
	      }
	  }

	pos = lowerPos;
	if (pos == std::string::npos)
	  break;

	std::string toStr = strMap[rep];

	source.replace(pos, rep.length(), toStr);
	pos+=toStr.size();

      } while ( (times==0) || (++total<times) );

    return source;
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

  // Gets file extension
  static std::string fileExtension(std::string fileName)
  {
    auto dotPos = fileName.find_last_of(".");
    if(dotPos != std::string::npos)
        return fileName.substr(dotPos+1);

    return "";
 }

  static std::string rfc1123date()
  {
    std::time_t t = time(NULL);
    std::tm tm;
    static const char *month_names[12] =
      {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
      };
    static const char *day_names[7] =
      {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
      };
    gmtime_r(&t, &tm);

    std::string s( 128, '\0' );
    s = std::string(day_names[tm.tm_wday])+", "+std::to_string(tm.tm_mday)+" "+
      std::string(month_names[tm.tm_mon])+" "+std::to_string(tm.tm_year)+" "+
      std::to_string(tm.tm_hour)+":"+std::to_string(tm.tm_min)+":"+
      std::to_string(tm.tm_sec)+" GMT";

    return s;
  }

  // Testing
  bool validHost(std::string hostName)
  {
    static const char* validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";
    return (hostName.find_first_not_of(validChars) == std::string::npos);
  }
};

GloveHttpRequest::GloveHttpRequest(GloveHttpServer* server, Glove::Client *c, int error, std::string method, std::string raw_location, std::string data, std::map<std::string, std::string> httpheaders, int serverPort):
  srv(server), c(c), error(error), raw_location(raw_location), method(method), data(data), headers(httpheaders)
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

std::string GloveHttpRequest::getVhost()
{
  auto headervhost = getHeader("Host");
  return srv->getVhostName(headervhost);
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

std::string GloveHttpRequest::getMessage(std::string _template)
{
  return string_replace(_template, 
			{
			  {"{:url}", location},
			  {"{:urlcut}", location.substr(0, 50) },
			    {"{:method}", method }
			});
  
}

GloveHttpResponse::GloveHttpResponse(std::string contentType):_contentType(contentType),_responseCode(GloveHttpResponse::OK)
{

}

GloveHttpResponse::~GloveHttpResponse()
{
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
      this->code(NOT_FOUND);
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

std::string GloveHttpResponse::responseMessage(short responseCode)
{
  auto _rc = responseCodes.find(responseCode);
  if (_rc!=responseCodes.end())
    return _rc->second.message;

  return "";
}

std::string GloveHttpResponse::getHeaderVary()
{
  return "Vary: Accept-Encoding" + std::string(Glove::CRLF);
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

  addResponseProcessor(name, GloveHttpResponse::NOT_FOUND, GloveHttpServer::response404Processor);
  // Errors 5XX
  addResponseGenericProcessor(name, GloveHttpResponse::INTERNAL_ERROR, GloveHttpServer::response5XXProcessor);
  // Errors 4XX
  addResponseGenericProcessor(name, GloveHttpResponse::BAD_REQUEST, GloveHttpServer::response4XXProcessor);

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

GloveHttpServer::GloveHttpServer(int listenPort, std::string bind_ip, const size_t buffer_size, const unsigned backlog_queue, int domain, unsigned max_accepted_clients, double timeout, double keepalive_timeout):port(listenPort)
{
  namespace ph = std::placeholders;

  _serverSignature = "Glove Http Server/" GHS_VERSION_STR " at {:serverHost} Port {:serverPort}";
  _simpleSignature = "Glove Http Server/" GHS_VERSION_STR;
  _defaultContentType = "text/html; charset=UTF-8";

  ghoptions.keepalive_timeout = keepalive_timeout;

  if (addVhost("%") != GloveHttpErrors::ALL_OK)
    return;

  // addResponseProcessor(GloveHttpResponse::NOT_FOUND, GloveHttpServer::response404Processor);
  // // Errors 5XX
  // addResponseGenericProcessor(GloveHttpResponse::INTERNAL_ERROR, GloveHttpServer::response5XXProcessor);
  // // Errors 4XX
  // addResponseGenericProcessor(GloveHttpResponse::BAD_REQUEST, GloveHttpServer::response4XXProcessor);

  // addAutoResponse(RESPONSE_ERROR, GloveHttpResponse::defaultResponseTemplate);
  // messages = _defaultMessages;

  initializeMetrics();

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

void GloveHttpServer::addRoute(std::string route, url_callback callback, std::string host, int maxArgs, std::vector<std::string> allowedMethods)
{
  auto vhost = getVHost(host);
  vhost->routes.push_back(GloveHttpUri(route, callback, maxArgs, allowedMethods));
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
      auto vhost = getVHost(request.getVhost());
      if (error)
	{
	  switch (error)
	    {
	    case GloveHttpErrors::ERROR_SHORT_REQUEST:
	    case GloveHttpErrors::ERROR_NO_URI:
	      response<<GloveHttpResponse::setCode(GloveHttpResponse::BAD_REQUEST);
	      break;
	    case GloveHttpErrors::ERROR_BAD_PROTOCOL:
	      response<<GloveHttpResponse::setCode(GloveHttpResponse::VERSION_NOT_SUP);
	      break;
	    default:
	      response<<GloveHttpResponse::setCode(GloveHttpResponse::INTERNAL_ERROR);
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
	      response<<GloveHttpResponse::setCode(GloveHttpResponse::NOT_FOUND);
	      // Test for error responses...
	    }
	}
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

  std::cout << "Request: "<<queryTime<<"s. T:"<<metrics.totalQueryTime<<"."<<std::endl;
  std::cout << "Processing: "<<processingTime<<"s. T:"<<metrics.totalProcessingTime<<"."<<std::endl;
  std::cout << "Answer: "<<responseTime<<"s. T:"<<metrics.totalResponseTime<<"."<<std::endl;
}
