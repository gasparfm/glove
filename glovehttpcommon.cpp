#include "glovehttpcommon.hpp"
#include "utils.hpp"

#define AddGloveHttpResponse(response, text, description)	\
  {response, {text, description} }

const short GloveHttpResponseCode::CONTINUE = 100;
const short GloveHttpResponseCode::SWITCH_PROTOCOLS = 101;
const short GloveHttpResponseCode::PROCESSING = 102;      // WebDAV
/* 2XX success */
const short GloveHttpResponseCode::OK = 200;
const short GloveHttpResponseCode::CREATED = 201;
const short GloveHttpResponseCode::ACCEPTED = 202;
const short GloveHttpResponseCode::NON_AUTHORITATIVE = 203; 
const short GloveHttpResponseCode::NO_CONTENT = 204;
const short GloveHttpResponseCode::RESET_CONTENT = 205;
const short GloveHttpResponseCode::PARTIAL_CONTENT = 206;
const short GloveHttpResponseCode::MULTI_STATUS = 207;     // WebDAV
const short GloveHttpResponseCode::ALREADY_REPORTED = 208; // WebDAV
const short GloveHttpResponseCode::IM_USED = 209;
/* 3XX redirection */
const short GloveHttpResponseCode::MULTIPLE_CHOICES = 300;
const short GloveHttpResponseCode::MOVED_PERMANENTLY = 301;
const short GloveHttpResponseCode::FOUND = 302;
const short GloveHttpResponseCode::SEE_OTHER = 303;
const short GloveHttpResponseCode::NOT_MODIFIED = 304;
const short GloveHttpResponseCode::USE_PROXY = 305;
const short GloveHttpResponseCode::SWITCH_PROXY = 306;
const short GloveHttpResponseCode::TEMPORARY_REDIRECT = 307;
const short GloveHttpResponseCode::PERMANENT_REDIRECT = 308;
/* 4XX client error  */
const short GloveHttpResponseCode::BAD_REQUEST = 400;
const short GloveHttpResponseCode::UNAUTHORIZED = 401;
const short GloveHttpResponseCode::PAYMENT_REQUIRED = 402;
const short GloveHttpResponseCode::FORBIDDEN = 403;
const short GloveHttpResponseCode::NOT_FOUND = 404;
const short GloveHttpResponseCode::BAD_METHOD = 405;
const short GloveHttpResponseCode::NOT_ACCEPTABLE = 406;
const short GloveHttpResponseCode::PROXY_AUTH_REQ = 407;
const short GloveHttpResponseCode::REQUEST_TIMEOUT = 408;
const short GloveHttpResponseCode::CONFLICT = 409;
const short GloveHttpResponseCode::GONE = 410;
const short GloveHttpResponseCode::LENGTH_REQUIRED = 411;
const short GloveHttpResponseCode::PRECOND_FAILED = 412;
const short GloveHttpResponseCode::REQUEST_TOO_LARGE = 413;
const short GloveHttpResponseCode::URI_TOO_LONG = 414;
const short GloveHttpResponseCode::UNSUPPORTED_MEDIA = 415;
const short GloveHttpResponseCode::RANGE_NOT_SATISF = 416;
const short GloveHttpResponseCode::EXPECTATION_FAILED = 417;
const short GloveHttpResponseCode::IM_A_TEAPOT = 418;
const short GloveHttpResponseCode::AUTH_TIMEOUT = 419; // Not standard
/* 420 (Method Failure - Spring Framework)
   Not part of the HTTP standard, but defined by Spring in the HttpStatus 
   class to be used when a method failed. This status code is deprecated 
   by Spring. */
/* 420 (Emhance Your Calm - Twitter)
   Not part of the HTTP standard, but returned by version 1 of the Twitter 
   Search and Trends API when the client is being rate limited.[16] Other 
   services may wish to implement the 429 Too Many Requests response code instead. */
/* 421 (Unused) */
const short GloveHttpResponseCode::UNPROC_ENTITY = 422;   // WebDAV
const short GloveHttpResponseCode::LOCKED = 423;	    // WebDAV
const short GloveHttpResponseCode::FAILED_DEPEND = 424;   // WebDAV
/* 425 (Unused) */
const short GloveHttpResponseCode::UPGRADE_REQUIRED = 426;
/* 427 (Unused) */
const short GloveHttpResponseCode::PRECOND_REQUIRED = 428;
const short GloveHttpResponseCode::TOO_MANY_REQUESTS = 429;
/* 430 (Unused) */
const short GloveHttpResponseCode::HEADER_TOO_LARGE = 431;
/* From 432 there are no used codes. 
   But some of them are used by certain servers (not as part of the standard) */
const short GloveHttpResponseCode::LOGIN_TIMEOUT = 440;     // Microsoft
const short GloveHttpResponseCode::NO_RESPONSE = 444;	      // Nginx
const short GloveHttpResponseCode::RETRY_WITH = 449;	      // Microsoft
const short GloveHttpResponseCode::BLOCKED_PARENTAL = 450;  // Microsoft
const short GloveHttpResponseCode::UNAVAILABLE_LEGAL = 451; // Draft: http://tools.ietf.org/html/draft-tbray-http-legally-restricted-status-04

/* 5XX server's fault */
const short GloveHttpResponseCode::INTERNAL_ERROR = 500;
const short GloveHttpResponseCode::NOT_IMPLEMENTED = 501;
const short GloveHttpResponseCode::BAD_GATEWAY = 502;
const short GloveHttpResponseCode::SERVICE_UNAVAIL = 503;
const short GloveHttpResponseCode::GATEWAY_TIMEOUT = 504;
const short GloveHttpResponseCode::VERSION_NOT_SUP = 505;
const short GloveHttpResponseCode::VAR_ALSO_NEGOT = 506;
const short GloveHttpResponseCode::INSUFF_STORAGE = 507; // WebDAV
const short GloveHttpResponseCode::LOOP_DETECTED = 508;  // WebDAV
const short GloveHttpResponseCode::BW_LIMIT_EXCEED = 509; // Apache extension
const short GloveHttpResponseCode::NOT_EXTENDED = 510;
const short GloveHttpResponseCode::NW_AUTH_REQ = 511;

const std::map <short, GloveHttpResponseCode::ResponseCode> GloveHttpResponseCode::responseCodes = 
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

#undef AddGloveHttpResponse

std::string GloveHttpResponseCode::responseMessage(short responseCode)
{
	  auto _rc = responseCodes.find(responseCode);
  if (_rc!=responseCodes.end())
    return _rc->second.message;

  return "";
}

void GloveHttpCommon::extract_headers( std::string input, std::map<std::string, std::string> &headers, int start)
{
	std::string::size_type colon;
	std::string::size_type crlf;

	if ( ( colon = input.find(':', start) ) != std::string::npos && 
			 ( ( crlf = input.find(GloveDef::CRLF, start) ) != std::string::npos ) )
		{
			if (crlf<colon)
				{
					/* Not a header!! */
				}
			else
				headers.insert( std::pair<std::string, std::string>( trim( input.substr(start, colon - start) ),
																														 trim( input.substr(colon+1, crlf - colon -1 ) ) )
				);

			extract_headers(input, headers, crlf+2);
		}
}
