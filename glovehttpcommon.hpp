#pragma once

#include <map>
#include <string>

class GloveHttpResponseCode
{
public:
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

	static std::string responseMessage(short responseCode);
private:
	struct ResponseCode
  {
    std::string message;
    std::string description;
  };
  static const std::map<short, ResponseCode> responseCodes;

};

/** Glove Http Errors  */
class GloveHttpErrors
{
 public:
  /** No error  */
  static const short ALL_OK = 0;

  /* Response errors GloveHttpResponse */
  /* action error codes */
  /**
     Cannot read file. Caused by GloveHttpResponse
		 file() could not read the file. 404 returned if addheaders=true
   */
  static const short FILE_CANNOT_READ = 1;

  /* Vhost errors */

  /** The specified host is not valid. Not for clients. */
  static const short BAD_HOST_NAME = 10;
  /** When you try to create a new alias */
  static const short BAD_ALIAS_NAME = 11;
  /** When you try to retrieve host information */
  static const short CANT_FIND_HOST = 12;
  /** When you try to create an existing vhost */
  static const short HOST_ALREADY_FOUND = 13;

  /* Url retrieving errors GloveHttpServer */
  /** Request line is too short to have needed information */
  static const short ERROR_SHORT_REQUEST = 20;
  /** Request has not URI: There's no space after the METHOD */
  static const short ERROR_NO_URI = 21;
  /** Malformed request string */
  static const short ERROR_MALFORMED_REQUEST = 22;
  /** Timeout when receiving data from client */
  static const short ERROR_TIMED_OUT = 30;
  /** Server request is not a valid HTTP/1.1 request */
  static const short ERROR_BAD_PROTOCOL = 45;
};

class GloveHttpCommon
{
protected:
  void extract_headers( std::string input, std::map<std::string, std::string> &headers, int start);
	
};
