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
*  20170403 : Directive ENABLE_WEBSOCKETS to compile with or without
*             Websockets support
*  20170403 : Helper methods auth(), checkPassword(), getAuthUser() for client
*             callbacks
*  20170401 : Digest Authentication Method
*  20170330 : Basic Authentication Method
*  20170327 : Response::clear adds clearHeaders argument. Default to true
*  20170112 : std::cout removed
*  20161004 : Minor connection bugs fixed
*  20161003 : Fixed bug. Error 500 when compression not enabled.
*           : HTTPS server
*  20161001 : Basic WebSockets support with. server.addWebSocket adds
*           : web socket route.
*  20160929 : fixed bug when clearing output
*           : ability to change headers from response object
*           : added compression support with zlib
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
#include <memory>
#include <chrono>

#if ENABLE_COMPRESSION
#include "glovecompress.hpp"
#endif

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
	{"js", "text/js" },
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

namespace
{
	/* Digest password repository */
	GloveSessionRepository digestAuthInfo;
};

GloveHttpRequest::GloveHttpRequest(GloveHttpServer* server, Glove::Client *c, int error, std::string method, std::string raw_location, std::string data, std::map<std::string, std::string> httpheaders, int serverPort):
  srv(server), c(c), error(error), raw_location(raw_location), method(method), data(data), headers(httpheaders)
{
  /* location = Glove::urldecode(raw_location); */
  // More services soon !!
  std::string service = "http://";

  std::string thishost = headers["Host"];
  if (thishost.empty())
    thishost = c->get_address(true)+":"+std::to_string(serverPort);

  std::string auth = getAuthData(raw_location);
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

std::vector<std::pair<std::string, std::string> > GloveHttpRequest::getDataCol() const
{
  std::vector<std::pair<std::string, std::string> > res;
  if (contentType=="application/x-www-form-urlencoded")
    {
			for (auto elem : urlencoded_data)
				{
					res.push_back(elem);
				}
		}
	
	return res;
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

std::string& GloveHttpRequest::getData() const
{
  return const_cast<std::string&> (data);
}

std::map<std::string, std::string>& GloveHttpRequest::getHeaders() const
{
  return const_cast<std::map<std::string, std::string>&> (headers);
}

std::string GloveHttpRequest::getHeader(std::string h) const
{
  auto el = headers.find(h);
  if ( el != headers.end())
    return el->second;

  return "";
}

bool GloveHttpRequest::connectionIs(std::string what)
{
	if (connectionHeader.size()==0) {
		connectionHeader = tokenize(headers["Connection"], ",", defaultTrim);
	}
	for (auto c: connectionHeader)
		{
			if (c == what)
				return true;
		}
	return false;
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

std::string GloveHttpRequest::getAuthData(const std::string& raw_location)
{
  auto auth = headers.find("Authorization");
  if (auth == headers.end())
    return "";

	auto space = auth->second.find(' ');
	if (space == std::string::npos)
		return "";
  authType = auth->second.substr(0, space);
	auto authData = auth->second.substr(space+1);
  if (authType=="Basic")
    {
      return GloveCoding::base64_decode(authData);
    }
	else if (authType=="Digest")
		{
			auto _digestData = tokenize(authData, ",", defaultTrim);
			auto digestData = mapize(_digestData, "=", defaultTrim);

			std::string address= c->get_address(true);
			std::string username;
			/* Must strip arguments */
			std::string path = raw_location;
			auto ok = checkDigestAuth(address, path, digestData, username);
			if (ok)
				{
					authData=GloveCoding::base64_encode((const unsigned char*)authData.c_str(), authData.length());

					return username+":"+authData;
				}
			else
				return "", authType="None";
		}
  else				// Not implemented
		{
			authType = "None";
			return "";
		}
}

bool GloveHttpRequest::checkDigestAuth(std::string& address, std::string& path, std::map<std::string, std::string>& data, std::string& username)
{
	auto nonce = unquote(data["nonce"], "\"", "\\");
	auto response = unquote(data["response"], "\"", "\\");
	auto algo = unquote(data["algorithm"], "\"", "\\");
	auto cnonce = unquote(data["cnonce"], "\"", "\\");
	auto nc = unquote(data["nc"], "\"", "\\");
	auto opaque = unquote(data["opaque"], "\"", "\\");
	auto realm = unquote(data["realm"], "\"", "\\");
	auto uri=  unquote(data["uri"], "\"", "\\");
	auto _username = unquote(data["username"], "\"", "\\");
	
	if (uri != path) {
		std::cout<<"PATH MALO: "<<uri<<" *" <<path<<"*\n";
		return false;								/* Path does not match */
	}
	if (algo.empty())
		algo="MD5";
	if ( (algo != "MD5") && (algo!="MD5-sess") ) {
		return false;								/* Wrong algorithm */
	}
	std::string address2;
	if (digestAuthInfo.pop(nonce+opaque+uri, address2))
		{
			return false;							/* Auth info not found */
		}
	username = _username;
	return true;
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

bool GloveHttpRequest::auth(GloveHttpResponse& response, std::function<int(GloveHttpRequest&, GloveHttpResponse&)> authFunc, const std::string& authTypes, const std::string& realm)
{
	auto _authTypes = tokenize(authTypes, ",", defaultTrim);

	if (std::find(_authTypes.begin(), _authTypes.end(), authType) != _authTypes.end())
		{
			if (authFunc(*this, response))
				return true;
			/* Check auth */
		}

		{
			std::string extraArguments;
			response.code(GloveHttpResponseCode::UNAUTHORIZED);
			if (_authTypes[0] == "Digest")
				{
					/* SEGUIR POR AQUI */
					std::string nonce = GloveCoding::randomHex(64, true);
					std::string opaque= GloveCoding::randomHex(64, true);
					std::string address= c->get_address(true);
					std::string info = uri.rawpath;
					/* digestAuthInfo.maxEntries(4); */
					/* digestAuthInfo.defaultTimeout(10); */
					digestAuthInfo.insert(nonce+opaque+address, info);
					/* digestAuthInfo.debug(); */
					
					extraArguments+=", nonce="+quote(nonce, "\"", "\\")+", qop="+quote("auth,auth-int", "\"", "\\")+", algorithm=MD5, opaque="+quote(opaque, "\"", "\\")+", domain=\"/private/ http://mirror.my.dom/private2/\"";
				}
			response.header("WWW-Authenticate", _authTypes[0]+" realm="+quote(realm, "\"", "\\")+extraArguments);

			return false;
		}
}

std::string GloveHttpRequest::getAuthType() const
{
	return authType;
}

std::string GloveHttpRequest::getAuthUser() const
{
	if (authType == "None")
		return "";

	return uri.username;
}

bool GloveHttpRequest::checkPassword(const std::string& password)
{
	if (authType == "Basic")
		return checkPasswordBasicAuth(password);
	else if (authType == "Digest")
		return checkPasswordDigestAuth(password);

	return false;
}

bool GloveHttpRequest::checkPasswordBasicAuth(const std::string& password)
{
	return ( (uri.password.length()>0) && (password== uri.password) );
}

bool GloveHttpRequest::checkPasswordDigestAuth(const std::string& password)
{
	if (uri.password.empty())
		return false;

	auto authData = GloveCoding::base64_decode(uri.password);
	auto _digestData = tokenize(authData, ",", defaultTrim);
	auto digestData = mapize(_digestData, "=", defaultTrim);

	auto nonce = unquote(digestData["nonce"], "\"", "\\");
	auto response = unquote(digestData["response"], "\"", "\\");
	auto algo = unquote(digestData["algorithm"], "\"", "\\");
	auto cnonce = unquote(digestData["cnonce"], "\"", "\\");
	auto nc = unquote(digestData["nc"], "\"", "\\");
	auto realm = unquote(digestData["realm"], "\"", "\\");
	auto uri=  unquote(digestData["uri"], "\"", "\\");
	auto qop=  unquote(digestData["qop"], "\"", "\\");
	auto method = getMethod();

	std::string HA1,HA2, resp;

	if (algo == "MD5")
		HA1= GloveCoding::md5_hex(this->uri.username+":"+realm+":"+password);
	else if (algo == "MD5-sess")
		HA1= GloveCoding::md5_hex(GloveCoding::md5_hex(this->uri.username+":"+realm+":"+password)+":"+nonce+":"+cnonce);
	else
		return false;								/* Bad algorithm. We will never do that because of checkDigestAuth restriction, */

	if (qop==  "auth-int")
		HA2 = GloveCoding::md5_hex(method+":"+uri+":"+GloveCoding::md5_hex(getData()));
	else
		HA2 = GloveCoding::md5_hex(method+":"+uri);

	if ( (qop == "auth") || (qop == "auth-int") )
		resp = GloveCoding::md5_hex(HA1+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+HA2);
  else if (qop.empty())
		resp = GloveCoding::md5_hex(HA1+":"+nonce+":"+HA2);
	else
		return false;
	
	return (response == resp);
}

GloveSessionRepository::GloveSessionRepository()
{
	_defaultTimeout = DEFAULT_SESSION_TIMEOUT;
	_maxEntries = DEFAULT_SESSION_ENTRIES;
}

GloveSessionRepository::~GloveSessionRepository()
{
}

void GloveSessionRepository::clearTimeouts()
{
	time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	for (auto entry=storage.begin(); entry != storage.end(); )
		{
			if (entry->second.creation + entry->second.timeout < now)
				entry = storage.erase(entry);
			else
				++entry;
		}
}

void GloveSessionRepository::clearOldEntries(uint64_t howmany)
{
	uint64_t deleted = 0;
	std::vector<std::map<std::string, GloveSessionRepository::sessionInfo_t>::iterator> toDelete;
	
	auto doInsert = [&](const std::map<std::string, GloveSessionRepository::sessionInfo_t>::iterator& entry)
		{
			bool inserted = false;
			for (auto ent = toDelete.begin(); ent != toDelete.end(); ++ent)
				{
					if (entry->second.creation < (*ent)->second.creation)
						{
							toDelete.insert(ent, entry);
							inserted = true;
							break;
						}
				}
			if ( (!inserted) && (toDelete.size()<howmany) )
				{
					toDelete.push_back(entry);
				}
			else if (toDelete.size()>howmany)
				{
					for (auto i=toDelete.begin()+howmany-1; i != toDelete.end(); ++i)
						toDelete.erase(i);
				}
		};
	auto tryInsert = [toDelete,howmany,doInsert](const std::map<std::string, GloveSessionRepository::sessionInfo_t>::iterator& entry)
		{
			auto currentSize = toDelete.size();
			if ( (currentSize<howmany) || (entry->second.creation < (*toDelete.rbegin())->second.creation))
				doInsert(entry);

		};
	
	for (auto entry=storage.begin(); entry != storage.end(); ++entry)
		{
			tryInsert(entry);
		}
	for (auto entry=toDelete.begin(); entry != toDelete.end(); ++entry)
		storage.erase(*entry);
}

void GloveSessionRepository::insert(const std::string key, const std::string& value, time_t timeout)
{
	if (timeout==0)
		timeout = _defaultTimeout;

	time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	if (storage.size()>=_maxEntries)
		clearTimeouts();

	if (storage.size()>=_maxEntries)
		clearOldEntries(_maxEntries-storage.size()+1);
	
	storage[key] = { now, timeout, value };
}

bool GloveSessionRepository::remove(const std::string& key)
{
	auto el = storage.find(key);
	if (el == storage.end())
		return false;

	storage.erase(el);
}

bool GloveSessionRepository::get(const std::string& key, std::string& value)
{
	auto el = storage.find(key);
	if (el == storage.end())
		return false;

	value = el->second.data;
	return true;
}

bool GloveSessionRepository::pop(const std::string& key, std::string& value)
{
	auto el = storage.find(key);
	if (el == storage.end())
		return false;

	value = el->second.data;
	storage.erase(el);
	return true;
	
}

uint64_t GloveSessionRepository::maxEntries(uint64_t val)
{
	_maxEntries = val;
	return _maxEntries;
}

uint64_t GloveSessionRepository::maxEntries()
{
	return _maxEntries;
}

time_t GloveSessionRepository::defaultTimeout(time_t val)
{
	_defaultTimeout = val;
	return _defaultTimeout;
}

time_t GloveSessionRepository::defaultTimeout()
{
	return _defaultTimeout;
}

void GloveSessionRepository::debug()
{
	for (auto info : storage)
		{
			std::cout << " --NAME: "<<info.first<<"; CREATED="<<info.second.creation<<"; TIMEOUT="<<info.second.timeout<<";\n";
			std::cout << "   DATA : "<<info.second.data<<"\n\n";
		}
}

GloveHttpResponse::GloveHttpResponse(std::string contentType):_contentType(contentType),_responseCode(GloveHttpResponseCode::OK),compression(true)
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

std::string GloveHttpResponse::header(std::string name)
{
	auto header = headers.find("name");
	return (header != headers.end())?header->second:"";
}

std::string GloveHttpResponse::header(std::string name, std::string value)
{
	headers[name] = value;
	return value;
}

bool GloveHttpResponse::hasHeader(std::string name)
{
	auto header = headers.find("name");
	return (header != headers.end());
}

int GloveHttpResponse::applyCompression(GloveHttpRequest &request, std::vector<std::string>& compression)
{
	std::string compressionMethod;

	if ( (!ENABLE_COMPRESSION) || (!this->compression) || (output.tellp()<100) || (!compressionPossible(request.getHeaders(), compressionMethod)) )
		return 0;
  #if ENABLE_COMPRESSION
	std::string out;
	auto chosenMethod = GloveCompress::getCompressionMethod(compressionMethod, compression);
	if (chosenMethod == -1)
		return 0;
	if (GloveCompress::dodeflate(output.str(), out,
															 chosenMethod,
																						 Z_BEST_COMPRESSION)<0)
		{
			return -1;
		}

	output.clear();
	output.str("");
	output << out;
	header("Content-Encoding", GloveCompress::getCompressionMethodName(chosenMethod));
	return 1;
	#endif
}

void GloveHttpResponse::send(GloveHttpRequest &request, Glove::Client &client)
{
  std::string outputStr = output.str();
  client << "HTTP/1.1 "<<std::to_string(code())<<" "<<responseMessage()<<GloveDef::CRLF;
  client << "Date: "<<rfc1123date()<<GloveDef::CRLF;

  // Server Signature
  std::string serverSig = request.server()->simpleSignature();
  if (!serverSig.empty())
    client << "Server: "<<serverSig<<GloveDef::CRLF;

	for (auto h: headers)
		{
			client << h.first <<": "<< h.second << GloveDef::CRLF;
		}
  client << getHeaderVary();
  client << "Content-Length: "<<outputStr.size()<<GloveDef::CRLF;
  client << "Content-Type: "<<_contentType<<GloveDef::CRLF;
  client << GloveDef::CRLF;
  client << outputStr;
}

std::string GloveHttpResponse::getFinalOutput(std::vector<std::string>& compression, std::map<std::string, std::string>& headers)
{
}

bool GloveHttpResponse::compressionPossible(std::map<std::string, std::string>& headers, std::string& compressionMethod)
{
	auto accept = std::find_if(headers.begin(), headers.end(), lowerCaseCompare("accept-encoding"));
	if (accept == headers.end())
		return false;
	compressionMethod = accept->second;
		
	return true;
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

void GloveHttpResponse::clear(bool clearHeaders)
{
	if (clearHeaders)
		headers.clear();
  output.clear();								/* Clears error flags */
	output.str("");
}

std::string GloveHttpResponse::getHeaderVary()
{
  return "Vary: Accept-Encoding" + std::string(GloveDef::CRLF);
}

namespace
{
	GloveUriHttpService gloveUriHttpService;
};

GloveHttpUri::GloveHttpUri(std::string route, _url_callback ucb, int maxArgs, int minArgs, std::vector<std::string> methods, bool partialMatch, GloveUriService& mission):
  route(route),
  callback(ucb),
  maxArgs(maxArgs), 
  allowedMethods(methods),
  partialMatch(partialMatch),
	_mission(mission)
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

GloveHttpUri::GloveHttpUri(std::string route, _url_callback ucb, int maxArgs, int minArgs, std::vector<std::string> methods, bool partialMatch):GloveHttpUri(route, ucb, maxArgs, minArgs, methods, partialMatch, gloveUriHttpService)
{
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
	/* Each 5ms it will process messages */
	wsInterval=5;
	/* Each 100 intervals will call maintenance function */
	wsMaintenanceInterval = 100;

	/* Web Socket messages will be 32768 octets long */
	wsFragmentation = 32768;
	
  if (addVhost("%") != GloveHttpErrors::ALL_OK)
    return;			/* Exception here? */
	/* std::cout << "Initialized\n"; */
  initializeMetrics();
}

GloveHttpServer::GloveHttpServer()
{
  baseInitialization();
}

void GloveHttpServer::listen(int listenPort, std::string bind_ip, const size_t buffer_size, const unsigned backlog_queue, int domain, unsigned max_accepted_clients, double timeout, double keepalive_timeout, int secure, std::string certchain, std::string certkey)
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

  server = new Glove();
	server->server_error_callback(std::bind(&GloveHttpServer::gloveError, this, ph::_1, ph::_2, ph::_3));
	server->buffer_size(buffer_size);
	server->listen(listenPort, 
								std::bind(&GloveHttpServer::clientConnection, this, ph::_1),
								bind_ip,
								backlog_queue,
								domain,
								secure,
								certchain,
								certkey);
  server->max_accepted_clients(max_accepted_clients);
  server->timeout(timeout);
}

GloveHttpServer::GloveHttpServer(int listenPort, std::string bind_ip, const size_t buffer_size, const unsigned backlog_queue, int domain, unsigned max_accepted_clients, double timeout, double keepalive_timeout, int secure, std::string certchain, std::string certkey)
{
  baseInitialization();
  listen(listenPort, bind_ip, buffer_size, backlog_queue, domain, max_accepted_clients, timeout, keepalive_timeout, secure, certchain, certkey);
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

#if ENABLE_WEBSOCKETS
void GloveHttpServer::addWebSocket(std::string route, url_callback callback, ws_accept_callback acceptCallback, ws_receive_callback receiveCallback, ws_maintenance_callback maintenanceCallback, ws_maintenance_callback closeCallback, std::string host, int maxArgs, int minArgs, bool partialMatch, url_callback normalhttp)
{
  auto vhost = getVHost(host);

	/* Any smarter way to do this?
		   - GloveUriService is an abstract class.
	     - GloveHttpUri must receive a reference to an object derived from GloveUrihttpservice
			 - I created this static vector just to store all Services in a vector, but it's
			   like a lost pointer... Memory won't be freed... well when the server is destroyed.
				 Very few bytes and must be stored while
				 the service is running, feel a bit uncomfortable with this.
	*/
	static std::vector<std::shared_ptr<GloveUriWebSocketService>> references;
	auto service = std::make_shared<GloveUriWebSocketService>(GloveUriWebSocketService(acceptCallback, receiveCallback, maintenanceCallback, closeCallback, wsInterval, wsMaintenanceInterval, wsFragmentation));
	references.push_back(service);
  vhost->routes.push_back(GloveHttpUri(route, callback, maxArgs, minArgs, { "GET" }, partialMatch, *service));
}

void GloveHttpServer::addWebSocket(std::string route, url_callback callback, int maxArgs, ws_accept_callback acceptCallback, ws_receive_callback receiveCallback, ws_maintenance_callback maintenanceCallback, ws_maintenance_callback closeCallback, int minArgs, bool partialMatch, url_callback normalhttp)
{
	addWebSocket(route, callback, acceptCallback, receiveCallback, maintenanceCallback, closeCallback, defaultVhostName, maxArgs, minArgs, partialMatch, normalhttp);
}
#endif

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
					if ( (first_crlf = input.find(GloveDef::CRLF) ) == std::string::npos)
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
	//  std::cout << "IP: "<<client.get_address(true)<<std::endl;

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
			//      std::cout << "Request: "<<raw_location<<std::endl;
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
							#if ENABLE_WEBSOCKETS
							if ((guri->mission().name()=="websocket") && (webSocketHandshake(client, request)) )
								return doWebSockets(client, guri, request, response);
							#endif
							guri->callAction(request, response);
						}
					else
						{
							response<<GloveHttpResponse::setCode(GloveHttpResponseCode::NOT_FOUND);
							// Test for error responses...
						}
				}
			applyProcessors(vhost, request, response, response.code());
      // request chrono, processing chrono..
      auto processingTime = std::chrono::steady_clock::now();
			if (response.applyCompression(request, ghoptions.compression)<0)
				{
					response << GloveHttpResponse::setCode(GloveHttpResponseCode::INTERNAL_ERROR);
					applyProcessors(vhost, request, response, response.code());
				}

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

#if ENABLE_WEBSOCKETS
bool GloveHttpServer::webSocketHandshake(Glove::Client& client, GloveHttpRequest& req)
{
	/* Header "Connection: Upgrade"
	   Header "Upgrade: websocket" */
	//	std::cout << "Handshake: "<<(req.connectionIs("Upgrade"))<<", "<<req.getHeader("Upgrade")<<std::endl;

	if ( (req.connectionIs("Upgrade")) && (req.getHeader("Upgrade") != "websocket") )
		return false;

	if (req.getHeader("Sec-WebSocket-Version")=="13")
			return webSocket13Handshake(client, req);

	return false;
}

bool GloveHttpServer::webSocket13Handshake(Glove::Client& client, GloveHttpRequest& req)
{
	/* Magic number for websocket handshake */
	static std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	auto key = req.getHeader("Sec-WebSocket-Key");
	if (key.empty())
		return false;
	auto acceptHash = GloveCoding::sha1_b64(key+magic);
	/* Switching protocols */
	client << "HTTP/1.1 101 Web Socket Protocol Handshake"<<GloveDef::CRLF;
	client << "access-control-allow-credentials: true"<<GloveDef::CRLF;
	client << "Access-Control-Allow-Headers: x-websocket-version"<< GloveDef::CRLF;
	client << "Access-Control-Allow-Origin: null"<< GloveDef::CRLF;
	client << "Connection: Upgrade" << GloveDef::CRLF;
	client << "Date: "<<rfc1123date()<<GloveDef::CRLF;

  std::string serverSig = req.server()->simpleSignature();
  if (!serverSig.empty())
    client << "Server: "<<serverSig<<GloveDef::CRLF;
	client << "Sec-WebSocket-Accept: "<<acceptHash<<GloveDef::CRLF;
	client << "Upgrade: websocket" << GloveDef::CRLF;
	client <<GloveDef::CRLF;

	return true;
}

int GloveHttpServer::doWebSockets(Glove::Client& client, GloveHttpUri* guri, GloveHttpRequest& request, GloveHttpResponse& response)
{
	auto ws = dynamic_cast<GloveUriWebSocketService&>(guri->mission());
	auto handler = GloveWebSocketHandler(client, ws.fragmentation());
	auto wsdata = GloveWebSocketData();

	bool finish = false;
	double interval = (double)ws.interval()/1000;
	uint64_t intervalCount=0;
	ws.accept(request, handler);
	while (!finish)
		{
			std::string incoming;
			auto error = client.receive2(incoming, interval, 0);
			if (error == 0)
				{
					auto frame = GloveWebSocketFrame(incoming);

					/* Control frames MUST have <=125bytes payload
					   Control data IS NOT fragmented */
					if (frame.error())
						{
							handler.close(1, "Unexpected error");
							finish = true;
						}
					if (frame.opcode()==GloveWebSocketFrame::TYPE_PING)
						handler.pong(frame);
					else if (frame.opcode()==GloveWebSocketFrame::TYPE_CLOSE)
						{
							handler.close(frame);
							finish = true;		/* Received a close! */
						}
					else if (frame.opcode()==GloveWebSocketFrame::TYPE_PONG)
						handler.pong();
					else
						{
							wsdata.update(frame);
							ws.receive(wsdata, handler);							
						}

					/* We have data */
				}
			else if (error == 8 || error == 40 || error == 9)
				{
					std::cout << "Connection error" << std::endl;
					finish = true;
					/* Connection errors */
				}
			else if (error == 21)
				{
					finish = true;
					std::cout << "SHUTDOWN!!!!"<<std::endl;
					/* Peer shutdown */
				}
			/* else if (error == 7) // timeout
			 {
			  // Carry on my wayward son...
				// No need to exit or do anything
			}*/
			if ((!finish) && (++intervalCount % ws.intervalsMaintenance()==0) )
				{
					intervalCount=0;
					finish = ws.maintenance(handler);
				}
		}
	ws.close(handler);
	return 0;
}
#endif

void GloveHttpServer::applyProcessors(VirtualHost* vhost, GloveHttpRequest& request, GloveHttpResponse& response, int code)
{
	if (response.disableProcessor())
		return;
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

void GloveHttpServer::tmcReject(bool enabled)
{
	this->server->reject_connections(enabled);
	if (enabled)
		{
			this->server->wait_before_reject_connection(5); /* default value */
			this->server->tmcRejectMessage("Too many connections!");
		}
}

void GloveHttpServer::tmcReject(bool enabled, double time, std::string message)
{
	this->server->reject_connections(enabled);
	this->server->wait_before_reject_connection(time);
	this->server->tmcRejectMessage(message);
}

void GloveHttpServer::tmcReject(double time, std::string message)
{
	tmcReject(true, time, message);
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

void GloveHttpServer::fileServerFixed(GloveHttpRequest &request, GloveHttpResponse& response, std::string path)
{
	if (response.file(path) != GloveHttpErrors::ALL_OK)
		{
			response.code(404);
		}
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
  response.clear(false);
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
  response.clear(false);
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
