/* @(#)glovehttpclient.hpp
 */

#ifndef _GLOVEHTTPCLIENT_H
#define _GLOVEHTTPCLIENT_H 1

#include "glove.hpp"
#include "utils.hpp"
#include "gloveexception.hpp"
#include "glovehttpcommon.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <iostream>
#include <functional>
#include <mutex>

/** Glove Http Client Version (numeric)  */
#define GHC_VERSION 0001000
/** Glove Http Client Version (string)  */
#define GHC_VERSION_STR "0.1.0"

#define GLOVEHTTPCLIENT_DEFAULT_USERAGENT "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/45.0.2454.101 Chrome/45.0.2454.101 Safari/537.36"
#define GLOVEHTTPCLIENT_DEFAULT_CHECKCERTS true
#define GLOVEHTTPCLIENT_DEFAULT_MAXREDIRECTS 10
#define GLOVEHTTPCLIENT_DEFAULT_FOLLOWREDIRECTS true
#define GLOVEHTTPCLIENT_DEFAULT_TIMEOUT 5

class GloveHttpClientResponse
{
public:
	GloveHttpClientResponse()
	{
	}
  GloveHttpClientResponse(int statusCode,
													std::string& htmlOutput,
													std::map<std::string, std::string>& headers,
													std::vector<std::string> redirections,
													std::chrono::milliseconds firstByte,
													std::chrono::milliseconds allData): _statusCode(statusCode),
		_htmlOutput(htmlOutput),
		_headers(headers),
		_redirections(redirections),
		_firstByte(firstByte),
		_allData(allData)
  {
  }
  ~GloveHttpClientResponse()
	{
	}

  std::chrono::milliseconds firstByteMs() const
  {
    return _firstByte;
  }
  std::chrono::milliseconds allDataMs() const
  {
    return _allData;
  }

  double firstByte()
  {
    return (double)_firstByte.count()/1000;
  }

  double allData()
  {
    return (double)_allData.count()/1000;
  }

  int statusCode()
  {
    return _statusCode;
  }

  std::string& htmlOutput()
  {
    return _htmlOutput;
  }

  std::string header(std::string key)
  {
    return _headers[key];
  }

  std::map<std::string, std::string> headers()
  {
    return _headers;
  }

	void prevRedirect(std::string prevUrl)
	{
		_redirections.insert(_redirections.begin(), prevUrl);
	}

private:
  int _statusCode;
  std::string _htmlOutput;
  std::map<std::string, std::string> _headers;
  std::vector<std::string> _redirections;
  std::chrono::milliseconds _firstByte;
  std::chrono::milliseconds _allData;
};

struct GloveHttpClientRequest
{
	GloveHttpClientRequest(std::string url, std::string& data, std::string contentType, std::map<std::string, std::string> &headers, std::string reqType):
		url(url), data(data), contentType(contentType), headers(headers), reqType(reqType)
	{
	}
	std::string url;
	std::string data;
	std::string contentType;
	std::map<std::string, std::string> headers;
	std::string reqType;
};

class GloveHttpClient : public GloveHttpCommon
{
public:
	typedef std::function<void(GloveHttpClientRequest, GloveHttpClientResponse)> Callback;
	typedef std::function<void(std::string, GloveException&)> ErrorHandler;
	
  GloveHttpClient();

	GloveHttpClient(std::string url, GloveHttpClientResponse& r, std::string reqType="GET");
	GloveHttpClient(std::string url, GloveHttpClientResponse& r, std::string reqType, std::string& data);
	GloveHttpClient(std::string url, GloveHttpClientResponse& r, std::string reqType, std::string& data, std::map<std::string, std::string>& headers, std::string contentType="");
	GloveHttpClient(Callback callback, ErrorHandler errhandler=nullptr);
  ~GloveHttpClient();
	GloveHttpClientResponse request(std::string url, std::string reqType="GET");
	GloveHttpClientResponse request(std::string url, std::string reqType, std::string& data);
	GloveHttpClientResponse request(std::string url, std::string reqType, std::string& data, std::map<std::string, std::string>& headers, std::string contentType="");
	void bgrequest(std::string url, std::string reqType="GET");
	void bgrequest(std::string url, std::string reqType, std::string& data);
	void bgrequest(std::string url, std::string reqType, std::string& data, std::map<std::string, std::string>& headers, std::string contentType="");

	void setCallback(Callback callback)
	{
		_callback = callback;
	}

#define clientConfigSetting(name, type) type name()	\
	{																									\
		return clientConfig.name;												\
	}																									\
	type name(type val)																\
	{																									\
		clientConfig.name = val;												\
		return clientConfig.name;												\
	}

	clientConfigSetting(userAgent, std::string);
	clientConfigSetting(timeout, double);
	clientConfigSetting(checkCertificates, bool);
	clientConfigSetting(maxRedirects, int);
	clientConfigSetting(followRedirects, bool);
	
#undef clientConfigSetting	

protected:
  int parseFirstLine(std::string input, std::string& protocol, std::string &statusmsg);
  GloveHttpClientResponse getUrlData(GloveHttpClientRequest &request, double timeout, bool checkCertificates, int max_redirects);
	void addRequestToQueue(GloveHttpClientRequest& req);
	void processBackgroundQueue();
	void backgroundThread();
	
	Callback _callback;
	ErrorHandler _errhandler;
	std::mutex queueMutex;
	std::vector <GloveHttpClientRequest> requestQueue;
	
  struct
  {
    std::string userAgent;
    double timeout;
    bool checkCertificates;
    int maxRedirects;
    bool followRedirects;
  } clientConfig;
};

#endif
