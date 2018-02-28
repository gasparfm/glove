/**
*************************************************************
* @file glovehttpclient.cpp
* @brief HTTP Client for Glove
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version 0.3
* @date 1 jun 2016
*
* Notes:
*   - Lots of ideas borrowed from other projects
*
* Changelog
*  20170127 : - Error handler for background requests
*  20170112 : - SSL condition to compile without SSL support
*  20161004 : - Use CRLF from utils.hpp
*  20160927 : - GloveHttpClientRequest / GloveHttpClientResponse / request methods
*             - Separated cpp and hpp file
*  20160830 : - Just requests by URL
*  20160816 : - First release
*
* To-do:
*  0 - Multipart management
*  1 - Optimization
*  2 - Some more control over requests
*
* MIT Licensed:
* Copyright (c) 2016 Gaspar Fernández
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

#include "glovehttpclient.hpp"
#include <thread>

GloveHttpClient::GloveHttpClient()
{
	clientConfig.userAgent = GLOVEHTTPCLIENT_DEFAULT_USERAGENT;
	clientConfig.timeout = GLOVEHTTPCLIENT_DEFAULT_TIMEOUT;
	clientConfig.checkCertificates = GLOVEHTTPCLIENT_DEFAULT_CHECKCERTS;
	clientConfig.maxRedirects = GLOVEHTTPCLIENT_DEFAULT_MAXREDIRECTS;
	clientConfig.followRedirects = GLOVEHTTPCLIENT_DEFAULT_FOLLOWREDIRECTS;
	_callback = nullptr;
}

GloveHttpClient::GloveHttpClient(std::string url, GloveHttpClientResponse& r, std::string reqType): GloveHttpClient()
{
	r = request(url, reqType);
}

GloveHttpClient::GloveHttpClient(std::string url, GloveHttpClientResponse& r, std::string reqType, std::string& data): GloveHttpClient()
{
	r = request(url, reqType, data);
}

GloveHttpClient::GloveHttpClient(std::string url, GloveHttpClientResponse& r, std::string reqType, std::string& data, std::map<std::string, std::string>& headers, std::string contentType): GloveHttpClient()
{
	r = request(url, reqType, data, headers, contentType);
}

GloveHttpClient::GloveHttpClient(Callback callback, ErrorHandler errhandler): GloveHttpClient()
{
	_callback = callback;
	_errhandler = errhandler;
}

GloveHttpClient::~GloveHttpClient()
{
}

GloveHttpClientResponse GloveHttpClient::request(std::string url, std::string reqType)
{
	std::string data = "";
	std::map < std::string, std::string> headers;
	GloveHttpClientRequest request (url, data, "", headers, reqType);
	return getUrlData(request, clientConfig.timeout, clientConfig.checkCertificates, clientConfig.maxRedirects);
}

GloveHttpClientResponse GloveHttpClient::request(std::string url, std::string reqType, std::string& data)
{
	std::map < std::string, std::string> headers;
	GloveHttpClientRequest request (url, data, "", headers, reqType);
	return getUrlData(request, clientConfig.timeout, clientConfig.checkCertificates, clientConfig.maxRedirects);
}

GloveHttpClientResponse GloveHttpClient::request(std::string url, std::string reqType, std::string& data, std::map<std::string, std::string>& headers, std::string contentType)
{
	GloveHttpClientRequest request (url, data, contentType, headers, reqType);
	return getUrlData(request, clientConfig.timeout, clientConfig.checkCertificates, clientConfig.maxRedirects);
}

void GloveHttpClient::bgrequest(std::string url, std::string reqType)
{
	std::string data = "";
	std::map < std::string, std::string> headers;
	GloveHttpClientRequest request (url, data, "", headers, reqType);
	addRequestToQueue(request);
}

void GloveHttpClient::bgrequest(std::string url, std::string reqType, std::string& data)
{
	std::map < std::string, std::string> headers;
	GloveHttpClientRequest request (url, data, "", headers, reqType);
	addRequestToQueue(request);
}

void GloveHttpClient::bgrequest(std::string url, std::string reqType, std::string& data, std::map<std::string, std::string>& headers, std::string contentType)
{
	GloveHttpClientRequest request (url, data, contentType, headers, reqType);
	addRequestToQueue(request);
}


int GloveHttpClient::parseFirstLine(std::string input, std::string& protocol, std::string &statusmsg)
{
	std::string::size_type space_pos, space_pos2;
	std::string temp_status;
	int status=0;

	space_pos = input.find(' ');

	if (space_pos == std::string::npos)
		throw GloveHttpClientException (5, "Couldn't parse protocol from received data");

	protocol = input.substr(0, space_pos);
	space_pos2 = input.find(' ', space_pos+1);

	if (space_pos == std::string::npos)
		throw GloveHttpClientException (6, "Couldn't parse status from received data");

	temp_status = input.substr(space_pos+1, space_pos2-space_pos-1);
	statusmsg = input.substr(space_pos2+1);

	try
		{
			status = std::stoi(temp_status);
		}
	catch (std::invalid_argument ia)
		{
			throw GloveHttpClientException (7, "Wrong status code");
		}
	catch (std::out_of_range org)
		{
			throw GloveHttpClientException (8, "Wrong status code");
		}

	return status;
}

GloveHttpClientResponse GloveHttpClient::getUrlData(GloveHttpClientRequest &request, double timeout, bool checkCertificates, int max_redirects)
{
	if (max_redirects < 0)
		throw GloveHttpClientException (1, "Max redirects reached!");

	/* No keepAlive for now */
	Glove g;
	GloveBase::uri u = Glove::get_from_uri(request.url);
	std::map<std::string, std::string> httpheaders;
	std::string protocol, statusmsg;
	int status;
	std::string out;
	/* We can debug uri here */
	/* u.host="localhost"; */
	/* u.port=1234; */
#if ENABLE_OPENSSL
	if (checkCertificates)
		g.SSLFlags(Glove::SSL_FLAG_ALL);
#endif
	g.shutdown_on_destroy(true);
	g.timeout_when_data(false);
	g.remove_exceptions (Glove::EXCEPTION_DISCONNECTED);
	/* this->say("Connecting "+url+" with timeout "+std::to_string(timeout), 2); */
	if (timeout != -1)
		g.timeout(timeout);
	g.connect(u);
	if (u.rawpath.empty())
		u.rawpath = "/";
	auto startTime = std::chrono::steady_clock::now();
	std::string reqStr = request.reqType+" "+u.rawpath+" HTTP/1.1\r\n"
		"Host: "+u.host+"\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml\r\n"
		"Connection: close\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/45.0.2454.101 Chrome/45.0.2454.101 Safari/537.36\r\n";
	for (auto header : request.headers)
		{
			reqStr+=header.first+": "+header.second+"\r\n";
		}

	if (!request.data.empty())
		{
			if (request.contentType.empty())
				request.contentType = "application/x-www-form-urlencoded";
			reqStr+="Content-Type: "+request.contentType+"\r\n";
			reqStr+="Content-Length: "+std::to_string(request.data.length())+"\r\n";
		}

	g.send(reqStr+ "\r\n"+request.data);
	out = g.receive();
	auto firstByte = std::chrono::steady_clock::now();
	auto firstline = out.find(GloveDef::CRLF); /* End of first line. Protocol Code Status...*/
	if (firstline == std::string::npos)
		throw GloveHttpClientException (2, "Didn't receive protocol or status");

	status = parseFirstLine(out.substr(0, firstline), protocol, statusmsg);

	auto headerend = out.find(GloveDef::CRLF2);
	if (headerend == std::string::npos)
		throw GloveHttpClientException (3, "Unexpected data received");

	extract_headers(out.substr(firstline+1, headerend-firstline-1), httpheaders, 0);
	/* this->say("Return status: "+std::to_string(status), 3); */
	namespace chr = std::chrono;
	if ( (status>=300) && (status<400) )
		{
			auto location = httpheaders.find("Location");
			if ( (location != httpheaders.end()) || ((location = httpheaders.find("location")) != httpheaders.end()) )
				{
					std::string newUrl = location->second;
					newUrl = newUrl.substr(newUrl.find_first_not_of("/")); /* remove starting / */
					if (newUrl.find(u.service)!=0)
						newUrl=u.service+"://"+u.host+"/"+newUrl;
					request.url = newUrl;
					GloveHttpClientResponse response = getUrlData(request, timeout, checkCertificates, max_redirects-1);
					response.prevRedirect(request.url);
					return response;
				}
			else
				{
					throw GloveHttpClientException (4, "Redirection requested but Location not found");
				}
		}
	else
		{
			out = out.substr(headerend+4);
			return GloveHttpClientResponse(status, out, httpheaders, { request.url },
																		 chr::duration_cast<chr::milliseconds>(firstByte - startTime),
																		 chr::duration_cast<chr::milliseconds>(firstByte - startTime));
		}
}

void GloveHttpClient::addRequestToQueue(GloveHttpClientRequest& req)
{
	if (_callback == nullptr)
		throw GloveHttpClientException (9, "No callback specified");

	queueMutex.lock();
	unsigned queueLen = requestQueue.size();
	requestQueue.push_back(req);
	queueMutex.unlock();

	if (queueLen==0)
		processBackgroundQueue();
}

void GloveHttpClient::processBackgroundQueue()
{
	std::lock_guard<std::mutex> lock(queueMutex);

	if (requestQueue.size()==0)
		return;

	std::thread(&GloveHttpClient::backgroundThread, this).detach();
}

void GloveHttpClient::backgroundThread()
{
	queueMutex.lock();
	if (requestQueue.size()==0)
		{
			queueMutex.unlock();
			return ;
		}

	GloveHttpClientRequest request = requestQueue.front();
	try
		{
			requestQueue.erase(requestQueue.begin());
			queueMutex.unlock();

			GloveHttpClientResponse response = getUrlData(request, clientConfig.timeout, clientConfig.checkCertificates, clientConfig.maxRedirects);
			_callback(request, response);
		}
	catch (GloveException &e)
		{
			if (_errhandler)
				_errhandler(request.url, e);
		}
	backgroundThread();
}
