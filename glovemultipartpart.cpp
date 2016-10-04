/**
*************************************************************
* @file glovemultipartpart.cpp
* @brief Part processor for multipart content in C++11 . Made for Glove
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version 0.2
* @date 01 sep 2016
*
* Notes:
*   - Lots of ideas borrowed from other projects
*   - Some parts extracted from Glove source code and separated to use in
*     an independent way.
*   - Changes and improvements are welcome! Issue/fork on GitHub
* 
* Changelog
*  20161004 : - Using CRLF from utils.hpp
*  20160927 : - First release
*
* To-do:
*  0 - Setter for part attributes
*  1 - Code optimization. Maybe there are some leaks
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

#include "glovemultipartpart.hpp"
#include "utils.hpp"
#include "glovecoding.hpp"
#include "gloveexception.hpp"
#include <cstring>
#include <algorithm>

void GloveMultipartPart::init(std::string& content, std::vector<Meta> meta)
{
	auto len = content.length();
	this->_content = new char[len+1];
	this->_contentSize = len;
	content.copy(this->_content, len);
	this->_content[len] = '\0';

	
	//std::terminate();
	this->metaData = meta;
}

GloveMultipartPart::GloveMultipartPart(std :: string & content,
																			 std :: vector < Meta > meta)
{
	this->init(content, meta);
}

GloveMultipartPart::GloveMultipartPart(std::string &content,
																			 std::string contentType,
																			 std :: string contentDisposition,
																			 std :: string contentTransferEncoding)
{
	std::vector <Meta> meta;
	Meta m;
	if ( (!contentType.empty()) && (parseMeta(m, contentType, "Content-Type")) )
		meta.push_back (m);
	if ( (!contentDisposition.empty()) && (parseMeta(m, contentDisposition, "Content-Disposition")) )
		meta.push_back (m);
	if ( (!contentTransferEncoding.empty()) && (parseMeta(m, contentTransferEncoding, "Content-Transfer-Encoding")) )
		meta.push_back (m);

	this->init(content, meta);
}

GloveMultipartPart::GloveMultipartPart(const GloveMultipartPart& old)
{
	this->_contentSize = old._contentSize;
	this->_content = new char[this->_contentSize+1];
	if (memcpy(this->_content, old._content, this->_contentSize) == NULL)
		throw GloveException(102, "Out of memory while copying mail part");
	
	this->metaData = old.metaData;
}

std::string GloveMultipartPart::debugMeta()
{
	std::string out;
	for (auto met : metaData)
		{
			out+=met.name+": "+metaInfo(met)+GloveDef::CRLF;
		}
	
	return out;
}

/* Full = false:
	 text/plain; charset=utf-8

	 Full = true
	 Content-Type: text/plain; charset=utf-8
*/
bool GloveMultipartPart::parseMeta(Meta& meta, std::string inputStr, std::string metaName)
{
	auto insertMetaAttributes = [](Meta& meta, std::string& inputStr, std::string::size_type semicolon)
	{
		do
			{
				auto lastsc = semicolon;
				semicolon = inputStr.find(';', semicolon+1);
				auto temp = (semicolon==inputStr.npos)?inputStr.substr(lastsc+1):inputStr.substr(lastsc+1, semicolon-1);
				if (trim(temp).empty())
					continue;						/* If temp no key, no more metadata. */
				auto equal = temp.find('=');					
				if (equal == temp.npos)
					meta.extra.insert({ trim(temp), "" });
				else
					meta.extra.insert({ trim(temp.substr(0, equal)), trim(temp.substr(equal+1))});
			}
		while (semicolon != inputStr.npos);
		
	};
	meta = { "", "", {} };
	if (metaName.empty())
		{
			auto colon = inputStr.find(':');
			if (colon == inputStr.npos)
				{
					return false;
				}
			metaName = inputStr.substr(0, colon);
			return parseMeta(meta, inputStr.substr(colon+1), metaName);
		}

	auto semicolon = inputStr.find(';');
	if (semicolon==inputStr.npos)
		{
			meta = { trim(metaName), trim(inputStr) };
			return true;
		}
	else
		{
			meta.name = trim(metaName);
			meta.value = trim(inputStr.substr(0, semicolon));
			insertMetaAttributes(meta, inputStr, semicolon);
			return true;
		}
	return false;
}


std::string GloveMultipartPart::metaInfo(const Meta& meta, bool full)
{
	std::string out = (full)?meta.name+": "+meta.value:meta.value;
	for (auto me : meta.extra)
		{
			out+="; "+me.first+"="+me.second;
		}
	
	return out;
}

std::string GloveMultipartPart::getMeta(std::string name, std::string attribute)
{
	auto meta = std::find_if (metaData.begin(), metaData.end(), [name](const Meta &me) -> bool { return (me.name==name); });
	if (meta == metaData.end())
		return "";

	if ( (attribute=="") || (attribute=="_value") )
		return meta->value;
	else if (attribute=="*")
		return metaInfo(*meta);
	else
		{
			auto mex = meta->extra.find(attribute);
			if (mex != meta->extra.end())
				return mex->second;
			else
				return "";
		}
}

std::string GloveMultipartPart::str()
{
	std::string out;
	for (auto met : metaData)
		{
			out+=metaInfo(met, true)+GloveDef::CRLF;
		}
	out+=GloveDef::CRLF;
	auto transferEncoding = getMeta("Content-Transfer-Encoding");
	std::transform(transferEncoding.begin(), transferEncoding.end(), transferEncoding.begin(), ::tolower);
	if ( (transferEncoding == "binary") || (transferEncoding == "") )
		out+=this->_content;
	else if (transferEncoding == "base64") 
		out+=GloveCoding::base64_encode((const unsigned char*)this->_content, this->_contentSize,77);
	else if (transferEncoding == "quoted-printable")
		out+=GloveCoding::qp_encode((const char*)this->_content);
	else
		{
			throw GloveException(100, "Transfer-Encoding method "+transferEncoding+" not implemented.");
		}

	return out+GloveDef::CRLF;
}


GloveMultipartPart::~GloveMultipartPart()
{
	delete this->_content;
}

void GloveMultipartPart::parseContent(std::string& content)
{
	auto crlfcrlf = content.find(GloveDef::CRLF2);
	if (crlfcrlf == content.npos)
		throw GloveException(101, "Invalid multipart part data. Could not find CRLFCRLF");
	auto inputData = content.substr(crlfcrlf+4);
	auto inputMeta = content.substr(0, crlfcrlf);
	std::vector<Meta> mdata;
	std::string::size_type crlf;
	std::string cte;
	std::vector<std::string> metalines;
	bool append=false;
	do
		{
			crlf = inputMeta.find(GloveDef::CRLF);
			if (crlf == 0)
				{
					inputMeta = inputMeta.substr(2);
					continue;								/* Empty line */
				}
			auto metaline = trim((crlf!=inputMeta.npos)?inputMeta.substr(0, crlf):inputMeta);
			if (!append)
				metalines.push_back(metaline);
			else
				metalines.back().append(metaline);
			append = (metaline.back()==';');
			inputMeta = inputMeta.substr(crlf+2);
		} while (crlf != inputMeta.npos);

	for (auto metaline : metalines)
		{
			Meta m;
			if (parseMeta(m, metaline))
				mdata.push_back(m);
			if (m.name == "Content-Transfer-Encoding")
				cte = m.value;

		}
	std::string finalData;
	if ( (cte=="binary") || (cte=="8bit") || (cte=="") )
		finalData = inputData;
	else if (cte=="base64")
		finalData=GloveCoding::base64_decode(inputData);
	else if (cte=="quoted-printable")
		finalData=GloveCoding::qp_decode(inputData.c_str());
	else
		throw GloveException(101, "Transfer-Encoding method "+cte+" not implemented.");

	init(finalData, mdata);
}

GloveMultipartPart::GloveMultipartPart(std::string& content, bool parse)
{
	if (!parse)
		init(content, {});
	
	parseContent(content);
}

GloveMultipartPart::GloveMultipartPart(char* content, bool parse)
{
	std::string cont(content);
	if (!parse)
		init(cont, {});
	parseContent(cont);
}
