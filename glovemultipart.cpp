/**
*************************************************************
* @file glovemultipart.cpp
* @brief Multipart processor in C++11 . Made for Glove
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
*   - MUST BE USED WITH multipartpart.hpp/cpp
* 
* Changelog
*  20161004 : - Using CRLF from utils.hpp
*  20160927 : - First release
*
* To-do:
*  0 - Part manipulation
*  1 - Part deletion
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

#include "glovemultipart.hpp"
#include "gloveexception.hpp"
#include "utils.hpp"

GloveMultipart::GloveMultipart(std::string boundary):_boundary(boundary)
{
}

GloveMultipart::~GloveMultipart()
{
}

std::string GloveMultipart::str()
{
	std::string out;
	for (GloveMultipartPart mpp : parts)
		{
			out+="--"+_boundary+GloveDef::CRLF+mpp.str()+GloveDef::CRLF;
		}
	out+="--"+_boundary+"--"+GloveDef::CRLF;
	return out;
}

GloveMultipart::GloveMultipart(std::string data, std::string boundary)
{
	parse(data, boundary);
}

void GloveMultipart::parse(std::string &data, std::string boundary)
{
	if (boundary.empty())
		{
			throw GloveException(106, "Auto boundary not implemented");
			/* Not implemented, get boundary from first line */
			return;
		}
	auto __boundary = "--"+boundary;
	auto begin = data.find(__boundary);
	auto end = data.find(__boundary+"--");

	if (begin == data.npos)
		throw GloveException(103, "Can't find multipart data begin");
	if (end == data.npos)
		throw GloveException(104, "Can't find multipart data end");

	if (begin == end)
		throw GloveException(105, "Can't find multipart data begin");

	std::string::size_type partend;
	do
		{
			partend = data.find(__boundary, begin+__boundary.length());
			add(data.substr(begin+__boundary.length(), partend-begin).c_str());
			begin = partend;
		} while (partend != end);
}

GloveMultipartPart& GloveMultipart::getPart(unsigned num)
{
	if (num>=parts.size())
		throw GloveException(105, "Part "+std::to_string(num)+" not found");
	
	return parts.at(num);
}

void GloveMultipart::add(GloveMultipartPart part)
{
	parts.push_back(part);
}

void GloveMultipart::add(const char* data)
{
	GloveMultipartPart mpp((char*)data, true);
	parts.push_back(mpp);
}

void GloveMultipart::add(std::string &data)
{
	GloveMultipartPart mpp(data, true);
	parts.push_back(mpp);
}

void GloveMultipart::add(std::string contentType, std::string content, std::string contentTransferEncoding, std::string contentDisposition)
{
	GloveMultipartPart mpp(content, contentType, contentDisposition, contentTransferEncoding);
	parts.push_back(mpp);
}
