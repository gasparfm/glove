/**
*************************************************************
* @file utils.hpp
* @brief Some common misc utils for Glove
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @date 10 ago 2016
*
* Notes:
*  - Some ideas borrowed from some projects I've made in the past and
*    public domain code.
*
* Changelog
*  20170401 : md5, random_base64, unescape, unquote
*  20170328 : quote, escape and several string_replace overloads
*  20160812 : - First release
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
#pragma once

#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <ctime>
#include <functional>
#include <algorithm>
#include <map>

namespace GloveDef
{
	static std::string white_spaces =" \f\n\r\t\v" ;
	static std::string CRLF = "\r\n";
	static std::string CRLF2= "\r\n\r\n";
};

namespace
{
  std::string _defaultStartDelimiter = ":";
  std::string _defaultEndDelimiter = "";
};

static std::string trim( std::string str, const std::string& trimChars = GloveDef::white_spaces)
{
	if (str.empty())
		return "";
	std::string::size_type pos_end = str.find_last_not_of( trimChars );
	std::string::size_type pos_start = str.find_first_not_of( trimChars );

	return str.substr( pos_start, pos_end - pos_start + 1 );
}

/* When using as callback some compilers can't detect the
 right trim() to use. */
static std::string defaultTrim( std::string str)
{
	return trim(str, GloveDef::white_spaces);
}

  // We could use regex but gcc 4.8 still hasn't implemented them.
  // gcc 4.9 finally can use regex, but I MUST do it compatible with 4.8
  /* static std::string string_replace(std::string source, std::map<std::string,std::string>strMap, int offset=0, int times=0) */
  /* { */
  /*   int total = 0; */
  /*   std::string::size_type pos=offset; */
  /*   std::string::size_type newPos; */
  /*   std::string::size_type lowerPos; */

  /*   do */
  /*     { */
	/* 			std::string rep; */
	/* 			for (auto i=strMap.begin(); i!=strMap.end(); ++i) */
	/* 				{ */
	/* 					std::string fromStr = i->first; */
	/* 					newPos = source.find(fromStr, pos); */
	/* 					if ( (i==strMap.begin()) || (newPos<lowerPos) ) */
	/* 						{ */
	/* 							rep = fromStr; */
	/* 							lowerPos = newPos; */
	/* 						} */
	/* 				} */

	/* 			pos = lowerPos; */
	/* 			if (pos == std::string::npos) */
	/* 				break; */

	/* 			std::string toStr = strMap[rep]; */

	/* 			source.replace(pos, rep.length(), toStr); */
	/* 			pos+=toStr.size(); */

  /*     } while ( (times==0) || (++total<times) ); */

  /*   return source; */
  /* } */

static std::string string_replace(std::string source, std::string from, std::string to, int offset=0, int times=0)
{
	int total = 0;
	std::string::size_type pos=offset;

	do
		{
			pos = source.find(from, pos);
			if (pos == std::string::npos)
				break;

			source.replace(pos, from.length(), to);
			pos+=to.size();

		} while ( (times==0) || (++total<times) );

	return source;
}

static std::string string_replace(std::string source, std::map<std::string,std::string>strMap, int offset, int times, bool delimiters, std::string before, std::string after="")
{
	int total = 0;
	std::string::size_type pos=offset;
	std::string::size_type newPos;
	std::string::size_type lowerPos;
	std::string::size_type delsize;

	if (strMap.size() == 0)
		return source;

	if (delimiters)
		delsize = before.length() + after.length();

	do
		{
			std::string rep;
			for (auto i=strMap.begin(); i!=strMap.end(); ++i)
				{
					auto fromStr = i->first;
					newPos = (delimiters)?
						source.find(before + fromStr + after, pos):
						source.find(fromStr, pos);
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
			source.replace(pos, rep.length()+((delimiters)?delsize:0), toStr);
			pos+=toStr.size();

		} while ( (times==0) || (++total<times) );

	return source;
}

static std::string string_replace(std::string source, std::map<std::string,std::string>strMap, int offset=0, int times=0, bool delimiters=false)
{
	return (delimiters)?string_replace(source, strMap, offset, times, delimiters, _defaultStartDelimiter, _defaultEndDelimiter):
		string_replace(source, strMap, offset, times, delimiters, "");
}

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
      std::string(month_names[tm.tm_mon])+" "+std::to_string(1900+tm.tm_year)+" "+
      std::to_string(tm.tm_hour)+":"+std::to_string(tm.tm_min)+":"+
      std::to_string(tm.tm_sec)+" GMT";

    return s;
  }

  // Testing
static bool validHost(std::string hostName)
  {
    static const char* validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";
    return (hostName.find_first_not_of(validChars) == std::string::npos);
  }

// Tokenizer from: http://oopweb.com/CPP/Documents/CPPHOWTO/Volume/C++Programming-HOWTO-7.html
// Modified
static std::vector<std::string> tokenize(const std::string& str,
																				 const std::string& delimiters = " ",
																				 std::function<std::string (std::string)> callback = nullptr)
{
	std::vector<std::string> tokens;
	// Skip delimiters at beginning.
	std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
	// Find first "non-delimiter".
	std::string::size_type pos     = str.find_first_of(delimiters, lastPos);

	while (std::string::npos != pos || std::string::npos != lastPos)
    {
			// Found a token, add it to the vector.
			auto item = str.substr(lastPos, pos - lastPos);
			tokens.push_back((callback == nullptr)?item:callback(item));
			// Skip delimiters.  Note the "not_of"
			lastPos = str.find_first_not_of(delimiters, pos);
			// Find next "non-delimiter"
			pos = str.find_first_of(delimiters, lastPos);
    }
	return tokens;
}

static std::map<std::string, std::string> mapize(std::vector<std::string> elements, std::string separator=":", std::function<std::string (std::string)> callback = nullptr)
{
	std::map<std::string, std::string> out;
	
	for (auto el : elements)
		{
			auto seppos = el.find(separator);
			std::string first, second;
			if (seppos != std::string::npos)
				{
					first = el.substr(0, seppos);
					second = el.substr(seppos+1);
				}
			if (callback)
				{
					first = callback(first);
					second = callback(second);
				}
			
			out.insert( std::pair<std::string, std::string>( first, second ) );
		}
	return out;
}

static std::string& toLower(std::string& s)
{
	std::transform(s.begin(), s.end(), s.begin(), (int(*)(int)) tolower );
	return s;
}

struct lowerCaseCompare
{
	std::string compareWith;
	lowerCaseCompare(std::string s): compareWith(toLower(s))
	{
	}

	bool operator()(std::map<std::string, std::string>::value_type& s)
	{
		auto str = s.first;
		return (toLower(str)==compareWith);
	}
};

/* Escape with utf8 string support */
static std::string escape(std::string source, const std::string escapable, std::string escapeChar, bool unescape=false)
{
	std::map<std::string, std::string> substmap;
	short utf8octets=0;
	std::string ch;
	char* chptr;

	for (char _ch : escapable)
		{
			if (utf8octets==0)
				{
					if ((_ch & 0x80) == 0) utf8octets=1;
					else if ((_ch & 0xE0) == 0xC0) utf8octets = 2;
					else if ((_ch & 0xF0) == 0xE0) utf8octets = 3;
					else if ((_ch & 0xF8) == 0xF0) utf8octets = 4;
					else
						utf8octets=1;				/* There is an error, but we will do it anyway*/
					ch = std::string(5, '\0');
					chptr = &ch[0];
				}
			--utf8octets;
			*chptr++= _ch;

			if (utf8octets == 0)
				{
					if (unescape)
						substmap.insert({ escapeChar+ch.c_str(), ch.c_str() });
					else
						substmap.insert({ ch.c_str(), escapeChar+ch.c_str() });

				}
		}
	
	return string_replace(source, substmap, 0);
}

static std::string quote(std::string source, const std::string _quote, const std::string escapeChar)
{
	if (escapeChar.empty())
		source=_quote+source+_quote;
	else
		source=_quote+escape(source, _quote+escapeChar, escapeChar)+_quote;

	return source;
}

static std::string unquote(std::string source, const std::string _quote, const std::string escapeChar)
{
	auto first = source.find_first_of(_quote);
	auto last = source.find_last_of(_quote);
	auto quotel = _quote.length();
	if (first != std::string::npos)
		{
			if (escapeChar.empty())
				source=source.substr(first+quotel, last-first-quotel);
			else
				source=escape(source.substr(first+quotel, last-first-quotel), _quote+escapeChar, escapeChar, true);
		}
	return source;
}

static std::string quote(const char* source, const std::string _quote, const std::string escapeChar)
{
	std::string _source(source);
	return quote(_source, _quote, escapeChar);
}

static std::string unquote(const char* source, const std::string _quote, const std::string escapeChar)
{
	std::string _source(source);
	return unquote(_source, _quote, escapeChar);
}

static void setDefaultDelimiters(std::string start, std::string end)
{
	_defaultStartDelimiter = start;
	_defaultEndDelimiter = end;
}

static std::string defaultStartDelimiter()
{
	return _defaultStartDelimiter;
}

static std::string defaultEndDelimiter()
{
	return _defaultEndDelimiter;
}

static std::string defaultStartDelimiter(std::string start)
{
	_defaultStartDelimiter = start;
	return _defaultStartDelimiter;
}

static std::string defaultEndDelimiter(std::string end)
{
	_defaultEndDelimiter = end;
	return _defaultEndDelimiter;
}
