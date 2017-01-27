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
  static std::string string_replace(std::string source, std::map<std::string,std::string>strMap, int offset=0, int times=0)
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
