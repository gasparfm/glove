/**
*************************************************************
* @file glovecoding.cpp
* @brief Several encoding/decoding routines in C++11. Made for
*        Glove, but they can be used indepently
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version 0.2
* @date 10 sep 2016
*
* Notes:
*  - Some code borrowed from r-lyeh's knot ( https://github.com/r-lyeh/knot )
*  - These functions are not the original ones from the original authors.
*  - urlencode/urldecode borrowed from knot base on code by Fred Bulback
*  - base64 encode/decode functions by René Nyffenegger (https://github.com/ReneNyffenegger/development_misc/tree/master/base64)
*  - quote-printable (QP) functions based on work by  Hiroshi Seki (https://github.com/rane-hs)
*    and JP Robinson (https://github.com/jprobinson).
*
* Changelog
*  20160926 - Initial release
*
* To-do:
*  0 - More routines
*  1 - Some optimization
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

#include "glovecoding.hpp"

namespace
{
  // Base64 encoder/decoder stuff
  static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

	static const std::string hex_chars = "ABCDEF0123456789";
	static const std::string hex_charsL = "abcdef0123456789";	

  static inline bool is_base64(unsigned char c, bool newline=true) {
    return (!newline)?(isalnum(c) || (c == '+') || (c == '/') ):
			(isalnum(c) || (c == '+') || (c == '/') || (c == '\r') || (c=='\n') );
  }
};

namespace GloveCoding
{
	// borrowed from original knot https://github.com/r-lyeh/knot
	// knot had adapted it from code by Fred Bulback
	std::string urlencode( const std::string &str ) 
	{
		auto to_hex = [](char code) -> char
			{
				static char hex[] = "0123456789abcdef";
				return hex[code & 15];
			};

		std::string out( str.size() * 3, '\0' );
		const char *pstr = str.c_str();
		char *buf = &out[0], *pbuf = buf;
		while (*pstr) 
			{
				if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
					*pbuf++ = *pstr;
				else if (*pstr == ' ')
					*pbuf++ = '+';
				else
					*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
				pstr++;
			}

		return out.substr( 0, pbuf - buf );
	}

	std::string urldecode( const std::string &str )
	{
		auto from_hex = [](char ch) -> char 
			{
				return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
			};

		const char *pstr = str.c_str();
		std::string out( str.size(), '\0' );
		char *buf = &out[0], *pbuf = buf;
		while (*pstr) 
			{
				if (*pstr == '%') 
					{
						if (pstr[1] && pstr[2]) 
							{
								*pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
								pstr += 2;
							}
					} 
				else if (*pstr == '+') 
					{
						*pbuf++ = ' ';
					} 
				else 
					{
						*pbuf++ = *pstr;
					}
				pstr++;
			}

		return out.substr( 0, pbuf - buf );
	}

	std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len, unsigned int lineLength) 
	{
		std::string ret;
		int i = 0;
		int j = 0;
		unsigned char char_array_3[3];
		unsigned char char_array_4[4];

		while (in_len--) 
			{
				char_array_3[i++] = *(bytes_to_encode++);
				if (i == 3) 
					{
						char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
						char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
						char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
						char_array_4[3] = char_array_3[2] & 0x3f;

						for(i = 0; (i <4) ; i++)
							{
								if (i && lineLength && ret.length()%lineLength==0)
									ret += '\n';
								ret += base64_chars[char_array_4[i]];
							}
						i = 0;
					}
			}

		if (i)
			{
				for(j = i; j < 3; j++)
					char_array_3[j] = '\0';

				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (j = 0; (j < i + 1); j++)
					{
						if (lineLength && ret.length()%lineLength==0)
							ret += '\n';
						ret += base64_chars[char_array_4[j]];
					}
				
				while((i++ < 3))
					ret += '=';

			}

		return ret;
	}

	/* Modified to support \r and \n in base64 string. These characters will be ignored
	   but we can find them when sending or receiving data. */
	std::string base64_decode(std::string const& encoded_string) 
	{
		int in_len = encoded_string.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		unsigned char char_array_4[4], char_array_3[3];
		std::string ret;
		while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_]) )
			{
				if (encoded_string[in_]=='\n' || encoded_string[in_]=='\r')
					{
						in_++;
						continue;
					}
				char_array_4[i++] = encoded_string[in_]; in_++;
				if (i ==4) 
					{
						for (i = 0; i <4; i++)
							char_array_4[i] = base64_chars.find(char_array_4[i]);

						char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
						char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
						char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

						for (i = 0; (i < 3); i++)
							ret += char_array_3[i];
						i = 0;
					}				
			}
		if (i) 
			{
				for (j = i; j <4; j++)
					char_array_4[j] = 0;

				for (j = 0; j <4; j++)
					char_array_4[j] = base64_chars.find(char_array_4[j]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
			}

		return ret;
	}

	std::string randomHex(unsigned int chars, bool lowerCase)
	{
		std::string out;
		while (chars--)
			{
				if (lowerCase)
					out+=hex_charsL[rand()%16];
				else
					out+=hex_chars[rand()%16];
			}
		
		return out;		
	}

	std::string randomBase64(unsigned int chars)
	{
		std::string out;
		while (chars--)
			{
				out+=base64_chars[rand()%64];
			}
		
		return out;				
	}
	
	const std::string qp_decode(const char *src)
	{
		const size_t len = std::string(src).length();
		return qp_decode<const char *> (src, &src[len]);
	}

	const std::string qp_encode(const char *src)
	{
		const size_t len = std::string(src).length();
		return qp_encode<const char *> (src, &src[len]);
	}

};
