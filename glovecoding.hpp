#pragma once

#include <string>
#include <sstream>
#include <cstdlib>
#include "utils.hpp"
#if ENABLE_OPENSSL
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "sha1.hpp"
#else
#include "sha1.hpp"
#include "md5.hpp"
#endif

namespace
{
	/* Helper functions for quoted-printable encode/decode */
	const char asciiToBinary(const char src1)
	{
		if( (src1 >= 'A') && (src1 <= 'F') ) return 10+(src1 - 'A');
		if( (src1 >= 'a') && (src1 <= 'f') ) return 10+(src1 - 'a');
		if( (src1 >= '0') && (src1 <= '9') ) return (src1 - '0');
		return -1;
	}
	const char asciiToBinary(const char src1, const char src2)
	{
		return (asciiToBinary(src1) << 4) + asciiToBinary(src2);
	}
};

namespace GloveCoding
{
	  /**
   * URL Encode string. To make it suitable for trasceiving with some protocols.
   * borrowed from original knot https://github.com/r-lyeh/knot
   * knot had adapted it from code by Fred Bulback
   *
   * @param str String to urlencode 
   *
   * @return urlencoded string
   */
	std::string urlencode( const std::string &str );

  /**
   * URL Decode string. To make it readable easily after transceiving by some protocols
   * borrowed from original knot https://github.com/r-lyeh/knot
   * knot had adapted it from code by Fred Bulback
   *
   * @param str String to urldecode
   *
   * @return urldecoded string
   */
	std::string urldecode( const std::string &str );

  /**
   * Base64 encode a string.
   * Originally by René Nyffenegger (https://github.com/ReneNyffenegger/development_misc/tree/master/base64)
   * Left as char* because sometimes it's useful to encode a file when reading it.
   *
   * @param s     String to encode
   * @param len   How many bytes to encode
   *
   * @return encoded string
   */
  std::string base64_encode(unsigned char const* s, unsigned int len, unsigned int lineLength=0);

  /**
   * Base64 decode a string.
   * Originally by René Nyffenegger (https://github.com/ReneNyffenegger/development_misc/tree/master/base64)
   *
   * @param s    String to decode
   *
   * @return decoded string .
   */
  std::string base64_decode(std::string const& s);

	/* Puts random hexadecimal characters */
	std::string randomHex(unsigned int chars, bool lowerCase=false);

	/* Puts random base64 characters */
	std::string randomBase64(unsigned int chars);
	
	/**
	 * Quoted-printable encode a string
	 * Originally by Hiroshi Seki (https://github.com/rane-hs) but modified
	 *
	 */
	template <typename Iter_>
	const std::string qp_decode(Iter_ begin, Iter_ end)
	{
		std::ostringstream	oss("");
		Iter_ nowPos = begin;
		while(nowPos < end)
			{
				char byte = *nowPos++;
				if(byte == '=')
					{
						Iter_ nextPos = nowPos;
						if ((nextPos == end) || (nextPos+1 == end) )
							break;
						if( ((*nextPos) == '\n') || ((*nextPos) == '\r') )		//quoted-printable改行('='+'\n')
							++nowPos;
						else
							{
								const char srcPos1 = *(nowPos++);
								const char srcPos2 = *(nowPos++);
				/* 				//ascii -> char */
								oss << asciiToBinary(srcPos1, srcPos2);
							}
					}
				else
					{
						oss << byte;
					}
				/* ++nowPos; */
			}
		return oss.str();
	}

	const std::string qp_decode(const char *src);
	
	/**
	 * Quoted-printable encode a string
	 * Based on Hiroshi Seki (https://github.com/rane-hs) and
	 * JP Robinson (https://github.com/jprobinson) code
	 *
	 */
	template <typename Iter_>
	const std::string qp_encode(Iter_ begin, Iter_ end)
	{
		Iter_ veryBegin = begin;
		
		std::ostringstream	oss("");
		int lineLength = 0;
		while(begin != end)
			{
				unsigned char byte = *begin;
				if (lineLength>72)
					{
						/* Insert '=' if prev char exists and is not a space */
						if ( (begin != veryBegin) && (*(begin-1) != 0x20) )
							oss << "=";
						oss << "\n";
						lineLength=0;
					}
				if (byte == 0x20)
					oss << byte;
				else if ((byte >= 33) && (byte <= 126) && (byte != 61))
					{
						oss << byte;
						// double escape newline periods
            // http://tools.ietf.org/html/rfc5321#section-4.5.2
            if((lineLength) == 0 && (byte == 46))
							{
                oss << ".";
							}
					}
				else
					{
						oss << '='
								<< std::uppercase << std::hex << ((byte >> 4) & 0x0F)
								<< std::uppercase << std::hex << (byte & 0x0F);
            // 2 more chars bc hex and equals
						lineLength += 2;
					}
				lineLength++;
				begin++;
			}
		return oss.str();
	}

	const std::string qp_encode(const char *src);

	static std::string bin2hex(const std::string& in)
	{
    std::stringstream ss;

    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i)
			{
				ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
			}

    return ss.str(); 
	}

	static std::string hex2bin(const std::string& in)
	{
    std::string output;

    if ((in.length() % 2) != 0)
			{
				return "";
			}

    size_t cnt = in.length() / 2;

    for (size_t i = 0; cnt > i; ++i)
			{
				uint32_t s = 0;
				std::stringstream ss;
				ss << std::hex << in.substr(i * 2, 2);
				ss >> s;

				output.push_back(static_cast<unsigned char>(s));
			}

    return output;
	}

	static std::string sha1(std::string origin)
	{
		/* openssl method is muuuuuuuuch faster */
		#if ENABLE_OPENSSL
		std::string hash(20, '\0');
		SHA1((const unsigned char*)origin.c_str(),
				 origin.length(),
				 (unsigned char*)&hash[0]);
		return hash;
		#else
		Digest::SHA1 checksum;
    checksum.update(origin);
    return checksum.final();
		#endif
	}

	static std::string sha1_b64(std::string origin)
	{
		return base64_encode((unsigned char*)sha1(origin).c_str(), 20);
	}

	static std::string sha1_hex(std::string origin)
	{
		return bin2hex(sha1(origin));
	}

	static std::string md5(std::string origin)
	{
		/* openssl method is muuuuuuuuch faster */
		#if ENABLE_OPENSSL
		std::string hash(16, '\0');
		MD5((const unsigned char*)origin.c_str(),
				 origin.length(),
				 (unsigned char*)&hash[0]);
		return hash;
		#else
		Digest::MD5 md5 = Digest::MD5(origin);
    return md5.digest();
		#endif
	}

	static std::string md5_b64(std::string origin)
	{
		return base64_encode((unsigned char*)md5(origin).c_str(), 16);
	}

	static std::string md5_hex(std::string origin)
	{
		return bin2hex(md5(origin));
	}
};
