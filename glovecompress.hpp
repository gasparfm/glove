#pragma once

#include <zlib.h>
#include <iostream>
#include <string>
#include <algorithm>
#include "utils.hpp"

namespace
{
	/* Gets name of compression method */
	static std::string getCompressionMethodStr(std::string& accepted, std::vector<std::string>& compatible)
	{
		auto _accepted = tokenize(accepted, ",", defaultTrim);
		for (auto m: compatible)
			{
				auto el = std::find(_accepted.begin(), _accepted.end(), m);
				if (el != _accepted.end())
					return *el;
			}
		
		return "";
	}	
};

namespace GloveCompress
{
	/* This errors are far from deflate/inflate errors, will indicate
		 our destination buffer is not big enough to store the whole
		 compressed or uncompressed data. */

	const short ERR_UNDERSIZED = -100;
	const short ERR_DEFLATE_PARTIAL = -101;
	const short ERR_DEFLATE_PARTIAL_STREAM = -102;
	const short ERR_INVALID_METHOD = -103;
	
	const long CHUNK = 16384;

	static short getCompressionMethodCode(std::string name)
	{
		if (name == "gzip")
			return 1;
		else if (name =="deflate")
			return 0;
		
		return -1;

	}
	
	static std::string getCompressionMethodName(short code)
	{
		switch (code)
			{
			case 0: return "deflate";
			case 1: return "gzip";
			default: return "";
			}
	}

	/* Will select one accepted method if compatible.
		 After that, will get the code of the compression method*/
	static short getCompressionMethod(std::string& accepted, std::vector<std::string>& compatible)
	{
		auto cmet = getCompressionMethodStr(accepted, compatible);
		return getCompressionMethodCode(cmet);
	}

	/** ***********************************
	 * Compress source data from memory to memory.
	 *
	 * @param source Source data
	 * @param source_size Size of source data (if compressing a string, it can be strlen(source)+1)
	 * @param dest Where to store compressed data
	 * @param destination_size Max. size of compressed data
	 * @param method 0 (deflate), 1 (gzip)
	 * @param level Compession level
	 *
	 * @return If <0, error, Z_MEM_ERROR if could not allocate memory.
	 *                       Z_VERSION_ERROR if version of zlib.h and linked library
	 *                       Z_STREAM_ERROR if invalid compression level supplied.
	 *                       ERR_UNDERSIZED if dest is not big enough to store all data
	 *                       ERR_DEFLATE_PARTIAL if there was a problem running deflate
	 *                                           and it was not fully deflated
	 *                       ERR_DEFLATE_PARTIAL_STREAM there was a problem and the compressed
	 *                                                  stream does not ends right.
	 *                       ERR_INVALID_METHOD if method number is not valid
	 *         If >0, size of compressed data
	 */
	static int dodeflate(char* source, size_t source_size, char* dest, size_t& destination_size, short method, int level)
	{
		int ret, flush;
		size_t have;
		z_stream strm;
		unsigned char *in = (unsigned char*)source;
		unsigned char *out = (unsigned char*)dest;
		size_t original_dest_size = destination_size;

		if ( (method<0) || (method>1) )
			return ERR_INVALID_METHOD;

		/* Initialize deflate */
		strm.zalloc = Z_NULL;
		strm.zfree = Z_NULL;
		strm.opaque = Z_NULL;
		strm.next_in = in;
		
		ret = (method==0)?deflateInit(&strm, level):deflateInit2(&strm, level, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
		if (ret != Z_OK)
			return ret;

		/* compress !! */
		do
			{
				if (source_size>CHUNK)
					{
						strm.avail_in = CHUNK;
						source_size-=CHUNK;
					}
				else
					{
						strm.avail_in = source_size;
						source_size = 0;
					}
				flush = (source_size == 0) ? Z_FINISH : Z_NO_FLUSH;
				strm.next_in = in;

				/* run deflate() on input until output buffer not full, finish
					 compression if all of source has been read in */
				do
					{
						strm.avail_out = CHUNK;
						strm.next_out = out;

						ret = deflate(&strm, flush);    /* no bad return value */
						if (ret == Z_STREAM_ERROR)      /* error check */
							return ret;

						have = CHUNK - strm.avail_out;
						out+=have;          /* Move out pointer */
						destination_size-=have; /* calculate destination size left */
					} while (strm.avail_out == 0);

				if (strm.avail_in != 0)
					return ERR_DEFLATE_PARTIAL;

				in+=CHUNK;       /* Move in to the next chunk */
				/* done when last data in file processed */
			} while (flush != Z_FINISH);

		if (ret != Z_STREAM_END)
			return ERR_DEFLATE_PARTIAL_STREAM;

		/* clean up and return */
		(void)deflateEnd(&strm);
	
		destination_size = original_dest_size-destination_size;
		return 0;
	}

	static int dodeflate(const std::string& in, std::string& out, short method, int level)
	{
		auto size = in.length();
		out.clear();
		out.resize(size);
		auto result = GloveCompress::dodeflate((char*)in.c_str(), size+1, &out[0], size, method, level);
		out.shrink_to_fit();
		return result;
	}
	
	/* THIS FUNCTION WILL BE CHANGED SOON */
	/** ***********************************
	 * Uncompress source data from memory to memory.
	 *
	 * @param source Source data (compressed data)
	 * @param source_size Size of source data
	 * @param dest Where to store uncompressed data
	 * @param destination_size Max. size of compressed data
	 *
	 * @return If <0, error, Z_DATA_ERROR if deflated data is invalid or incomplete
	 *                       Z_VERSION_ERROR if version of zlib.h and linked library
	 *                       Z_STREAM_ERROR if there was a problem deflating.
	 *                       Z_MEM_ERROR problem allocating memory
	 *                       ERR_UNDERSIZED if dest is not big enough to store all data
	 *         If >0, size of uncompressed data
	 */
	static int doinflate(char* source, size_t source_size, char* dest, size_t destination_size)
	{
    int ret;
    size_t have;
    z_stream strm;
    unsigned char* in = (unsigned char*)source;
    unsigned char* out = (unsigned char*)dest;
    size_t original_dest_size = destination_size;

    /* initialize z_stream */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
			return ret;

    /* decompress until source is completelly read */
    do
      {
				if (source_size>CHUNK)
					{
						strm.avail_in = CHUNK;
						source_size-=CHUNK;
					}
				else
					{
						strm.avail_in = source_size;
						source_size = 0;
					}

				strm.next_in = in;

        /* run inflate() on input until output buffer  */
        do
					{
						if (destination_size<CHUNK)
							return ERR_UNDERSIZED;

            strm.avail_out = CHUNK;
            strm.next_out = out;

						/* inflate data */
            ret = inflate(&strm, Z_NO_FLUSH);

            switch (ret)
							{
							case Z_NEED_DICT:
								ret = Z_DATA_ERROR;
							case Z_DATA_ERROR:
							case Z_MEM_ERROR:
								(void)inflateEnd(&strm);
							case Z_STREAM_ERROR:
								return ret;
							}
            have = CHUNK - strm.avail_out;
						out+=have;      /* Move out pointer */
						destination_size-=have;
					} while (strm.avail_out == 0);
				in+=CHUNK;

				/* done when inflate() says it's done or we have no more input data */
      } while ( (ret != Z_STREAM_END) && (source_size != 0) );

    /* clean up and return */
    (void)inflateEnd(&strm);
    return (ret == Z_STREAM_END) ? original_dest_size-destination_size : Z_DATA_ERROR;
	}
}
