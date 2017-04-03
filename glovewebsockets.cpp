/**
*************************************************************
* @file glovewebsockets.cpp
* @brief Basic WebSockets support for Glove
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 30 sep 2016
*
* Changelog:
*  20161001 : Initial release
* 
* To-do:
*   - Apply support for some extensions
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

#include "glovewebsockets.hpp"

#if ENABLE_WEBSOCKETS

#include <netinet/in.h>

/* Process Web Socket Frame. Extracted from RFC6455:
	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-------+-+-------------+-------------------------------+
	 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
	 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
	 | |1|2|3|       |K|             |                               |
	 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	 |     Extended payload length continued, if payload len == 127  |
	 + - - - - - - - - - - - - - - - +-------------------------------+
	 |                               |Masking-key, if MASK set to 1  |
	 +-------------------------------+-------------------------------+
	 | Masking-key (continued)       |          Payload Data         |
	 +-------------------------------- - - - - - - - - - - - - - - - +
	 :                     Payload Data continued ...                :
	 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	 |                     Payload Data continued ...                |
	 +---------------------------------------------------------------+
*/
GloveWebSocketFrame::GloveWebSocketFrame(std::string& data):frameError(true)
{
	auto len = data.length();
	auto d = (unsigned char*)&data[0];
	auto dorig = d;
	if (len<4)
		return;

	_fin = (d[0] > 127);
	_opcode = d[0] & 0x0f;
	_masked = (d[1] > 127);
	uint64_t pllength = *++d & 0x7f; /* d[1]*/
	uint64_t pllength2 = 0;
	uint64_t pllength3 = 0;
	payloadLen=pllength;
	unsigned char mask[4];

	if (pllength>=126)
		{
			if (d-dorig+2 > len) return;		
			pllength2= (*++d<<8)+*++d; /* d[2] , d[3]*/
			payloadLen=pllength2;
		}
	if (pllength==127)
		{
			if (d-dorig+6 > len) return;
			pllength3= ((uint64_t)*++d<<40)+((uint64_t)*++d<<32)+(*++d<<24)+(*++d<<16)+(*++d<<8)+*++d; /* d[4]...d[9] */
			payloadLen=pllength2<<56;
		}

	if (_masked)
		{
			if (d-dorig+4 > len) return;
			mask[0] = *++d;	mask[1] = *++d;	mask[2] = *++d;	mask[3] = *++d;
		}

	if (++d-dorig > len) return; /* Bad payload length */

	if (!_masked)
		_data = data.substr(d-dorig, payloadLen);
	else
		{
			/* Unmask data */
			short loops=0;
			while (payloadLen--)
				{
					_data+= (*(d++) ^ mask[loops++]);
					loops%=4;
				}
		}

	if ( (_opcode != TYPE_CONT) &&
			 (_opcode != TYPE_TEXT) &&
			 (_opcode != TYPE_BIN) &&
			 (_opcode != TYPE_CLOSE) &&
			 (_opcode != TYPE_PING) &&
			 (_opcode != TYPE_PONG))
		return;
	frameError= false;
}

GloveWebSocketFrame::GloveWebSocketFrame(unsigned char opcode, std::string& data, bool fin, bool masked):_fin(fin), _masked(masked), _opcode(opcode), payloadLen(data.length()), _data(data)
{
}

bool GloveWebSocketFrame::error()
{
	if (frameError)
		{
			_data.clear();
			return true;
		}
	return false;
}

/* Gets frame data to send a client/server */
std::string GloveWebSocketFrame::raw()
{
	std::string out;
	unsigned char byte = _opcode + ((_fin)?128:0);
	unsigned char* mask;
	out+=byte;
	byte  = (_masked)?128:0;
	if (payloadLen<126)
		{
			byte += payloadLen;
			out+=byte;
		}	
	else if (payloadLen<65535)
		{
			byte+=126;
			out+=byte;
			uint16_t _len = htons(payloadLen);
			char *len = (char*)&_len;
			out+={len[0], len[1]};
		}
	else if (payloadLen<std::numeric_limits<uint64_t>::max())
		{
			byte+=127;
			out+=byte;
			/* network byte order */
			uint64_t _len = ((((uint64_t)htonl(payloadLen)) << 32) + htonl((payloadLen) >> 32));
			char* len = (char*)&_len;
			out+={len[0], len[1], len[2], len[3],
					len[4], len[5], len[6], len[7]};
		}

	if (_masked)
		{
			uint32_t __mask = rand()%65536 * (1+rand()%65535);
			mask = (unsigned char*)&__mask;
			out+=mask[0] + mask[1] + mask[2] + mask[3];			 
			auto d = (unsigned char*)&_data[0];
			short loops=0;
			while (payloadLen--)
				{
					out+= ((*d++) ^ mask[loops++]);
					loops%=4;
				}				
		}
	else
		out+=std::move(_data);
	/* Not checking opcode */

	return std::move(out);
}

bool GloveWebSocketFrame::iscontrol()
{
	return ( (_opcode>=0x08) && (_opcode<=0x0a) );
}

bool GloveWebSocketFrame::isdata()
{
	return ( (_opcode>=0x00) && (_opcode<=0x02) );
}

/* --- GloveWebSocketData --- */

GloveWebSocketData::GloveWebSocketData():clearWhenData(true), dataType(INVALID_DATATYPE)
{
}

void GloveWebSocketData::update(GloveWebSocketFrame& frame)
{
	if (clearWhenData)
		{
			_data.clear();
			dataType = INVALID_DATATYPE;				
		}
	/* If type is CONT, preserve last dataType. If CONT comes
		 with clearWhenData = 1, INVALID_DATATYPE will be the type,
		 so the callback will know there is a problem with received
		 info. */
	if (frame.opcode() != GloveWebSocketFrame::TYPE_CONT)
		dataType = frame.opcode();
	_data+=frame.data();
}

/* --- GloveWebSocketHandler --- */

GloveWebSocketHandler::GloveWebSocketHandler(Glove::Client& client, uint64_t fragmentation):_client(client), _fragmentation(fragmentation), waitingForPong(false), _latency(0), _type(GloveWebSocketFrame::TYPE_TEXT)
{
}

bool GloveWebSocketHandler::pong(GloveWebSocketFrame& frame)
{
	GloveWebSocketFrame f(GloveWebSocketFrame::TYPE_PONG, frame.data(), true, false);
	_client << f.raw();
	return true;
}

bool GloveWebSocketHandler::pong()
{
	if (!waitingForPong)
		return false;
	waitingForPong = false;
	_latency = (double) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - temp_start).count();
	if (pongCallback != nullptr)
		pongCallback(*this);
}

void GloveWebSocketHandler::ping(std::string data, std::function<void(GloveWebSocketHandler&)> callback)
{
	waitingForPong = true;
	temp_start = std::chrono::steady_clock::now();
	pongCallback = callback;
	GloveWebSocketFrame f(GloveWebSocketFrame::TYPE_PING, data, true, false);
	_client << f.raw();
}


void GloveWebSocketHandler::close(GloveWebSocketFrame& frame)
{
	GloveWebSocketFrame f(GloveWebSocketFrame::TYPE_CLOSE, frame.data(), true, false);
	_client << f.raw();
}

int GloveWebSocketHandler::send(std::string data, unsigned char type)
{
	if (type == 0)
		type = _type;
	
	std::vector <GloveWebSocketFrame> frames = divideMessage(type, data, false);
	for (auto f:  frames)
		{
			_client << f.raw();
		}
}

std::vector <GloveWebSocketFrame> GloveWebSocketHandler::divideMessage(unsigned char opcode, std::string& data, bool masked)
{
	auto len = data.length();
	std::vector<GloveWebSocketFrame> frames;
	bool fin;

	while (len)
		{
			auto _data = data.substr(0, (_fragmentation>len)?len:_fragmentation);
			data = (len>_fragmentation)?data.substr(_fragmentation):"";
			fin = (data.empty());
			frames.push_back(GloveWebSocketFrame(opcode, _data, fin, masked));
			opcode = GloveWebSocketFrame::TYPE_CONT;
			len = data.length();
		}
	return frames;
}

void GloveWebSocketHandler::close(uint16_t closeCode, std::string closeMessage)
{
	auto closeBytes = (unsigned char*)&closeCode;
	std::string data;
	data += closeBytes[0];
	data += closeBytes[1];
	data+=closeMessage;
	GloveWebSocketFrame f(GloveWebSocketFrame::TYPE_CLOSE, data, true, false);
	_client << f.raw();
}

#endif
