#pragma once

#if ENABLE_WEBSOCKETS
#   include "glovewebsockets.hpp"
#endif

#if ENABLE_WEBSOCKETS

#include <string>
#include <chrono>
#include "glove.hpp"

class GloveWebSocketFrame
{
public:
	GloveWebSocketFrame(std::string& data);
	GloveWebSocketFrame(unsigned char opcode, std::string& data, bool fin=true, bool masked=true);
	
	std::string& data()
	{
		return _data;
	}

	bool fin()
	{
		return _fin;
	}

	bool masked()
	{
		return _masked;
	}
	
	bool error();
	bool iscontrol();
	bool isdata();
	
	std::string raw();

	unsigned short opcode() const
	{
		return _opcode;
	}
	static const unsigned char TYPE_CONT = 0x0;
	static const unsigned char TYPE_TEXT = 0x1;
	static const unsigned char TYPE_BIN = 0x2;
	static const unsigned char TYPE_CLOSE = 0x8;
	static const unsigned char TYPE_PING = 0x9;
	static const unsigned char TYPE_PONG = 0xa;
	/* All reserved non-control 0x3-0x7 and control 0xb-0xf
		 are considered errors and cannot be handled */
	static const unsigned char TYPE_ERROR = 0xf;
	
private:
	std::string _data;
	unsigned short _opcode;
	uint64_t payloadLen;
	bool frameError;
	bool _masked;
	bool _fin;
};

class GloveWebSocketData
{
public:
	GloveWebSocketData();

	void update(GloveWebSocketFrame& frame);

	unsigned char type()
	{
		return dataType;
	}
	
	std::string& data()
	{
		return _data;
	}

	std::string::size_type length()
	{
		return _data.length();
	}

	bool empty()
	{
		return _data.empty();
	}

	static const unsigned char INVALID_DATATYPE = 0xff;

private:
	/* Clears data when something comes */
	bool clearWhenData;
	unsigned char dataType;
	std::string _data;

};

class GloveWebSocketHandler
{
public:
	GloveWebSocketHandler(Glove::Client& client, uint64_t fragmentation);
	/* Send pong */
	bool pong(GloveWebSocketFrame& frame);
	/* Receive pong */
	bool pong();
	void ping(std::string data ="", std::function<void(GloveWebSocketHandler&)> callback=nullptr);
	void close(GloveWebSocketFrame& frame);
	void close(uint16_t closeCode, std::string closeMessage);
	unsigned clientId()
	{
		return _client.id();
	}
	
	unsigned char type ()
	{
		return _type;
	}

	double latency()
	{
		return _latency;	
	}
	
	unsigned char type (unsigned char type)
	{
		_type = type;
		return _type;
	}

	uint64_t fragmentation()
	{
		return _fragmentation;
	}

	uint64_t fragmentation(uint64_t val)
	{
		_fragmentation = val;
		return _fragmentation;
	}

	int send(std::string data, unsigned char type=0);
private:
	std::vector <GloveWebSocketFrame> divideMessage(unsigned char opcode, std::string& data, bool masked=true);
	Glove::Client& _client;
	unsigned char _type;
	uint64_t _fragmentation;
	bool waitingForPong;
	std::function<void(GloveWebSocketHandler&)> pongCallback;
	double _latency;
	std::chrono::time_point<std::chrono::steady_clock> temp_start;
};

#endif
