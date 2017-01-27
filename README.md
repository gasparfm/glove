glove
=====

C++11 sockets TCP wrapper

What you can do
---------------
  - Create client and server for modern C++ applications in a few lines:
	  - You can read/write data with << , >> operators
		- You can define how to read/write data
	- Use SSL connections (with openSSL) in a transparent way:
	  - Just give Glove a certificate file and a key for servers.
		- Just indicate it's a secure connections (or autodetect) for clients (example4.cc)
  - Create dynamic web applications in C++:
	  - Just define and endpoint and give a callback to it (webserver.cc)
		- Support for RESTful API (apiexample.cc) giving a callback for each valid method.
		- Create WebSockets services (glovewsecho.cc , glovewschat.cc)
	- Read/Write multipart data (example and integration with HTTP server on the way)
	  
--
Notes:
  - json.hpp from https://github.com/nlohmann/json added to compile some examples
