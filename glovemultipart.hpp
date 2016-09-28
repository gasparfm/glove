#pragma once

#include <string>
#include <vector>
#include "glovemultipartpart.hpp"

class GloveMultipart
{
public:
  GloveMultipart(std::string boundary);
	GloveMultipart(std::string data, std::string boundary);
  ~GloveMultipart();

	void add(GloveMultipartPart part);
	void add(const char* data);
	void add(std::string &data);
	void add(std::string contentType, std::string content, std::string contentTransferEncoding, std::string contentDisposition="");

	unsigned count()
	{
		return parts.size();
	}

	GloveMultipartPart& getPart(unsigned num);
	
	std::string str();
	
	std::string boundary()
	{
		return _boundary;
	}
protected:
	void parse(std::string &data, std::string boundary);
  std::vector<GloveMultipartPart> parts;
	std::string _boundary;

};
