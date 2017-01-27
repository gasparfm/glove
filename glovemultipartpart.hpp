#pragma once

#include <string>
#include <map>
#include <vector>

class GloveMultipartPart
{
public:
// Content-Type: xxxxxxx; charset=yyyy
// Content-Disposition: xxxxxxxx; name="name"; filename="filename"
	struct Meta
	{
		std::string name;
		std::string value;
		std::map < std::string, std::string > extra;
	};
	
	GloveMultipartPart(std :: string & content, std :: vector < Meta > meta);
	GloveMultipartPart(std::string& content, bool parse);
	GloveMultipartPart(char* content, bool parse);
  GloveMultipartPart(std::string& content, std::string contentType="", std::string contentDisposition="", std::string contentTransferEncoding=""); 
	GloveMultipartPart(const GloveMultipartPart& old);
  ~GloveMultipartPart();

	std::string debugMeta();
	std::string getMeta(std::string name, std::string attribute="*");
	std::string contentType()
	{
		return this->getMeta("Content-Type");
	}
	
	std::string contentDisposition()
	{
		return this->getMeta("Content-Disposition");
	}

	std::string contentTransferEncoding()
	{
		return this->getMeta("Content-Transfer-Encoding");
	}
	
	std::string str();
	std::string content()
	{
		return std::string(_content, _contentSize);
	}

protected:
	void init(std::string& content, std::vector<Meta> meta);
	void parseContent(std::string& content);
	std::string metaInfo(const Meta& meta, bool full=false);
	bool parseMeta(Meta& meta, std::string inputStr, std::string metaName="");

	/* Attributes */
  char* _content;
	long long unsigned _contentSize;
	std::vector<Meta> metaData;
};
