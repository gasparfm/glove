/**
*************************************************************
* @file webserver.cpp
* @brief Breve descripción
* Pequeña documentación del archivo
*
*
*
*
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 03 abr 2015
* Changelog:
*
*
*
*
* Compilation:
*  $ g++ -g -o webserver webserver.cpp glovehttpserver.cpp glove.o -std=c++11 -lpthread -lcrypto -lssl
*
*************************************************************/

#include "glovehttpserver.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include "json.hpp"

int atoi(std::string s)
{
	try
		{
			return std::stod(s);
		}
	catch (std::exception &e)
		{
			return 0;
		}
}

static std::string jsonkv(std::string k, std::string v)
{
	/* "k": "v" */
	return "\""+k+"\": \""+v+"\"";
}

struct Film
{
	unsigned id;
	std::string title;
	std::string director;
	std::string stars;
	unsigned duration;
};

class Cinema
{
public:
	Cinema()
	{
	}
	~Cinema()
	{
	}

	unsigned addFilm(std::string title, std::string director,
									 std::string stars, unsigned duration)
	{
		unsigned id = currentId++;
		films.push_back({id, title, director, stars, duration});
		return id;
	}

	unsigned delFilm(unsigned id)
	{
		auto film = findFilm(id);
		if (film != films.end())
			return films.erase(film), id;
		
		return 0;
	}

	unsigned updateFilm(unsigned id, std::string title, std::string director,
											std::string stars, unsigned duration)
	{
		auto film = findFilm(id);
		if (film != films.end())
			{
				film->title = title;
				film->director = director;
				film->stars = stars;
				film->duration = duration;
				return id;
			}
		return 0;
	}

	unsigned patchFilm(unsigned id, std::string field, std::string value)
	{
		std::cout << "PATCHEO\n";
		auto film = findFilm(id);
		if (film != films.end())
			{
				std::cout << "TENGO\n";
				if (field == "title")
					film->title = value;
				else if (field == "director")
					film->director = value;
				else if (field == "stars")
					film->stars = value;
				else if (field == "duration")
					film->duration = atoi(value);
				std::cout << "PATCHEO\n";

				return id;
			}
		return 0;
	}

	std::string getFilm(unsigned id)
	{
		std::string out;
		auto film = findFilm(id);
		if (film != films.end())
			out=filmjson(*film);
		return out;
	}

	std::string getFilms()
	{
		if (films.size()==0)
			return "[\n]";
		
		std::string out;
		auto f = films.begin();
		out+=filmjson(*f);
		while (++f != films.end())
			out+=",\n"+filmjson(*f);
		return "[\n "+ out + "\n]";
	}
	
	size_t size()
	{
		return films.size();
	}
private:	
	static std::string filmjson(Film& f)
	{
		return "{ "
			+ jsonkv("id", std::to_string(f.id))+",\n"
			+ jsonkv("title", f.title)+",\n"
			+ jsonkv("director", f.director)+",\n"
			+ jsonkv("stars", f.stars)+",\n"
			+ jsonkv("duration", std::to_string(f.duration))
			+ " }";
	}
	
	std::vector<Film>::iterator findFilm(unsigned id)
	{
		for (auto f=films.begin(); f!=films.end(); ++f)
			{
				if (f->id==id)
					return f;
			}
		return films.end();
	}
	static unsigned currentId;
	std::vector<Film> films;
};

unsigned Cinema::currentId=1;

class CinemaApi
{
public:
	CinemaApi()
	{
		/* Populate database */
		films.addFilm("Doctor Strange", "Scott Derrickson", "Rachel McAdams, Benedict Cumberbatch, Mads Mikkelsen", 115);
		films.addFilm("The Magnificent Seven", "Antoine Fuqua", "Denzel Washington, Chris Pratt, Ethan Hawke", 133);
		films.addFilm("Bridget Jones' Baby", "Sharon Maguire", " Renée Zellweger, Gemma Jones, Jim Broadbent", 123);
		films.addFilm("Snowden", "Oliver Stone", " Joseph Gordon-Levitt, Shailene Woodley, Melissa Leo", 134);
		films.addFilm("Don't Breathe", "Fede Alvarez", "Stephen Lang, Jane Levy, Dylan Minnette", 88);
		films.addFilm("Suicide Squad", "David Ayer", "Will Smith, Jared Leto, Margot Robbie", 123);
	}	
	
	void get(GloveHttpRequest &request, GloveHttpResponse& response)
	{
		response.contentType("text/json");
		if (request.special["filmId"].empty())
			response << films.getFilms();
		else
			{
				auto res = films.getFilm(atoi(request.special["filmId"]));
				if (res.empty())
					throw GloveApiException(3, "No films found");
				response << res;
			}
	}

	void post(GloveHttpRequest& request, GloveHttpResponse& response)
	{
		auto jsonInput = nlohmann::json::parse(request.getData());
		auto title = jsonInput["title"];
		auto director = jsonInput["director"];
		auto stars = jsonInput["stars"];
		auto duration = jsonInput["duration"];
		if (title.is_null())
			throw GloveApiException(1, "No title given");
		if (director.is_null())
			throw GloveApiException(1, "No director given");
		if (stars.is_null())
			throw GloveApiException(1, "No stars given");
		if (duration.is_null())
			throw GloveApiException(1, "No duration given");

		unsigned id = films.addFilm(title.get<std::string>(),
																director.get<std::string>(),
																stars.get<std::string>(),
																duration.get<uint32_t>());
		if (!id)
			throw GloveApiException(1, "There was a problem adding film");
		auto targetUri = request.getUri().servicehost()+"/films/"+std::to_string(id);
		response << "{ "
						 << jsonkv("status", "ok") << ",\n"
						 << jsonkv("target", targetUri) << " }";
	}

	void put(GloveHttpRequest& request, GloveHttpResponse& response)
	{
		unsigned currentId = atoi(request.special["filmId"]);
		if (!currentId)
			throw GloveApiException(5, "Invalid id given");
		auto jsonInput = nlohmann::json::parse(request.getData());
		auto title = jsonInput["title"];
		auto director = jsonInput["director"];
		auto stars = jsonInput["stars"];
		auto duration = jsonInput["duration"];
		if (title.is_null())
			throw GloveApiException(1, "No title given");
		if (director.is_null())
			throw GloveApiException(1, "No director given");
		if (stars.is_null())
			throw GloveApiException(1, "No stars given");
		if (duration.is_null())
			throw GloveApiException(1, "No duration given");

		unsigned id = films.updateFilm(currentId,
																	 title.get<std::string>(),
																	 director.get<std::string>(),
																	 stars.get<std::string>(),
																	 duration.get<uint32_t>());
		if (!id)
			throw GloveApiException(1, "There was a problem updating the record");
		
		auto targetUri = request.getUri().servicehost()+"/films/"+std::to_string(id);
		response << "{ "
						 << jsonkv("status", "ok") << ",\n"
						 << jsonkv("target", targetUri) << " }";
	}

	void patch(GloveHttpRequest& request, GloveHttpResponse& response)
	{
		unsigned currentId = atoi(request.special["filmId"]);
		if (!currentId)
			throw GloveApiException(5, "Invalid id given");
		auto jsonInput = nlohmann::json::parse(request.getData());
		auto title = jsonInput["title"];
		auto director = jsonInput["director"];
		auto stars = jsonInput["stars"];
		auto duration = jsonInput["duration"];
		bool ok = true;
		if ( (ok) && (!title.is_null()) )
			ok = ok && films.patchFilm(currentId, "title", title.get<std::string>());
		if ( (ok) && (!director.is_null()) )
			ok = ok && films.patchFilm(currentId, "director", director.get<std::string>());
		if ( (ok) && (!stars.is_null()) )
			ok = ok && films.patchFilm(currentId, "stars", stars.get<std::string>());
		if ( (ok) && (!duration.is_null()) )
			ok = ok && films.patchFilm(currentId, "duration", std::to_string(duration.get<std::uint32_t>()));

		if (!ok)
			throw GloveApiException(1, "There was a problem updating the record");
		
		auto targetUri = request.getUri().servicehost()+"/films/"+std::to_string(currentId);
		response << "{ "
						 << jsonkv("status", "ok") << ",\n"
						 << jsonkv("target", targetUri) << " }";
	}

	void delet(GloveHttpRequest& request, GloveHttpResponse& response)
	{
		unsigned currentId = atoi(request.special["filmId"]);
		if (!currentId)
			throw GloveApiException(5, "Invalid id given");

		if (!films.delFilm(currentId))
			throw GloveApiException(8, "There was a problem deleting the record");

		response << "{ "+jsonkv("status", "ok")+" }";
	}

private:
	Cinema films;
};

int main(int argc, char *argv[])
{
	CinemaApi cine;

  GloveHttpServer serv(8080, "", 2048);
	serv.compression("gzip, deflate");
	namespace ph = std::placeholders;
  /* serv.addRoute("/films/$filmId", restFilm, 2, 1, { "GET", "POST", "PUT", "PATCH", "DELETE" }); */
	serv.addRest("/films/$filmId", 1,
							 GloveHttpServer::jsonApiErrorCall,
							 std::bind(&CinemaApi::get, &cine, ph::_1, ph::_2),
							 std::bind(&CinemaApi::post, &cine, ph::_1, ph::_2),
							 std::bind(&CinemaApi::put, &cine, ph::_1, ph::_2),
							 std::bind(&CinemaApi::patch, &cine, ph::_1, ph::_2),
							 std::bind(&CinemaApi::delet, &cine, ph::_1, ph::_2)
	);
  std::cout << "READY"<<std::endl;
  while(1)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }

  std::cout << "TEST"<<std::endl;

}

