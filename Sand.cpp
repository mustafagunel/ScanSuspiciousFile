#include "Sand.h"


std::mutex g_pages_mutex;

M::Sand::Sand(Json::Value jsonData) {
	detection = jsonToStr(jsonData);
}
std::string M::Sand::jsonToStr(Json::Value jsonData) {

	Json::StreamWriterBuilder builder;
	builder["indentation"] = ""; // If you want whitespace-less output
	const std::string temp = Json::writeString(builder, jsonData);

	std::lock_guard<std::mutex> guard(g_pages_mutex);

	return temp;
}

