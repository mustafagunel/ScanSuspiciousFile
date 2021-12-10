#pragma once
#include <string>

#include <json/value.h>
#include <json/json.h>

#include <mutex>

namespace M {

	class Sand {
		public:
			std::string link = "";
			std::string detection = "";
			Sand(Json::Value jsonData);

			std::string jsonToStr(Json::Value jsonData);

	};
	
	class Cert : public Sand {
		public:

			Cert(Json::Value jsonData)
				: Sand(jsonData["detection"]) {
				link = jsonToStr(jsonData["link"]);
			}
	};
	class AnyRun : public Sand {
		public:
			AnyRun(Json::Value jsonData)
				: Sand(jsonData[0]["verdict"]) {

			}
	};
	class Yoroi :public Sand {
		public:
			std::string score;
		
			Yoroi(Json::Value jsonData)
				: Sand(jsonData["detection"]) {
				score = jsonToStr(jsonData["score"]);
			}
	};
	class VxCube:public Sand {
		public:
			std::string maliciousness;
			std::string behaviour[11][2] = {"threat_level","rule"};

			VxCube(Json::Value jsonData)
				: Sand(jsonData["detection"]) {
				maliciousness = jsonToStr(jsonData["maliciousness"]);

				for (int i = 0; i < jsonData["behaviour"].size(); i++) {
					if (i == 10) {
						break;
					}
					behaviour[i+1][0] = jsonToStr(jsonData["behaviour"][i]["threat_level"]);
					behaviour[i+1][1] = jsonToStr(jsonData["behaviour"][i]["rule"]);
				}

			}
			
	};
	class Intezer:public Sand {
		public:
			std::string familyName;

			Intezer(Json::Value jsonData)
				: Sand(jsonData["verdict"]) {
				familyName = jsonToStr(jsonData["family_name"]);
				link = jsonToStr(jsonData["analysis_url"]);

			}
	};
	class InQuest:public Sand {
		public:
			std::string details[11][3] = {"Category", "Title", "Description"};

			InQuest(Json::Value jsonData)
				: Sand(jsonData["verdict"]) {
				link = jsonToStr(jsonData["url"]);
				for (int i = 0; i < jsonData["details"].size();i++) {
					if (i == 10) 
						break;
					details[i + 1][0] = jsonToStr(jsonData["details"][i]["category"]);
					details[i + 1][1] = jsonToStr(jsonData["details"][i]["title"]);
					details[i + 1][2] = jsonToStr(jsonData["details"][i]["description"]);
				}
			}
	};
	class Cape:public Sand {
		public:
			Cape(Json::Value jsonData)
				: Sand(jsonData["detection"]) {
				link = jsonToStr(jsonData["link"]);
			}
	};
	class Triage:public Sand {
		public:
			std::string malwareFamily;
			std::string score;
			std::string tags;
			std::string malwareConfig[11][3] = {"Extraction","Family", "c2 Server"};

			Triage(Json::Value jsonData)
				: Sand(jsonData["malware_family"]) {
				link = jsonToStr(jsonData["link"]);
				malwareFamily = jsonToStr(jsonData["malware_family"]);
				score = jsonToStr(jsonData["score"]);
				tags = jsonToStr(jsonData["tags"]);

				for (int i = 0; i < jsonData["malware_config"].size(); i++) {
					if (i == 10)
						break;
					malwareConfig[i + 1][0] = jsonToStr(jsonData["malware_config"][i]["extraction"]);
					malwareConfig[i + 1][1] = jsonToStr(jsonData["malware_config"][i]["family"]);
					malwareConfig[i + 1][2] = jsonToStr(jsonData["malware_config"][i]["c2"]);
				}

			}
	};

	class ReversingLabs:public Sand {
		public:
			/* Ayarlanmadý! */
			ReversingLabs(Json::Value jsonData)
				: Sand(jsonData["threat_name"]) {

			}
	};

	class UnpackMe:public Sand {
		public:
			/* Ayarlanmadý! */
			UnpackMe(Json::Value jsonData)
				: Sand(jsonData[0]["detections"]) {

			}
	};
	class VMRay:public Sand {
		public:
			std::string malwareFamily;
			VMRay(Json::Value jsonData)
				: Sand(jsonData["verdict"]) {
				link = jsonToStr(jsonData["report_link"]);
				malwareFamily = jsonToStr(jsonData["malware_family"]);
			}
	};
	class FileScanIO:public Sand {
		public:
			/* Ayarlanmadý! */
			FileScanIO(Json::Value jsonData)
				: Sand(jsonData) {
				link = jsonToStr(jsonData["report_link"]);
			}
	};
}