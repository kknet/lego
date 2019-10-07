#include "stdafx.h"
#include "ip/ip_with_country.h"

#include "common/split.h"
#include "common/string_utils.h"

namespace lego {

namespace ip {

IpWithCountry* IpWithCountry::Instance() {
    static IpWithCountry ins;
    return &ins;
}

int IpWithCountry::Init(
    const std::string& geolite_path,
        const std::string& geo_country_path) {
    if (cidr_.Init(geolite_path) != kIpSuccess) {
        return kIpError;
    }

    if (LoadGeoCountry(geo_country_path) != kIpSuccess) {
        return kIpError;
    }
    return kIpSuccess;
}

int IpWithCountry::LoadGeoCountry(const std::string& geo_country_path) {
    FILE *fp = fopen(geo_country_path.c_str(), "r");
    if (fp == NULL) {
        IP_ERROR("open ip file[%s] failed!", geo_country_path.c_str());
        return kIpError;
    }

    char buf[128];
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        common::Split spliter(buf, '\t');
        if (spliter.Count() != 2) {
            continue;
        }

        auto geoid = atoi(spliter[0]);
        std::string country = spliter[1];
        common::StringUtil::Trim(country);
        assert(country.size() == 2);
        country_geo_code_map_[geoid] = country;
    }
    fclose(fp);
    return kIpSuccess;
}

uint8_t IpWithCountry::GetCountryUintCode(const std::string& ip) {
    auto geo_id = cidr_.GetGeoId(ip);
    if (geo_id != 0) {
        auto iter = country_geo_code_map_.find(geo_id);
        if (iter != country_geo_code_map_.end()) {
            auto citer = common::global_country_map.find(iter->second);
            if (citer != common::global_country_map.end()) {
                return citer->second;
            }
        }
    }
    return kInvalidCountryCode;
}

std::string IpWithCountry::GetCountryCode(const std::string& ip) {
    auto geo_id = cidr_.GetGeoId(ip);
    if (geo_id != 0) {
        auto iter = country_geo_code_map_.find(geo_id);
        if (iter != country_geo_code_map_.end()) {
            return iter->second;
        }
    }
    return "";
}

IpWithCountry::IpWithCountry() {}

IpWithCountry::~IpWithCountry() {}

}  // namespace ip

}  // namespace lego
