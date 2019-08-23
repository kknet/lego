#pragma once

#include "common/country_code.h"
#include "ip/ip_utils.h"
#include "ip/cidr.h"

namespace lego {

namespace ip {

class IpWithCountry {
public:
    static IpWithCountry* Instance();
    int Init(const std::string& geolite_path, const std::string& geo_country_path);
    uint8_t GetCountryUintCode(const std::string& ip);
    std::string GetCountryCode(const std::string& ip);

private:
    IpWithCountry();
    ~IpWithCountry();
    int LoadGeoCountry(const std::string& geo_country_path);

    Cidr cidr_;
    std::unordered_map<uint32_t, std::string> country_geo_code_map_;

    DISALLOW_COPY_AND_ASSIGN(IpWithCountry);
};

}  // namespace ip

}  // namespace lego
