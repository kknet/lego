#include "ip/cidr.h"

#include <cstdlib>
#include <cassert>
#include <bitset>

#include "common/split.h"
#include "common/string_utils.h"

namespace lego {

namespace ip {

Cidr::Cidr() {}

Cidr::~Cidr() {}

in_addr_t Cidr::Netmask(int prefix) {
    return prefix == 0 ? 0 : ~(in_addr_t)0 << (32 - prefix);
}

in_addr_t Cidr::atoh(char *s) {
    struct in_addr in;
    if (inet_aton(s, &in) == 0) {
        assert(false);
        exit(0);
    }
    return ntohl(in.s_addr);
}

void Cidr::ParseCidr(in_addr_t *addr, in_addr_t *mask, char *str) {
    char *p;
    int prefix;

    prefix = 32;
    p = strchr(str, '/');
    if (p != NULL) {
        *p = '\0';
        prefix = atoi(p + 1);
        if (prefix < 0) {
            prefix = 0;
        }

        if (prefix > 32) {
            prefix = 32;
        }
    }
    *addr = atoh(str);
    *mask = Netmask(prefix);
}

int Cidr::Init(const std::string& file_path) {
    FILE *fp = fopen(file_path.c_str(), "r");
    if (fp == NULL) {
        IP_ERROR("open ip file[%s] failed!", file_path.c_str());
        return kIpError;
    }

    char buf[128];
    in_addr_t addr;
    in_addr_t mask;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        common::Split spliter(buf, '\t');
        if (spliter.Count() != 2) {
            continue;
        }

        common::Split mask_split(spliter[0], '/');
        ParseCidr(&addr, &mask, spliter[0]);
        uint32_t prefix = addr & mask;
        cicd_map_[prefix] = std::make_pair(atoi(spliter[1]),atoi(mask_split[1])) ;
    }
    fclose(fp);
    return kIpSuccess;
}

uint32_t Cidr::GetGeoId(const std::string& ip) {
    in_addr_t addr = atoh((char*)ip.c_str());
    for (uint32_t i = 32; i > 6; --i) {
        in_addr_t mask = Netmask(i);
        uint32_t prefix = addr & mask;
        auto iter = cicd_map_.find(prefix);
        if (iter != cicd_map_.end() && iter->second.second == i) {
            return iter->second.first;
        }
    }
    return 0;
}

}  // namespace ip

}  // namespace lego
