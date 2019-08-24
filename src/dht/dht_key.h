#pragma once

#include <string.h>

#include "dht/dht_utils.h"

namespace lego {

namespace dht {

#pragma pack(push) 
#pragma pack(1)
union DhtKey {
    DhtKey() {
        memset(dht_key, 0, sizeof(dht_key));
    }

    struct Construct {
        uint32_t net_id;
        uint8_t country;
        uint8_t reserve1;
        uint8_t reserve2;
        uint8_t reserve3;
        char hash[24];
    } construct;
    char dht_key[32];
};
#pragma pack(pop)

class DhtKeyManager {
public:
    explicit DhtKeyManager(const std::string& str_key);
    DhtKeyManager(uint32_t net_id, uint8_t country);
    DhtKeyManager(uint32_t net_id, uint8_t country, bool rand);
    DhtKeyManager(uint32_t net_id, uint8_t country, const std::string& node_id);
    ~DhtKeyManager();
    const std::string& StrKey();
    static uint32_t DhtKeyGetNetId(const std::string& dht_key);
    static uint8_t DhtKeyGetCountry(const std::string& dht_key);
    void SetCountryId(uint8_t country) {
        dht_key_.construct.country = country;
        str_key_ = std::string(dht_key_.dht_key, sizeof(dht_key_.dht_key));
    }

private:
    DhtKey dht_key_;
    std::string str_key_;
};

}  // namespace dht

}  // namespace lego
