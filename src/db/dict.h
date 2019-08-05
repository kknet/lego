#pragma once

#include "db.h"

namespace lego {

namespace db {

class Dict {
public:
    static Dict* Instance();
    bool Hset(const std::string& key, const std::string& field, const std::string& value);
    bool Hget(const std::string& key, const std::string& field, std::string* value);
    bool Hdel(const std::string& key, const std::string& field);

private:
    Dict() {};
    ~Dict() {};
    Dict(const Dict&);
    Dict(const Dict&&);
    Dict& operator=(const Dict&);
};

}  // db

}  // lego
