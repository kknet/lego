#pragma once

#include <mutex>
#include <memory>

#include "leveldb/db.h"

namespace lego {

namespace db {

class Db {
public:
    static Db* Instance();
    bool Init(const std::string& db_path);
    leveldb::Status Put(const std::string& key, const std::string& value);
    leveldb::Status Get(const std::string& key, std::string* value);
    leveldb::Status Delete(const std::string& key);
    bool Exist(const std::string& key);

private:
    Db();
    ~Db();
    Db(const Db&);
    Db(const Db&&);
    Db& operator=(const Db&);

    bool inited_;
    std::mutex mutex;
    std::shared_ptr<leveldb::DB> db_;
};

}  // db

}  // lego
