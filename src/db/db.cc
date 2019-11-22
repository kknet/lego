#include "stdafx.h"
#include "db/db.h"

#include <iostream>

#include "leveldb/options.h"
#include "leveldb/slice.h"
#include "leveldb/status.h"
#include "leveldb/write_batch.h"
#include "leveldb/cache.h"
#include "leveldb/filter_policy.h"

#include "common/utils.h"
#include "common/log.h"

namespace lego {

namespace db {

Db::Db() : inited_(false), mutex(), db_() {
}

Db::~Db() {
}

Db* Db::Instance() {
    static Db db;
    return &db;
}

bool Db::Init(const std::string& db_path) {
    if (inited_) {
        ERROR("storage db is inited![%s]", db_path.c_str());
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex);
    if (inited_) {
        ERROR("storage db is inited![%s]", db_path.c_str());
        return false;
    }

    leveldb::Options options;
    options.compression = leveldb::kSnappyCompression;
    options.block_cache = leveldb::NewLRUCache(10 * 1024 * 1024);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.create_if_missing = true;
    leveldb::DB* db = NULL;
    leveldb::Status status = leveldb::DB::Open(options, db_path, &db);
    if (!status.ok()) {
        ERROR("open db[%s] failed, error[%s]", db_path.c_str(), status.ToString().c_str());
        return false;
    }

    db_.reset(db);
    inited_ = true;
    return true;
}

leveldb::Status Db::Put(const std::string& key, const std::string& value) {
    leveldb::WriteOptions write_opt;
    return db_->Put(write_opt, leveldb::Slice(key), leveldb::Slice(value));
}

leveldb::Status Db::Get(const std::string& key, std::string* value) {
    leveldb::ReadOptions read_opt;
    return db_->Get(read_opt, leveldb::Slice(key), value);
}

leveldb::Status Db::Delete(const std::string& key) {
    leveldb::WriteOptions write_opt;
    return db_->Delete(write_opt, leveldb::Slice(key));
}

bool Db::Exist(const std::string& key) {
    leveldb::Iterator* it = db_->NewIterator(leveldb::ReadOptions());
    it->Seek(key);
    if (it->Valid() && it->key().ToString() == key) {
        return true;
    }
    return false;
}

}  // db

}  // lego
