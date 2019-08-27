#include <cassert>

#include "common/bloom_filter.h"

namespace lego {

namespace common {

BloomFilter::BloomFilter(uint32_t bit_count, uint32_t hash_count) : hash_count_(hash_count) {
    assert((bit_count % 64) == 0);
    uint32_t data_cnt = bit_count / 64;
    for (uint32_t i = 0; i < data_cnt; ++i) {
        data_.push_back(0ull);
    }
    assert(!data_.empty());
}

BloomFilter::BloomFilter(const std::vector<uint64_t>& data, uint32_t hash_count)
        : data_(data), hash_count_(hash_count) {}

BloomFilter::~BloomFilter() {}

void BloomFilter::Add(uint64_t hash) {
    uint32_t hash_high = static_cast<uint32_t>((hash >> 32) & 0x00000000FFFFFFFF);
    uint32_t hash_low = static_cast<uint32_t>(hash & 0x00000000FFFFFFFF);
    for (uint32_t i = 0; i < hash_count_; ++i) {
        uint32_t index = (hash_high + i * hash_low);
        uint32_t vec_index = (index % (64 * data_.size())) / 64;
        uint32_t bit_index = (index % (64 * data_.size())) % 64;
        data_[vec_index] |= (uint64_t)((uint64_t)(1) << bit_index);
    }
}

bool BloomFilter::Contain(uint64_t hash) {
    uint32_t hash_high = static_cast<uint32_t>((hash >> 32) & 0x00000000FFFFFFFF);
    uint32_t hash_low = static_cast<uint32_t>(hash & 0x00000000FFFFFFFF);
    for (uint32_t i = 0; i < hash_count_; ++i) {
        uint32_t index = (hash_high + i * hash_low);
        uint32_t vec_index = (index % (64 * data_.size())) / 64;
        uint32_t bit_index = (index % (64 * data_.size())) % 64;
        if ((data_[vec_index] & ((uint64_t)((uint64_t)(1) << bit_index))) == 0ull) {
            return false;
        }
    }
    return true;
}

BloomFilter& BloomFilter::operator=(const BloomFilter& src) {
    if (this == &src) {
        return *this;
    }

    data_ = src.data_;
    hash_count_ = src.hash_count_;
    return *this;
}

bool BloomFilter::operator==(const BloomFilter& r) const {
    if (this == &r) {
        return true;
    }

    return (data_ == r.data_ && hash_count_ == r.hash_count_);
}

}  // namespace common

}  // namespace lego