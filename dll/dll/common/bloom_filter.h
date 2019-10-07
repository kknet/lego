#pragma once

#include <cstdint>
#include <vector>

namespace lego {

namespace common {

class BloomFilter {
public:
    BloomFilter(uint32_t bit_count, uint32_t hash_count);
    BloomFilter(const std::vector<uint64_t>& data, uint32_t hash_count);
    ~BloomFilter();
    void Add(uint64_t hash);
    bool Contain(uint64_t hash);
    BloomFilter& operator=(const BloomFilter& src);
    bool operator==(const BloomFilter& r) const;

    const std::vector<uint64_t>& data() const {
        return data_;
    }

    uint32_t hash_count() {
        return hash_count_;
    }

    uint32_t valid_count() {
        return valid_count_;
    }

private:
    std::vector<uint64_t> data_;
    uint32_t hash_count_{ 0 };
    uint32_t valid_count_{ 0 };
};

}  // namespace common

}  // namespace lego
