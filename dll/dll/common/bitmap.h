#pragma once

#include <cstdint>
#include <vector>

namespace lego {

namespace common {

class Bitmap {
public:
    Bitmap(uint32_t bit_count);
    Bitmap(const std::vector<uint64_t>& data);
    ~Bitmap();
    void Set(uint32_t bit_index);
    void UnSet(uint32_t bit_index);
    bool Valid(uint32_t bit_index);
    Bitmap& operator=(const Bitmap& src);
    bool operator==(const Bitmap& r) const;

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
    uint32_t hash_count_{ 1 };
    uint32_t valid_count_{ 0 };
};

}  // namespace common

}  // namespace lego
