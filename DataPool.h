#pragma once

#include <cstdint>

class DataPool{
public:
    uint8_t* data;
    size_t length;
    size_t offset;
    DataPool();
    ~DataPool();
    bool cat(uint8_t * in_data, size_t in_length);
    bool extend(size_t in_length);
};
