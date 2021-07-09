#pragma once
#include <cstdint>
bool Util_wipe(uint8_t* data, ssize_t length);
bool Util_alloc(uint8_t** bptr, size_t length);
bool Util_realloc(uint8_t** data, size_t old_length, size_t n_length);
bool Util_catdata(uint8_t** bsrc_data, size_t old_length, uint8_t* add_data, size_t add_length, size_t* new_length);
void Utils_printfDBG(const char *format, ...);
void Utils_print_bufferDBG(unsigned char* data, unsigned int len);