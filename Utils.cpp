//
// Created by merca on 5/8/2019.
//

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <cstdarg>
#include <debugapi.h>
#include "Utils.h"


bool Util_wipe(uint8_t* data, ssize_t length){
    if(data == nullptr){return false;}
    if(length < 1){return false;}
    memset(data,0x00,length);
    free(data);
    data = nullptr;
    return true;
}

bool Util_alloc(uint8_t** bptr, size_t length){
    if(bptr == nullptr){return false;}
    *bptr = (uint8_t*)calloc(1,length);
    if(*bptr == nullptr){return false;}
    return true;
}

bool Util_realloc(uint8_t** data, size_t old_length, size_t n_length){
    if(data == nullptr){ return false;}
    *data = (uint8_t*)realloc(*data,n_length);
    if(*data == nullptr){return false;}
    if(n_length > old_length){
        memset(*data+old_length,0x00,(n_length - old_length));
    }
    return true;
}

bool Util_catdata(uint8_t** bsrc_data, size_t old_length, uint8_t* add_data, size_t add_length, size_t* new_length){
    if(bsrc_data == nullptr){return false;}
    if(*bsrc_data == nullptr){
        Util_alloc(bsrc_data,add_length);
        memcpy(*bsrc_data,add_data,add_length);
        *new_length = add_length;
        return true;
    }
    void* np = realloc((void*)*bsrc_data, old_length + add_length);
    if(!np){return false;}

    *bsrc_data = (uint8_t*)np;
    memcpy(*bsrc_data+old_length,add_data,add_length);
    *new_length = old_length + add_length;
    return true;
}

void Utils_printfDBG(const char *format, ...) {

    char s[8192];
    va_list args;
    ZeroMemory(s, 8192 * sizeof(s[0]));
    va_start(args, format);
    vsprintf(s, format, args);
    va_end(args);
    s[8191] = 0;
    OutputDebugString(s);
}


void Utils_print_bufferDBG(unsigned char* data, unsigned int len) {
    unsigned char* msgb = (unsigned char*)malloc(len + 1);
    msgb[len] = 0x00;
    for (unsigned int i = 0; i < len; i++) {
        sprintf((char*)msgb + i, "%02X", data[i]);

    }
    Utils_printfDBG("%s", msgb);
    free(msgb);
    Utils_printfDBG("\n");
}