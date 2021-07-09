#include "Utils.h"
#include "DataPool.h"

DataPool::DataPool(){
    this->data = nullptr;
    this->length = 0;
    this->offset = 0;
}

DataPool::~DataPool(){
    Util_wipe(this->data,this->length);
    this->length = 0;
    this->offset = 0;
}

bool DataPool::cat(uint8_t* in_data, size_t in_length){
    if(!Util_catdata(&this->data,this->length,in_data,in_length,&this->length)){return false;}
    this->offset = this->length;
    return true;
}

bool DataPool::extend(size_t in_length){
    if(!Util_realloc(&this->data,this->length,this->length+in_length)){return false;}
    this->offset = this->length;
    this->length += in_length;
    return true;
}