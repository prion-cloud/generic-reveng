#include "stdafx.h"

#include "binary_reader.h"

binary_reader::binary_reader(const char* file_name)
{
    fopen_s(&stream_, file_name, "rb");

    fseek(stream_, 0, SEEK_END);
    length_ = ftell(stream_);
    rewind(stream_);
}

void binary_reader::close() const
{
    fclose(stream_);
}

long binary_reader::length() const
{
    return length_;
}

long binary_reader::offset() const
{
    return ftell(stream_);
}

void binary_reader::seek() const
{
    seek(0);
}
void binary_reader::seek(const long offset) const
{
    seek(offset, SEEK_SET);
}
void binary_reader::seek(const long offset, const int origin) const
{
    fseek(stream_, offset, origin);
}
