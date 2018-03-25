#include "stdafx.h"

#include "bin_dump.h"

std::vector<char> create_dump(std::string file_name)
{
    const auto file = fopen(file_name.c_str(), "rb");

    fseek(file, 0, SEEK_END);
    const auto length = ftell(file);
    rewind(file);

    const auto buffer = static_cast<char*>(malloc(length));
    fread(buffer, sizeof(char), length, file);
    fclose(file);
    const auto bytes = std::vector<char>(buffer, buffer + length);
    free(buffer);

    return bytes;
}
