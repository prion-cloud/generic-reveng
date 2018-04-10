#include "stdafx.h"
#include "macro.h"

#include "bin_dump.h"

int create_dump(std::string file_name, std::vector<char>& bytes)
{
    struct stat buf;
    if (stat(file_name.c_str(), &buf))
        return F_FAILURE;

    const auto file = fopen(file_name.c_str(), "rb");

    fseek(file, 0, SEEK_END);
    const auto length = ftell(file);
    rewind(file);

    const auto buffer = static_cast<char*>(malloc(length));
    fread(buffer, sizeof(char), length, file);
    fclose(file);
    bytes = std::vector<char>(buffer, buffer + length);
    free(buffer);

    return F_SUCCESS; // TODO: F_FAILURE
}
