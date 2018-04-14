#include "stdafx.h"
#include "macro.h"

#include "bin_dump.h"

int create_filedump(std::string file_name, std::vector<char>& bytes)
{
    struct stat buf;
    E_ERR(stat(file_name.c_str(), &buf));

    FILE* file;
    E_ERR(fopen_s(&file, file_name.c_str(), "rb"));

    E_ERR(fseek(file, 0, SEEK_END));
    const auto length = ftell(file);
    rewind(file);

    const auto buffer = static_cast<char*>(malloc(length));
    fread(buffer, sizeof(char), length, file);
    E_ERR(fclose(file));

    bytes = std::vector<char>(buffer, buffer + length);
    free(buffer);

    return R_SUCCESS;
}

int create_dumpfile(std::string file_name, std::vector<char> bytes)
{
    FILE* file;
    E_ERR(fopen_s(&file, file_name.c_str(), "wb"));

    fwrite(&bytes[0], sizeof(char), bytes.size(), file);
    E_ERR(fclose(file));

    return R_SUCCESS;
}
