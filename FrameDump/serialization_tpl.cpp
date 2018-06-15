#include "stdafx.h"

static size_t get_size(std::ifstream& stream)
{
    const auto pos = stream.tellg();

    stream.seekg(0, std::ios::end);
    const size_t size = stream.tellg();

    stream.seekg(pos, std::ios::beg);

    return size;
}

TPL int serialize(const std::string file_name, const std::vector<T> data)
{
    std::ofstream file_stream(file_name, std::ios::binary);

    if (!file_stream.is_open())
        return RES_FAILURE;

    const auto size = data.size() * sizeof(T);

    file_stream.write(reinterpret_cast<const char*>(&data.at(0)), size);

    return RES_SUCCESS;
}
TPL int deserialize(const std::string file_name, std::vector<T>& data)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream.is_open())
        return RES_FAILURE;

    const auto size = get_size(file_stream);
    const auto count = size / sizeof(T);

    const auto load = new T[count];
    file_stream.read(reinterpret_cast<char*>(load), size);

    data = std::vector<T>(load, load + count);

    delete[] load;

    return RES_SUCCESS;
}
