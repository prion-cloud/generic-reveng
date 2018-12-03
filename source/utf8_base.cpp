#include <algorithm>
#include <cstring>

#include <unimage/utf8_base.hpp>

template <typename SizePredicate>
void project_string(std::string const& source, std::string* destination, SizePredicate get_size)
{
    auto const pos = destination->size();
    destination->append(source.substr(pos, get_size(source, pos)));
}

std::string::size_type get_escaped_size(std::string const& byte_string, std::string::size_type const pos = 0)
{
    auto constexpr escape_begin = "\x1B[";
    auto constexpr escape_end = "m";

    auto const escape_begin_size = std::strlen(escape_begin);

    auto cur_pos = pos;
    while (byte_string.compare(cur_pos, escape_begin_size, escape_begin) == 0)
    {
        auto const end_pos = byte_string.find(escape_end, cur_pos + escape_begin_size);

        if (end_pos == std::string::npos)
            return std::string::npos;

        cur_pos = end_pos + 1;
    }

    if (cur_pos == byte_string.size())
        return std::string::npos;

    return cur_pos - pos;
}
std::string::size_type get_utf8_char_size(std::string const& byte_string, std::string::size_type const pos = 0)
{
    auto const indicator_byte = byte_string.at(pos);

    if ((indicator_byte & 0x80u) == 0x00u)
        return 1;

    if ((indicator_byte & 0xE0u) == 0xC0u)
        return 2;

    if ((indicator_byte & 0xF0u) == 0xE0u)
        return 3;

    if ((indicator_byte & 0xF8u) == 0xF0u)
        return 4;

    return 0;
}

size_t measure_utf8_string_size(std::string byte_string)
{
    size_t size = 0;
    while (!byte_string.empty())
    {
        byte_string.erase(0, ::get_escaped_size(byte_string));

        if (byte_string.empty())
            break;

        byte_string.erase(0, ::get_utf8_char_size(byte_string));

        ++size;
    }

    return size;
}

utf8_char::utf8_char(std::string const& byte_string)
{
    ::project_string(byte_string, &value, ::get_escaped_size);
    ::project_string(byte_string, &value, ::get_utf8_char_size);
    ::project_string(byte_string, &value, ::get_escaped_size);
}

std::ostream& operator<<(std::ostream& stream, std::vector<std::vector<utf8_char>> utf8_illustration)
{
    for (size_t y = 0; y < utf8_illustration.size(); ++y)
    {
        if (y > 0)
            stream << '\n';

        for (auto const& utf8_char : utf8_illustration.at(y))
            stream << utf8_char.value;
    }

    return stream;
}
