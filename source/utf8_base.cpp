#include <algorithm>

#include <unimage/utf8_base.hpp>

size_t get_utf8_char_size(unsigned char const indicator_byte)
{
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

size_t measure_utf8_string_size(std::string const& byte_string)
{
    return std::count_if(byte_string.cbegin(), byte_string.cend(), ::get_utf8_char_size);
}

utf8_char::utf8_char(std::string const& byte_string)
{
    std::string::size_type value_pos = 0;

    std::string const escape_start = "\x1B[";
    if (byte_string.compare(0, escape_start.size(), escape_start) == 0)
    {
        auto const escape_end_pos = byte_string.find_first_of('m');
        if (escape_end_pos != std::string::npos)
        {
            value += byte_string.substr(0, escape_end_pos + 1);
            value_pos = escape_end_pos + 1;
        }
    }

    if (value_pos >= byte_string.size())
    {
        value += ' ';
        return;
    }

    value += byte_string.substr(value_pos, ::get_utf8_char_size(byte_string.at(value_pos)));
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
