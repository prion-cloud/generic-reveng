#include <algorithm>

#include <unimage/utf8_base.hpp>

size_t get_utf8_char_size(char const indicator_byte)
{
    if ((indicator_byte & 0x80) == 0x00)
        return 1;

    if ((indicator_byte & 0xE0) == 0xC0)
        return 2;

    if ((indicator_byte & 0xF0) == 0xE0)
        return 3;

    if ((indicator_byte & 0xF8) == 0xF0)
        return 4;

    return 0;
}

size_t measure_utf8_string_size(std::string const& byte_string)
{
    return std::count_if(byte_string.cbegin(), byte_string.cend(), get_utf8_char_size);
}

utf8_char::utf8_char(std::string const& byte_string)
{
    value = byte_string.substr(0, get_utf8_char_size(byte_string.front()));
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
