#include <algorithm>
#include <sstream>

#include "../include/scout/utf8_canvas.h"

size_t indicate_utf8_char_size(char const indicator_byte_char)
{
    if ((indicator_byte_char & 0x80) == 0x00)
        return 1;

    if ((indicator_byte_char & 0xE0) == 0xC0)
        return 2;

    if ((indicator_byte_char & 0xF0) == 0xE0)
        return 3;

    if ((indicator_byte_char & 0xF8) == 0xF0)
        return 4;

    return 0;
}

size_t measure_utf8_string_size(std::string const& byte_string)
{
    return std::count_if(byte_string.cbegin(), byte_string.cend(),
        indicate_utf8_char_size);
}

utf8_canvas::utf8_canvas(int const width)
    : width_(std::max(0, width)), height_(0) { }

int utf8_canvas::width_at(int const y) const
{
    if (y < 0)
        return 0;

    auto const line_search = find(y);

    if (line_search == end())
        return 0;

    return line_search->second.crbegin()->first + 1;
}

int utf8_canvas::height() const
{
    return height_;
}

std::string utf8_canvas::str() const
{
    std::ostringstream ss;
    for (auto y = 0; y < height_; ++y)
    {
        if (y > 0)
            ss << '\n';

        auto const line_search = find(y);

        if (line_search == end())
        {
            ss << std::string(width_, ' ');
            continue;
        }

        auto const& line = line_search->second;

        for (auto x = 0; x < width_; ++x)
        {
            auto const char_search = line.find(x);

            if (char_search == line.end())
            {
                ss << ' ';
                continue;
            }

            ss << char_search->second;
        }
    }

    return ss.str();
}

void utf8_canvas::print(std::string byte_string, int const x_pos, int const y_pos)
{
    if (y_pos < 0)
        return;

    auto& print_string = operator[](y_pos);

    for (auto x = x_pos; x < width_; ++x)
    {
        if (byte_string.empty())
            break;

        auto const utf8_char_size = indicate_utf8_char_size(byte_string.front());
        auto const utf8_char = byte_string.substr(0, utf8_char_size);

        byte_string.erase(0, utf8_char_size);

        if (x < 0)
            continue;

        print_string[x] = utf8_char;
    }

    height_ = std::max(height_, y_pos + 1);
}
void utf8_canvas::print(std::vector<std::string> const& byte_string_lines, int const x_pos, int const y_pos)
{
    for (auto y = std::max(0, y_pos); y < static_cast<int>(byte_string_lines.size()) + y_pos; ++y)
        print(byte_string_lines.at(y - y_pos), x_pos, y);
}

int utf8_canvas::print_centered(std::string const& byte_string, int x_pos, int const y_pos)
{
    x_pos += width_ / 2 - measure_utf8_string_size(byte_string) / 2;

    print(byte_string, x_pos, y_pos);
    return x_pos;
}
int utf8_canvas::print_centered(std::vector<std::string> const& byte_string_lines, int x_pos, int const y_pos)
{
    if (byte_string_lines.empty())
        return x_pos;

    x_pos += width_ / 2 - measure_utf8_string_size(byte_string_lines.front()) / 2;

    print(byte_string_lines, x_pos, y_pos);
    return x_pos;
}
