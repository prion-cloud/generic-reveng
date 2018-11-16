#include "../include/scout/text_canvas.h"

size_t measure_utf8_char_size::operator()(char const indicator_byte_char) const
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

text_canvas::text_canvas(int const width)
    : width_(std::max(0, width)), height_(0) { }

int text_canvas::width() const
{
    return width_;
}
int text_canvas::height() const
{
    return height_;
}

std::string text_canvas::str() const
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
