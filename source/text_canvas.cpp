#include <algorithm>
#include <sstream>
#include <vector>

#include "../include/scout/text_canvas.h"

text_canvas::text_canvas(size_t const width)
    : width_(width), height_(0) { }

size_t text_canvas::width() const
{
    return width_;
}
size_t text_canvas::height() const
{
    return height_;
}

std::string text_canvas::str()
{
    std::ostringstream ss;
    for (size_t i = 0; i < height_; ++i)
    {
        if (i > 0)
            ss << '\n';

        auto& base_line = base_[i];

        for (size_t j = 0; j < width_; ++j)
        {
            auto& base_char = base_line[j];

            if (base_char.empty())
                base_char = " ";

            ss << base_char;
        }
    }

    return ss.str();
}

void text_canvas::draw_utf8(std::string const& text, ssize_t const x, ssize_t y,
    alignment text_alignment)
{
    for (std::istringstream in_buffer(text);;)
    {
        std::string line;
        if (!std::getline(in_buffer, line))
            break;

        ssize_t line_x;
        switch (text_alignment)
        {
        case alignment::right:
            line_x = width_ - line.size() - x;
            break;
        case alignment::center:
            line_x = width_ / 2 - line.size() / 2 + x;
            break;
        default:
            line_x = x;
            break;
        }

        auto& base_line = base_[y++];

        for (size_t line_pos = 0, skip = 0; line_pos < line.size(); ++line_pos)
        {
            auto const byte = line.at(line_pos);

            size_t
                char_size = 1;
            if ((byte & 0xE0) == 0xC0)
                char_size = 2;
            if ((byte & 0xF0) == 0xE0)
                char_size = 3;
            if ((byte & 0xF8) == 0xF0)
                char_size = 4;

            auto const base_line_pos = line_x + line_pos - skip;

            skip += char_size - 1;

            if (base_line_pos < 0)
                continue;

            auto& base_char = base_line[base_line_pos];

            base_char = std::string(1, byte);

            for (size_t char_pos = 1; char_pos < char_size && line_pos < line.size() - 1; ++char_pos)
                base_char.push_back(line.at(++line_pos));
        }
    }

    height_ = std::max(static_cast<ssize_t>(height_), y);
}
