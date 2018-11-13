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

        auto& line = base_[i];

        for (size_t j = 0; j < width_; ++j)
        {
            auto& value = line[j];

            if (value.empty())
                value = " ";

            ss << value;
        }
    }

    return ss.str();
}

void text_canvas::draw(std::string const& text, size_t const x, size_t const y)
{
    std::istringstream in_buffer(text);

    // Split the text into lines
    std::vector<std::string> lines;
    while (true)
    {
        std::string line;
        if (!std::getline(in_buffer, line))
            break;

        lines.push_back(line);
    }

    for (size_t i = 0; i < lines.size(); ++i)
    {
        auto const line = lines.at(i);

        size_t skip = 0;

        for (size_t j = 0; j < line.size(); ++j)
        {
            char ch = line.at(j);

            size_t take;
            if (((~ch ^ 0xC0) & 0xE0) == 0xE0)
            {
                /* 2 byte UTF-8 */
                take = 2;
            }
            else if (((~ch ^ 0xE0) & 0xF0) == 0xF0)
            {
                /* 3 byte UTF-8 */
                take = 3;
            }
            else if (((~ch ^ 0xF0) & 0xF8) == 0xF8)
            {
                /* 4 byte UTF-8 */
                take = 4;
            }
            else
            {
                /* 1 byte UTF-8 */
                take = 1;
            }

            auto& put = base_[y + i][x + j - skip];
            put = std::string(1, ch);

            for (size_t k = 1; k < take; ++k, ++skip)
                put.push_back(line.at(++j));
        }
    }

    height_ = std::max(height_, y + lines.size());
}
