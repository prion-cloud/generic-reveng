#include "../include/scout/text_canvas.h"

text_canvas::text_canvas(size_t const width)
    : width_(width) { }

std::string text_canvas::str() const
{
    // Insert line breaks
    std::string text = out_buffer_.str();
    for (size_t pos = width_; pos < text.size(); pos += width_ + 1)
        text.insert(pos, 1, '\n');

    return text;
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

    size_t end_pos;

    auto line_it = lines.crbegin();
    for (; line_it != lines.crend(); ++line_it)
    {
        end_pos = line_it->find_last_not_of(' ');

        if (end_pos != std::string::npos)
            break;
    }

    // Remove trailing blank lines
    lines.erase(line_it.base(), lines.cend());

    // All text empty or whitespace?
    if (lines.empty())
        return;

    // Reserve exactly the space needed
    end_pos += x;
    end_pos = std::min(end_pos, width_);
    end_pos += (y + lines.size() - 1) * width_;
    reserve(end_pos);

    auto const x_max_pos = width_ - x;

    for (size_t y_pos = 0; y_pos < lines.size(); ++y_pos)
    {
        auto const& line = lines.at(y_pos);

        for (size_t x_pos = 0; x_pos < line.size();)
        {
            x_pos = line.find_first_not_of(' ', x_pos);

            if (x_pos == std::string::npos || x_pos >= x_max_pos)
                break;

            size_t x_end_pos = line.find_first_of(' ', x_pos);

            if (x_end_pos == std::string::npos)
                x_end_pos = line.size();

            x_end_pos = std::min(x_end_pos, x_max_pos);

            out_buffer_.seekp((y + y_pos) * width_ + x + x_pos);
            out_buffer_ << line.substr(x_pos, x_end_pos - x_pos);

            x_pos = x_end_pos;
        }
    }

    out_buffer_ << std::flush;
}

void text_canvas::reserve(size_t const position)
{
    out_buffer_.seekp(0, std::ios::end);

    size_t const size = out_buffer_.tellp();

    // Current buffer size insufficient?
    if (position > size)
        out_buffer_ << std::string(position - size, ' ');
}
