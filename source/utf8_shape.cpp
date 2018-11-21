#include "../include/scout/utf8_shape.h"

utf8_shape::utf8_shape(
    int const x_pos, int const y_pos,
    int const x_size, int const y_size) :
        x_pos(x_pos), y_pos(y_pos),
        x_size(x_size), y_size(y_size) { }

utf8_line::utf8_line(
    int const x_pos, int const y_pos,
    int const x_size, int const y_size,
    utf8_char start, utf8_char end,
    utf8_char body) :
        utf8_shape(
            x_pos, y_pos,
            x_size, y_size),
        start(std::move(start)), end(std::move(end)),
        body(std::move(body)) { }

utf8_h_line::utf8_h_line(
    int const x_pos, int const y_pos,
    int const x_size,
    utf8_char start, utf8_char end,
    utf8_char body) :
        utf8_line(
            x_pos + std::min(x_size + 1,  0), y_pos,
            std::abs(x_size), 1,
            std::move(x_size < 0 ? end : start), std::move(x_size < 0 ? start : end),
            std::move(body)) { }

utf8_illustration utf8_h_line::illustrate() const
{
    utf8_illustration illustration;

    if (x_size == 0)
        return illustration;

    auto& line = illustration.emplace_back();

    for (auto x = 0; x < x_size; ++x)
    {
        utf8_char cur;
        if (x == 0)
            cur = start;
        else if (x == x_size - 1)
            cur = end;
        else
            cur = body;

        line.push_back(cur);
    }

    return illustration;
}

utf8_v_line::utf8_v_line(
    int const x_pos, int const y_pos,
    int const y_size,
    utf8_char start, utf8_char end,
    utf8_char body) :
        utf8_line(
            x_pos, y_pos + std::min(y_size + 1, 0),
            1, std::abs(y_size),
            std::move(y_size < 0 ? end : start), std::move(y_size < 0 ? start : end),
            std::move(body)) { }

utf8_illustration utf8_v_line::illustrate() const
{
    utf8_illustration illustration;

    if (y_size == 0)
        return illustration;

    for (auto y = 0; y < y_size; ++y)
    {
        utf8_char cur;
        if (y == 0)
            cur = start;
        else if (y == y_size - 1)
            cur = end;
        else
            cur = body;

        illustration.emplace_back().push_back(cur);
    }

    return illustration;
}

int get_max_utf8_string_size(std::vector<std::string> const& text)
{
    size_t max_utf8_string_size = 0;
    for (auto const& byte_string : text)
        max_utf8_string_size = std::max(max_utf8_string_size, measure_utf8_string_size(byte_string));

    return max_utf8_string_size;
}

utf8_text_rectangle::utf8_text_rectangle(
    int const x_pos, int const y_pos,
    std::vector<std::string> text, int const margin_size,
    utf8_char top_left, utf8_char top_right,
    utf8_char bottom_left, utf8_char bottom_right,
    utf8_char h_line, utf8_char v_line) :
        utf8_shape(
            x_pos, y_pos,
            get_max_utf8_string_size(text) + 2 * margin_size + 2, text.size() + 2),
        text(std::move(text)), margin_size(margin_size),
        top_left(std::move(top_left)), top_right(std::move(top_right)),
        bottom_left(std::move(bottom_left)), bottom_right(std::move(bottom_right)),
        h_line(std::move(h_line)), v_line(std::move(v_line)) { }

utf8_illustration utf8_text_rectangle::illustrate() const
{
    utf8_illustration illustration;

    if (x_size == 0 || y_size == 0)
        return illustration;

    for (auto y = 0; y < y_size; ++y)
    {
        auto& line = illustration.emplace_back();

        if (y > 0 && y < y_size - 1)
        {
            line.push_back(v_line);

            int x = 1;
            for (; x < margin_size + 1; ++x)
                line.emplace_back();

            auto text_line = text.at(y - 1);
            for (; x < x_size - margin_size - 1; ++x)
            {
                if (text_line.empty())
                {
                    line.emplace_back();
                    continue;
                }

                text_line.erase(0, line.emplace_back(text_line).value.size());
            }

            for (; x < x_size - 1; ++x)
                line.emplace_back();

            line.push_back(v_line);

            continue;
        }

        for (auto x = 0; x < x_size; ++x)
        {
            utf8_char cur;
            if (x == 0)
            {
                if (y == 0)
                    cur = top_left;
                else
                    cur = bottom_left;
            }
            else if (x == x_size - 1)
            {
                if (y == 0)
                    cur = top_right;
                else
                    cur = bottom_right;
            }
            else
                cur = h_line;

            line.push_back(cur);
        }
    }

    return illustration;
}
