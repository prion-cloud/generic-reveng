#pragma once

#include <unimage/utf8_base.hpp>

struct utf8_shape
{
    int
        x_pos, y_pos,
        x_size, y_size;

    utf8_shape(
        int x_pos, int y_pos,
        int x_size, int y_size);

    virtual utf8_illustration illustrate() const = 0;
};

struct utf8_line : utf8_shape
{
    utf8_char
        start, end,
        body;

    utf8_line(
        int x_pos, int y_pos,
        int x_size, int y_size,
        utf8_char start, utf8_char end,
        utf8_char body);
};

struct utf8_h_line : utf8_line
{
    utf8_h_line(
        int x_pos, int y_pos,
        int x_size,
        utf8_char start, utf8_char end,
        utf8_char body);

    utf8_illustration illustrate() const override;
};
struct utf8_v_line : utf8_line
{
    utf8_v_line(
        int x_pos, int y_pos,
        int y_size,
        utf8_char start, utf8_char end,
        utf8_char body);

    utf8_illustration illustrate() const override;
};

struct utf8_text_rectangle : utf8_shape
{
    std::vector<std::string> text;
    int margin_size;

    utf8_char
        top_left, top_right,
        bottom_left, bottom_right,
        h_line, v_line;

    utf8_text_rectangle(
        int x_pos, int y_pos,
        std::vector<std::string> text, int margin_size,
        utf8_char top_left, utf8_char top_right,
        utf8_char bottom_left, utf8_char bottom_right,
        utf8_char h_line, utf8_char v_line);

    utf8_illustration illustrate() const override;
};
