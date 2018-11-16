#pragma once

#include <algorithm>
#include <sstream>
#include <string>
#include <unordered_map>

struct measure_utf8_char_size
{
    size_t operator()(char indicator_byte_char) const;
};

template <typename CharSizeMeter = measure_utf8_char_size>
size_t measure_print_text_length(std::string const& byte_text,
    CharSizeMeter measure_print_char_size = CharSizeMeter());

class text_canvas : std::unordered_map<int, std::unordered_map<int, std::string>>
{
    int width_, height_;

public:

    explicit text_canvas(int width);

    int width() const;
    int height() const;

    std::string str() const;

    template <typename CharSizeMeter = measure_utf8_char_size>
    void print(std::string const& byte_text, int x_pos, int y_pos,
        CharSizeMeter measure_print_char_size = CharSizeMeter());

    template <typename CharSizeMeter = measure_utf8_char_size>
    void print_centered(std::string const& byte_text, int  x_pos, int y_pos,
        CharSizeMeter measure_print_char_size = CharSizeMeter());
    template <typename CharSizeMeter = measure_utf8_char_size>
    void print_centered(std::string const& byte_text, int* x_pos, int y_pos,
        CharSizeMeter measure_print_char_size = CharSizeMeter());
};

template <typename CharSizeMeter>
size_t measure_print_text_length(std::string const& byte_text,
    CharSizeMeter measure_print_char_size)
{
    return std::count_if(byte_text.cbegin(), byte_text.cend(), measure_print_char_size);
}

template <typename CharSizeMeter>
void text_canvas::print(std::string const& byte_text, int const x_pos, int const y_pos,
    CharSizeMeter measure_print_char_size)
{
    std::istringstream byte_text_buffer(byte_text);

    int y;
    for (y = y_pos;; ++y)
    {
        std::string byte_line;
        if (!std::getline(byte_text_buffer, byte_line))
            break;

        if (y < 0)
            continue;

        auto& print_line = operator[](y);

        for (auto x = x_pos; x < width_; ++x)
        {
            if (byte_line.empty())
                break;

            auto const print_char_size = measure_print_char_size(byte_line.front());

            auto const print_char = byte_line.substr(0, print_char_size);

            byte_line.erase(0, print_char_size);

            if (x < 0)
                continue;

            print_line[x] = print_char;
        }
    }

    height_ = std::max(height_, y);
}

template <typename CharSizeMeter>
void text_canvas::print_centered(std::string const& byte_text, int x_pos, int const y_pos,
    CharSizeMeter measure_print_char_size)
{
    print_centered(byte_text, &x_pos, y_pos, measure_print_char_size);
}
template <typename CharSizeMeter>
void text_canvas::print_centered(std::string const& byte_text, int* x_pos, int const y_pos,
    CharSizeMeter measure_print_char_size)
{
    auto const print_text_length =
        measure_print_text_length(byte_text.substr(0, byte_text.find_first_of('\n')),
            measure_print_char_size);

    *x_pos += width_ / 2 - print_text_length / 2;

    print(byte_text, *x_pos, y_pos, measure_print_char_size);
}
