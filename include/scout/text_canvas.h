#pragma once

#include <string>
#include <unordered_map>

/**
 * Device for printing rectangular ASCII blocks onto a text buffer.
 */
class text_canvas
{
    std::unordered_map<size_t, std::unordered_map<size_t, std::string>> base_;

    size_t width_, height_;

public:

    explicit text_canvas(size_t width);

    size_t width() const;
    size_t height() const;

    std::string str();

    void draw(std::string const& text, size_t x, size_t y);
};
