#pragma once

#include <sstream>
#include <string>
#include <vector>

/**
 * Device for printing rectangular ASCII blocks onto a text buffer.
 */
class text_canvas
{
    std::ostringstream out_buffer_;

    size_t width_;

public:

    explicit text_canvas(size_t width);

    std::string str() const;

    void draw(std::string const& text, size_t x, size_t y);

private:

    void reserve(size_t position);
};
