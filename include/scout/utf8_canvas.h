#pragma once

#include <map>

#include "utf8_shape.h"

class utf8_canvas : std::map<int, std::vector<utf8_shape const*>>
{
    int width_, height_;

public:

    explicit utf8_canvas(int width);

    int width() const;
    int height() const;

    void add_shape(int layer, utf8_shape const* shape);

    utf8_illustration illustrate() const;
};
