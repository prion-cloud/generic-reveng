#pragma once

#include <map>
#include <memory>

#include "utf8_shape.h"

class utf8_canvas : std::map<int, std::vector<std::unique_ptr<utf8_shape const>>>
{
    int width_;

public:

    explicit utf8_canvas(int width);

    void add_shape(int layer, std::unique_ptr<utf8_shape const> shape);

    utf8_illustration illustrate() const;
};
