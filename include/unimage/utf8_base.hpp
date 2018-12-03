#pragma once

#include <ostream>
#include <string>
#include <vector>

size_t measure_utf8_string_size(std::string byte_string);

struct utf8_char
{
    std::string value;

    explicit utf8_char(std::string const& byte_string = " ");
};

using utf8_illustration = std::vector<std::vector<utf8_char>>;

std::ostream& operator<<(std::ostream& stream, utf8_illustration illustration);
