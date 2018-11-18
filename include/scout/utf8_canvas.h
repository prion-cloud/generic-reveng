#pragma once

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

class utf8_canvas : std::unordered_map<int, std::map<int, std::string>>
{
    int width_, height_;

public:

    explicit utf8_canvas(int width);

    int width_at(int y) const;

    int height() const;

    std::string str() const;

    void print(std::string byte_string, int x_pos, int y_pos);
    void print(std::vector<std::string> const& byte_string_lines, int x_pos, int y_pos);

    int print_centered(std::string const& byte_string, int x_pos, int y_pos);
    int print_centered(std::vector<std::string> const& byte_string_lines, int x_pos, int y_pos);
};
