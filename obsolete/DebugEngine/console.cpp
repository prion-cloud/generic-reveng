#include "stdafx.h"

#include "console.h"

HANDLE h_console;

void replace(const std::string text)
{
    std::cout << '\r' << text << '\r';
}
void erase(const size_t size)
{
    replace(std::string(size, ' '));
}

void set_cursor(const int16_t line, const int16_t column)
{
    SetConsoleCursorPosition(h_console, { column, line });
}
void set_cursor(const std::pair<int16_t, int16_t> position)
{
    set_cursor(position.first, position.second);
}

CONSOLE_SCREEN_BUFFER_INFO get_buffer_info()
{
    CONSOLE_SCREEN_BUFFER_INFO info { };
    GetConsoleScreenBufferInfo(h_console, &info);
    return info;
}

std::pair<int16_t, int16_t> get_cursor()
{
    const auto info = get_buffer_info();
    return std::make_pair(info.dwCursorPosition.Y, info.dwCursorPosition.X);
}

int16_t get_cursor_line()
{
    return get_cursor().first;
}
int16_t get_cursor_column()
{
    return get_cursor().second;
}

colorize::colorize(const uint16_t color)
    : color_(color) { }

std::ostream& colorize::operator()(std::ostream& stream) const
{
    SetConsoleTextAttribute(h_console, color_);
    return stream;
}

std::ostream& operator<<(std::ostream& stream, const colorize colorize)
{
    return colorize(stream);
}

std::ostream& decolorize(std::ostream& stream)
{
    SetConsoleTextAttribute(h_console, FOREGROUND_WHITE);
    return stream;
}
