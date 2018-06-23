#include "stdafx.h"

#include "console.h"

HANDLE h_console;

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
