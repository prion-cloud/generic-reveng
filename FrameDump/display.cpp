#include "stdafx.h"

#include "display.h"

HANDLE dsp::h_console;

dsp::colorize::colorize(const uint16_t color)
    : color_(color) { }

std::ostream& dsp::colorize::operator()(std::ostream& stream) const
{
    SetConsoleTextAttribute(h_console, color_);
    return stream;
}

std::ostream& dsp::operator<<(std::ostream& stream, const colorize colorize)
{
    return colorize(stream);
}

std::ostream& dsp::decolorize(std::ostream& stream)
{
    SetConsoleTextAttribute(h_console, FOREGROUND_WHITE);
    return stream;
}
