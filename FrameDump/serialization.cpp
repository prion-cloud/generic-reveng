#include "stdafx.h"

#include "serialization.h"

#define TERM '\0'

std::ofstream& operator<<=(std::ofstream& stream, const std::string& string)
{
    for (const auto c : string)
        stream <<= c;

    stream <<= TERM;

    return stream;
}

std::ifstream& operator>>=(std::ifstream& stream, std::string& string)
{
    string = { };

    while (true)
    {
        auto c = TERM;
        stream >>= c;

        if (c == TERM)
            break;

        string += c;
    }

    return stream;
}
