#include "stdafx.h"

TPL T loader::parse_to(std::vector<uint8_t>::const_iterator& iterator)
{
    const auto next = iterator + sizeof(T);
    const auto value = *reinterpret_cast<const T*>(iterator._Ptr);

    iterator = next;

    return value;
}
