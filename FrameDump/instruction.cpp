#include "stdafx.h"

#include "instruction.h"
#include "serialization.h"

std::ofstream& operator<<=(std::ofstream& stream, const x86_operator& op)
{
    stream <<= op.type;
    stream <<= op.value;

    return stream;
}
std::ifstream& operator>>=(std::ifstream& stream, x86_operator& op)
{
    stream >>= op.type;
    stream >>= op.value;

    return stream;
}

std::ofstream& operator<<=(std::ofstream& stream, const x86_instruction& ins)
{
    stream <<= ins.id;
    stream <<= ins.address;
    stream <<= ins.bytes;
    stream <<= ins.representation;

    stream <<= ins.operators;

    return stream;
}
std::ifstream& operator>>=(std::ifstream& stream, x86_instruction& ins)
{
    stream >>= ins.id;
    stream >>= ins.address;
    stream >>= ins.bytes;
    stream >>= ins.representation;

    stream >>= ins.operators;

    return stream;
}
