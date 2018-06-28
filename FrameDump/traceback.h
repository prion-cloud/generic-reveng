#pragma once

struct data_transfer_x86
{
    operand_x86 destination;
    operand_x86 source;
};

struct traceback_x86
{
    instruction_x86 instruction;
    bool has_failed;

    std::vector<data_transfer_x86> data_transfers;

    traceback_x86(instruction_x86 instruction, uc_err error, context context);
};
