#include "stdafx.h"

#include "bin_dump.h"
#include "debugger.h"
#include "loader.h"

#define API extern "C" __declspec(dllexport)

API int debugger_load(debugger*& handle, uint64_t scale, const char* bytes, const int32_t size)
{
    // TODO: another loader
    return -1;
}
API int debugger_load_file(debugger*& handle, const char* file_name)
{
    std::vector<char> bytes;
    create_dump(file_name, bytes);
    
    handle = new debugger();

    C_IMP(handle->load(pe_loader(), bytes));

    return F_SUCCESS;
}

API int debugger_unload(debugger* handle)
{
    const auto res = handle->unload();

    delete handle;
    return res;
}

API int debugger_ins(debugger* handle, instruction_info& ins_info)
{
    return handle->ins(ins_info);
}

API int debugger_reg(debugger* handle, register_info& reg_info)
{
    return handle->reg(reg_info);
}

API int debugger_mem(debugger* handle, memory_info& mem_info)
{
    return handle->mem(mem_info);
}
