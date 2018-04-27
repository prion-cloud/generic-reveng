#include "stdafx.h"
#include "../DebugEngine.Static/stdafx.h"

#include "macro.h"

#include "bin_dump.h"
#include "debugger.h"
#include "loader.h"

#define API extern "C" __declspec(dllexport)

API int debugger_load_file(debugger*& handle, const char* file_name)
{
    std::vector<char> bytes;
    create_filedump(file_name, bytes);
    
    handle = new debugger();

    E_ERR(handle->load(new loader_pe(), bytes));

    return R_SUCCESS;
}

API int debugger_unload(debugger* handle)
{
    const auto res = handle->unload();

    delete handle;
    return res;
}

API int debugger_ins(debugger* handle, instruction_info& ins_info)
{
    return handle->debug(ins_info);
}
