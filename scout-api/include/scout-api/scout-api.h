#pragma once

#include <capstone/capstone.h>
#include <stdint.h>

#ifdef __cplusplus
#define CFG_API extern "C"
#else
#define CFG_API
#endif

CFG_API void const* cfg_construct(char const* file_name);
CFG_API void cfg_destruct(void const* cfg);

CFG_API void const* cfg_get_root(void const* cfg);

CFG_API int cfg_block_count_successors(void const* cfg_block);
CFG_API void const* cfg_block_get_successor(void const* cfg_block, int index);

CFG_API int cfg_block_count_instructions(void const* cfg_block);
CFG_API void cfg_block_get_instruction(void const* cfg_block, int index, cs_insn* instruction);

#undef CFG_API
