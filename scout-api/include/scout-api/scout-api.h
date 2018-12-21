#pragma once

#include <capstone.h>
#include <stdint.h>

#ifdef __cplusplus
#define SCOUT_API extern "C"
#else
#define SCOUT_API
#endif

SCOUT_API void const* create_control_flow(char const* file_name);
SCOUT_API void release_control_flow_handle(void const* control_flow_handle);

SCOUT_API void const* get_root_block(void const* control_flow_handle);

SCOUT_API int count_block_successors(void const* block_handle);
SCOUT_API void const* get_block_successor(void const* block_handle, int index);

SCOUT_API int count_block_instructions(void const* block_handle);
SCOUT_API void disassemble_block_instruction(void const* block_handle, int index, cs_insn* instruction);

#undef SCOUT_API
