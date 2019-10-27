let options = '
\ -D LINTER
\ -I revengine/include
\ -I revengine-disassembler/include
\ -I revengine/submodule/z3/src/api
\ -I revengine-disassembler/submodule/openreil/libopenreil/include
\'

let g:ale_cpp_gcc_options .= options
let g:ale_cpp_clangtidy_options .= options
