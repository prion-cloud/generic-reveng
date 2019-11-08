au BufRead,BufNewFile *.tpp setfiletype cpp

let g:ale_linters_explicit = 1
let g:ale_linters = {
\ 'cpp': [ 'gcc', 'clangtidy' ],
\}

let options = '
\ -std=c++17
\
\ -D LINT
\
\ -I revengine/include
\ -I revengine/submodule/z3/src/api
\
\ -I revengine-disassembler/include
\ -I revengine-disassembler/submodule/openreil/libopenreil/include
\
\ -I test/source
\'

let g:ale_cpp_gcc_options = options
let g:ale_cpp_clangtidy_options = options
