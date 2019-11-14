au BufRead,BufNewFile *.tpp setfiletype cpp

let g:ale_linters_explicit = 1
let g:ale_linters = {
\ 'cpp': [ 'gcc', 'clangtidy' ],
\}

let options = '
\ -std=c++2a
\
\ -D LINT
\
\ -I include
\ -I source
\ -I test
\
\ -I submodule/openreil/libopenreil/include
\ -I submodule/z3/src/api
\'

let g:ale_cpp_gcc_options = options
let g:ale_cpp_clangtidy_options = options
