# Generic Reverse Engineering

Static binary analysis through symbolic execution

___THIS PROJECT IS A WORK IN PROGRESS AND THEREFORE NOT READY TO BE USED IN PRODUCTION___

## API

A program analysis outputs an [`execution`](include/grev/execution.hpp) structure that contains:
* Code paths a program possibly takes (e.g. depending on user input).
* Import function calls including the respective values of their parameters.

Start with a [`machine_process`](include/grev/machine_process.hpp) to examine software.

## Example

Consider a compiled program containing x86/32 instructions.
A detected call to `printf` may create the following dependency:
```
[ESP - 48] := 004020F4 -> "Hello, world!"
```

This clearly shows a parameter access through the stack, particularly in `[ESP - 48]`.
From the program's perspective, the stack has already been increased in size, but during the library function, the parameter value is referred to as `[ESP + 4]`, just like familiar calling conventions would suggest.

Function arguments are revealed through the use of unbound (therefore unknown) registers and memory locations.
Evaluating these unknowns using the computed program state at the function call lead to the actual passed parameter values; in this particular example `004020F4`. The attempt to interpret this value as a memory location shows that it points to a `Hello, world!` string, the text to be printed.

## Build

Be sure to get all dependencies.
```
git submodule update --init --recursive
```
Use a different directory for the build tree.
```
mkdir build
cd build
```
Configure and compile the code using [CMake](https://cmake.org/).
```
cmake ..
make
```

## Test

To run the tests, a [Catch2](https://github.com/catchorg/Catch2) installation is required.

## License

This repository is licensed under the [GNU General Public License v3.0](LICENSE).

## Third Party

Software dependencies are managed through git submodules:
* [openreil](https://github.com/Cr4sh/openreil/tree/9b7226f7bb9c2c6b08b61eb69d91f06caaf0ea58) (master)
* [z3](https://github.com/Z3Prover/z3/tree/78ed71b8de7d4d089f2799bf2d06f411ac6b9062) (v4.8.6)
