@echo off

mkdir build
cd build
cmake -D_CMAKE_BUILD_TYPE=RELEASE -G "NMake Makefiles" ..

cd thirdparty\capstone\
nmake

cd ..\..
nmake
xcopy thirdparty\capstone\capstone.dll .\

cd ..
