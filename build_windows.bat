@echo off

mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RELEASE -G "NMake Makefiles" ..

cd capstone
nmake

cd ..
nmake
xcopy capstone\capstone.dll .\

cd ..
