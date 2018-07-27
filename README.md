### 🚧 This project is currently under construction. 🚧

Clone with submodules:
```
git clone --recurse-submodules https://github.com/superbr4in/generic-reveng.git
cd generic-reveng
```

Create `nmake` files:
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RELEASE -G "NMake Makefiles" ..
```

Build `capstone`:
```
cd capstone
nmake
```

Build project:
```
cd ..
nmake
cp capstone/capstone.dll ./
```
