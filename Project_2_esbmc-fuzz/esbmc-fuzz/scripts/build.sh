cmake .. -GNinja -DBUILD_TESTING=On -DENABLE_REGRESSION=On -DBUILD_STATIC=On -DClang_DIR=$PWD/../../clang11 -DLLVM_DIR=$PWD/../../clang11  -DZ3_DIR=$PWD/../../z3  -DC2GOTO_SYSROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk  -DCMAKE_INSTALL_PREFIX:PATH=$PWD/../../release

cmake --build . && ninja install