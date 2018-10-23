# run desktop builds
cmake .
cmake --build -DCMAKE_BUILD_TYPE=Coverage .

# run Gtest
./bin/Ark-Cpp-Crypto-tests
