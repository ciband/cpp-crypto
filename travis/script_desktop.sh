# run desktop builds
#cmake . -DCMAKE_BUILD_TYPE=Coverage
cmake .
cmake --build .

# run Gtest
./bin/Ark-Cpp-Crypto-tests
