
#include "gtest/gtest.h"
#include "arkCrypto.h"

TEST(configuration, fee_get)
{
    Ark::Crypto::Configuration::Fee fee;
    //ASSERT_TRUE(10000000 == fee.get(0));
    ASSERT_EQ(10000000ull, fee.get(0));
    ASSERT_EQ(500000000ull, fee.get(1));
    ASSERT_EQ(2500000000ull, fee.get(2));
    ASSERT_EQ(100000000ull, fee.get(3));
    ASSERT_EQ(500000000ull, fee.get(4));
    ASSERT_EQ(0ull, fee.get(5));
    ASSERT_EQ(0ull, fee.get(6));
    ASSERT_EQ(0ull, fee.get(7));
    ASSERT_EQ(0ull, fee.get(8));
}

TEST(configuration, fee_set)
{
    Ark::Crypto::Configuration::Fee fee;
    fee.set(0, 20000000ull);
    fee.set(1, 1000000000ull);
    fee.set(2, 4000000000ull);
    fee.set(3, 200000000ull);
    fee.set(4, 1000000000ull);
    fee.set(5, 1ull);
    fee.set(6, 1ull);
    fee.set(7, 1ull);
    fee.set(8, 1ull);

    ASSERT_EQ(20000000ull, fee.get(0));
    ASSERT_EQ(1000000000ull, fee.get(1));
    ASSERT_EQ(4000000000ull, fee.get(2));
    ASSERT_EQ(200000000ull, fee.get(3));
    ASSERT_EQ(1000000000ull, fee.get(4));
    ASSERT_EQ(1ull, fee.get(5));
    ASSERT_EQ(1ull, fee.get(6));
    ASSERT_EQ(1ull, fee.get(7));
    ASSERT_EQ(1ull, fee.get(8));
}
