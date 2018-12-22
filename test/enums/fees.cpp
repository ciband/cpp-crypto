#include "gtest/gtest.h"

#include "enums/fees.h"

TEST(enums, fees)
{
    Ark::Crypto::Enums::Fees fees;
    
    auto feeZERO = fees.TRANSFER;
    ASSERT_EQ(10000000ull, feeZERO);

    auto feeONE = fees.SECOND_SIGNATURE_REGISTRATION;
    ASSERT_EQ(500000000ull, feeONE);

    auto feeTWO = fees.DELEGATE_REGISTRATION;
    ASSERT_EQ(2500000000ull, feeTWO);

    auto feeTHREE = fees.VOTE;
    ASSERT_EQ(100000000ull, feeTHREE);

    auto feeFOUR = fees.MULTI_SIGNATURE_REGISTRATION;
    ASSERT_EQ(500000000ull, feeFOUR);

    auto feeFIVE = fees.IPFS;
    ASSERT_EQ(0ull, feeFIVE);

    auto feeSIX = fees.TIMELOCK_TRANSFER;
    ASSERT_EQ(0ull, feeSIX);

    auto feeSEVEN = fees.MULTI_PAYMENT;
    ASSERT_EQ(0ull, feeSEVEN);

    auto feeEIGHT = fees.DELEGATE_RESIGNATION;
    ASSERT_EQ(0ull, feeEIGHT);
}
