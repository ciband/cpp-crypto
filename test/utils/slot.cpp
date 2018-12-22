
#include "gtest/gtest.h"

#include "helpers/helpers.h"
#include "utils/slot.h"

TEST(utilities, slots_time) {
  const auto devnet = Ark::Crypto::Networks::Devnet;
  ASSERT_EQ(10ull, Ark::Crypto::Utils::Slot::time(1490101210000, devnet));
}

TEST(utilities, slots_begin_epoch_time) {
  const auto devnet = Ark::Crypto::Networks::Devnet;
  ASSERT_EQ(1490101200ull, std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(Ark::Crypto::Utils::Slot::begin_epoch_time(devnet))).count());
}

TEST(utilities, slots_get_real_time) {
  const auto devnet = Ark::Crypto::Networks::Devnet;
  ASSERT_EQ(1490101210000ull, Ark::Crypto::Utils::Slot::real_time(10, devnet));
}

