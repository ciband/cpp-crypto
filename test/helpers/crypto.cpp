
#include "gtest/gtest.h"

#include <array>

#include "fixtures/identity.hpp"

#include "identities/privatekey.hpp"
#include "identities/publickey.hpp"

#include "bcl/Sha256.hpp"
#include "bcl/Uint256.hpp"

#include "helpers/crypto.h"
#include "utils/hex.hpp"
#include "transactions/builder.h"

namespace { // NOLINT
  std::vector<uint8_t> MessageHashTestBytes = {
    165, 145, 166, 212,  11, 244,  32,  64,
     74,   1,  23,  51, 207, 183, 177, 144,
    214,  44, 101, 191,  11, 205, 163,  43,
     87, 178, 119, 217, 173, 159,  20, 110
  };

  std::array<uint8_t, 32> PrivateKeyTestBytes = {
    216, 131, 156,  36,  50, 191, 208, 166,
    126, 241,  10, 128,  75, 169, 145, 234,
    187, 161, 159,  21,  74,  61, 112, 121,
    23, 104,  29,  69, 130,  42,  87,  18
  };

  std::array<uint8_t, 33> PublicKeyTestBytes = {
      3,
     65,  81, 163, 236,  70, 181, 103,  10,
    104,  43,  10,  99,  57,  79, 134,  53,
    135, 209, 188, 151,  72,  59,  27, 108,
    112, 235,  88, 231, 240, 174, 209, 146
  };
  std::array<uint8_t, 33> InvalidPublicKeyTestBytes = {
      3,
     66,  81, 163, 236,  70, 181, 103,  10,
    104,  43,  10,  99,  57,  79, 134,  53,
    135, 209, 188, 151,  72,  59,  27, 108,
    112, 235,  88, 231, 240, 174, 209, 146
  };

  std::vector<uint8_t> RValueTestBytes = {
     15, 180, 173, 221, 209, 241, 214,  82,
    181,  68, 234, 106, 182,  40,  40, 160,
    166,  91, 113,  46, 212,  71, 226,  83,
    141, 176, 202, 235, 250, 104, 146, 158
  };

  std::vector<uint8_t> SValueTestBytes = {
     94, 203,  46,  28,  99, 178, 152, 121,
    194, 236, 241,  37,  93, 181,   6, 214,
    113, 200, 179, 250,  96,  23, 246, 124,
    253,  27, 240, 126, 110, 221,  28, 200
  };

  std::vector<uint8_t> SignatureTestBytes = {
     48,  68,   2,  32,  15, 180, 173, 221, 209, 241,
    214,  82, 181,  68, 234, 106, 182,  40,  40, 160,
    166,  91, 113,  46, 212,  71, 226,  83, 141, 176,
    202, 235, 250, 104, 146, 158,   2,  32,  94, 203,
     46,  28,  99, 178, 152, 121, 194, 236, 241,  37,
     93, 181,   6, 214, 113, 200, 179, 250,  96,  23,
    246, 124, 253,  27, 240, 126, 110, 221,  28, 200
  };
};

/**/

TEST(helpers, crypto_edcsa_sign) {
  Sha256Hash hash(&MessageHashTestBytes[0], MessageHashTestBytes.size());
  Ark::Crypto::identities::PrivateKey privateKey(PrivateKeyTestBytes);
  std::vector<uint8_t> signature;
  cryptoSignECDSA(
      hash,
      privateKey,
      signature);

  for (auto i = 0U; i < signature.size(); ++i) {
    ASSERT_EQ(signature[i], SignatureTestBytes[i]);
  };
}

/**/

TEST(helpers, crypto_ecdsa_verify_valid) {
  Ark::Crypto::identities::PublicKey publicKey(PublicKeyTestBytes);
  Sha256Hash hash(&MessageHashTestBytes[0], MessageHashTestBytes.size());

  bool isValid = cryptoVerifyECDSA(
      publicKey,
      hash,
      SignatureTestBytes);
  ASSERT_TRUE(isValid);
}

/**/

TEST(helpers, crypto_ecdsa_verify_invalid) {
  Ark::Crypto::identities::PublicKey publicKey(InvalidPublicKeyTestBytes);
//   Ark::Crypto::identities::PublicKey publicKey(&InvalidPublicKeyTestBytes[0]);
  Sha256Hash hash(&MessageHashTestBytes[0], MessageHashTestBytes.size());

  bool isValid = cryptoVerifyECDSA(
      publicKey,
      hash,
      SignatureTestBytes);
  ASSERT_FALSE(isValid);
}


TEST(helpers, crypto_schnorr_sign) {
  auto tx = Ark::Crypto::Transactions::Builder::buildTransfer(
    "AJWRd23HNEhPLkK1ymMnwnDBX2a7QBZqff",
    1000,
    "",
    Ark::Crypto::fixtures::identity::tPassphrase
  );
  tx.fee = 2000;
  tx.timestamp = 141738;

  //Ark::Crypto::identities::PrivateKey privateKey =
  //    Ark::Crypto::identities::PrivateKey::fromPassphrase(Ark::Crypto::fixtures::identity::tPassphrase);
  //const auto bytes = tx.toBytes();
  //const auto hash = Sha256::getHash(&bytes[0], bytes.size());
  const auto hash = HexToBytes("be6e299280ba6b18305fb01f5022f06de4fb31ee74a87d8c29b7736a8e8c77d4");
  const auto privateKey = Ark::Crypto::identities::PrivateKey::fromHex("d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712");
  std::vector<uint8_t> signature;

  cryptoSignSchnorr(
      hash,
      privateKey,
      signature);

  ASSERT_STREQ(
      "b335d8630413fdf5f8f739d3b2d3bcc19cfdb811acf0c769cc2b2faf477c1e053b6974ccaba086fc6e1dd0cfc16bba2f18ab3d8b6624f16479886d9e4cfeb95e",
      BytesToHex(signature).c_str());
}

TEST(helpers, crypto_schnorr_verify_valid) {
}

TEST(helpers, crypto_schnorr_verify_invalid) {
}

/*

const transaction = {
    type: 0,
    amount: Utils.BigNumber.make(1000),
    fee: Utils.BigNumber.make(2000),
    recipientId: "AJWRd23HNEhPLkK1ymMnwnDBX2a7QBZqff",
    timestamp: 141738,
    asset: {},
    senderPublicKey: identity.publicKey,
};
describe("schnorr", () => {
        it("should sign the data and verify it [String]", () => {
            const hash: Buffer = TransactionUtils.toHash(transaction);
            const signature: string = Hash.signSchnorr(hash, identity.keys);

            expect(Hash.verifySchnorr(hash, signature, identity.publicKey)).toBeTrue();

            expect(signature).toEqual(
                "b335d8630413fdf5f8f739d3b2d3bcc19cfdb811acf0c769cc2b2faf477c1e053b6974ccaba086fc6e1dd0cfc16bba2f18ab3d8b6624f16479886d9e4cfeb95e",
            );
        });

        it("should sign the data and verify it [Buffer]", () => {
            const hash: Buffer = TransactionUtils.toHash(transaction);
            const signature: string = Hash.signSchnorr(hash, identity.keys);

            expect(
                Hash.verifySchnorr(hash, Buffer.from(signature, "hex"), Buffer.from(identity.publicKey, "hex")),
            ).toBeTrue();

            expect(signature).toEqual(
                "b335d8630413fdf5f8f739d3b2d3bcc19cfdb811acf0c769cc2b2faf477c1e053b6974ccaba086fc6e1dd0cfc16bba2f18ab3d8b6624f16479886d9e4cfeb95e",
            );
        });
    });

*/
