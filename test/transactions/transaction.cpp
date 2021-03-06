#include "gtest/gtest.h"

#include "transactions/builder.h"
#include "helpers/json.h"

#include <map>
#include <string>

TEST(transactions, transaction_to_array) {
    //  Type 0
    auto transfer = Ark::Crypto::Transactions::Builder::buildTransfer("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", 1, "", "Secret passphrase");
    std::map<std::string, std::string> tArray = transfer.toArray();

    //  Amount
    ASSERT_STREQ("1", tArray["amount"].c_str());
    //  Fee
    ASSERT_STREQ("10000000", tArray["fee"].c_str());
    //  Id
    ASSERT_STRNE("", tArray["id"].c_str());
    //  RecipientId
    ASSERT_STREQ("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", tArray["recipientId"].c_str());
    //  SenderPublicKey
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", tArray["senderPublicKey"].c_str());
    //  Signature
    ASSERT_STRNE("", tArray["signature"].c_str());
    //  Timestamp
    ASSERT_STRNE("", tArray["timestamp"].c_str());
    //  Type
    ASSERT_STREQ("0", tArray["type"].c_str());


    //  Type 1
    auto secondSignatureRegistration = Ark::Crypto::Transactions::Builder::buildSecondSignatureRegistration("Secret passphrase", "Second Secret passphrase");
    std::map<std::string, std::string> ssArray = secondSignatureRegistration.toArray();

    //  Amount
    ASSERT_STREQ("0", ssArray["amount"].c_str());
    //  Asset
    ASSERT_STREQ("02e1684d8990c0a5625aec85977fcf22204884bc08d45dbc71b2859e5fa4f45104", ssArray["publicKey"].c_str());
    //  Fee
    ASSERT_STREQ("500000000", ssArray["fee"].c_str());
    //  Id
    ASSERT_STRNE("", ssArray["id"].c_str());
    //  RecipientId
    ASSERT_STREQ("", ssArray["recipientId"].c_str());
    //  SecondSignature
    ASSERT_STRNE("", ssArray["secondSignature"].c_str());
    //  SenderPublicKey
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", ssArray["senderPublicKey"].c_str());
    //  Signature
    ASSERT_STRNE("", ssArray["signature"].c_str());
    //  Timestamp
    ASSERT_STRNE("", ssArray["timestamp"].c_str());
    //  Type
    ASSERT_STREQ("1", ssArray["type"].c_str());


    //  Type 2
    auto delegateRegistration = Ark::Crypto::Transactions::Builder::buildDelegateRegistration("testName", "Secret passphrase");
    std::map<std::string, std::string> dArray = delegateRegistration.toArray();

    //  Amount
    ASSERT_STREQ("0", dArray["amount"].c_str());
    //  Asset
    ASSERT_STREQ("testName", dArray["username"].c_str());
    //  Fee
    ASSERT_STREQ("2500000000", dArray["fee"].c_str());
    //  Id
    ASSERT_STRNE("", dArray["id"].c_str());
    //  RecipientId
    ASSERT_STREQ("", dArray["recipientId"].c_str());
    //  SecondSignature
    ASSERT_STREQ("", dArray["secondSignature"].c_str());
    //  SenderPublicKey
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", dArray["senderPublicKey"].c_str());
    //  Signature
    ASSERT_STRNE("", dArray["signature"].c_str());
    //  Timestamp
    ASSERT_STRNE("", dArray["timestamp"].c_str());
    //  Type
    ASSERT_STREQ("2", dArray["type"].c_str());


    //  Type 3
    std::vector<std::string> votes = { "-0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6", "+0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6" };
    auto vote = Ark::Crypto::Transactions::Builder::buildVote(votes, "Secret passphrase");
    std::map<std::string, std::string> vArray = vote.toArray();

    //  Amount
    ASSERT_STREQ("0", vArray["amount"].c_str());
    //  Asset
    ASSERT_STREQ("-0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6,+0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6", vArray["votes"].c_str());
    //  Fee
    ASSERT_STREQ("100000000", vArray["fee"].c_str());
    //  Id
    ASSERT_STRNE("", vArray["id"].c_str());
    //  RecipientId
    ASSERT_STREQ("DPgZq5MK6rm5yVks9b7TrA22F8FwRvkCtF", vArray["recipientId"].c_str());
    //  SecondSignature
    ASSERT_STREQ("", vArray["secondSignature"].c_str());
    //  SenderPublicKey
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", vArray["senderPublicKey"].c_str());
    //  Signature
    ASSERT_STRNE("", vArray["signature"].c_str());
    //  Timestamp
    ASSERT_STRNE("", vArray["timestamp"].c_str());
    //  Type
    ASSERT_STREQ("3", vArray["type"].c_str());
}

TEST(transactions, transaction_to_json) {

    //  Type 0
    auto transfer = Ark::Crypto::Transactions::Builder::buildTransfer("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", 1, "", "Secret passphrase");
    std::string tJson = transfer.toJson();

    const size_t tCapacity = JSON_OBJECT_SIZE(8) + 450;
    DynamicJsonBuffer tJsonBuffer(tCapacity);

    JsonObject& tRoot = tJsonBuffer.parseObject(tJson);

    ASSERT_EQ(tRoot["amount"], 1);
    ASSERT_EQ(tRoot["fee"], 10000000);
    ASSERT_STRNE("", tRoot["id"].as<const char*>());
    ASSERT_STREQ("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", tRoot["recipientId"].as<const char*>());
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", tRoot["senderPublicKey"].as<const char*>());
    ASSERT_STRNE("", tRoot["signature"].as<const char*>());
    ASSERT_GT(tRoot["timestamp"], 50000000);
    ASSERT_LT(tRoot["timestamp"], 1000000000);
    ASSERT_EQ(tRoot["type"], 0);


    //  Type 1
    auto secondSignatureRegistration = Ark::Crypto::Transactions::Builder::buildSecondSignatureRegistration("Secret passphrase", "Second Secret passphrase");
    std::string ssJson = secondSignatureRegistration.toJson();

    const size_t ssCapacity = 2*JSON_OBJECT_SIZE(1) + JSON_OBJECT_SIZE(10) + 690;
    DynamicJsonBuffer ssJsonBuffer(ssCapacity);

    JsonObject& ssRoot = ssJsonBuffer.parseObject(ssJson);

    ASSERT_EQ(ssRoot["amount"], 0);
    ASSERT_STREQ("02e1684d8990c0a5625aec85977fcf22204884bc08d45dbc71b2859e5fa4f45104", ssRoot["asset"]["signature"]["publicKey"].as<const char*>());
    ASSERT_EQ(ssRoot["fee"], 500000000);
    ASSERT_STRNE("", ssRoot["id"].as<const char*>());
    ASSERT_STREQ("", ssRoot["recipientId"].as<const char*>());
    ASSERT_STRNE("", ssRoot["secondSignature"].as<const char*>());
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", ssRoot["senderPublicKey"].as<const char*>());
    ASSERT_STRNE("", ssRoot["signature"].as<const char*>());
    ASSERT_GT(ssRoot["timestamp"], 50000000);
    ASSERT_LT(ssRoot["timestamp"], 1000000000);
    ASSERT_EQ(ssRoot["type"], 1);


    //  Type 2
    auto delegateRegistration = Ark::Crypto::Transactions::Builder::buildDelegateRegistration("testName", "Secret passphrase");
    std::string dJson = delegateRegistration.toJson();

    const size_t dCapacity = 2*JSON_OBJECT_SIZE(1) + JSON_OBJECT_SIZE(9) + 450;
    DynamicJsonBuffer dJsonBuffer(dCapacity);

    JsonObject& dRoot = dJsonBuffer.parseObject(dJson);

    ASSERT_EQ(dRoot["amount"], 0);
    ASSERT_STREQ("testName", dRoot["asset"]["delegate"]["username"].as<const char*>());
    ASSERT_EQ(dRoot["fee"], 2500000000);
    ASSERT_STRNE("", dRoot["id"].as<const char*>());
    ASSERT_STREQ("", dRoot["recipientId"].as<const char*>());
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", dRoot["senderPublicKey"].as<const char*>());
    ASSERT_STRNE("", dRoot["signature"].as<const char*>());
    ASSERT_GT(dRoot["timestamp"], 50000000);
    ASSERT_LT(dRoot["timestamp"], 1000000000);
    ASSERT_EQ(dRoot["type"], 2);


    //  Type 3
    std::vector<std::string> votes = { "-0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6,+0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6" };
    auto vote = Ark::Crypto::Transactions::Builder::buildVote(votes, "Secret passphrase");
    std::string vJson = vote.toJson();

    const size_t vCapacity = JSON_ARRAY_SIZE(1) + JSON_OBJECT_SIZE(1) + JSON_OBJECT_SIZE(9) + 540;
    DynamicJsonBuffer vJsonBuffer(vCapacity);

    JsonObject& vRoot = vJsonBuffer.parseObject(vJson);

    ASSERT_EQ(vRoot["amount"], 0);
    ASSERT_STREQ("-0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6", vRoot["asset"]["votes"][0].as<const char*>());
    ASSERT_STREQ("+0250b742256f9321bd7d46f3ed9769b215a7c2fb02be951acf43bc51eb57ceadf6", vRoot["asset"]["votes"][1].as<const char*>());
    ASSERT_EQ(vRoot["fee"], 100000000);
    ASSERT_STRNE("", vRoot["id"].as<const char*>());
    ASSERT_STREQ("DPgZq5MK6rm5yVks9b7TrA22F8FwRvkCtF", vRoot["recipientId"].as<const char*>());
    ASSERT_STREQ("02f21aca9b6d224ea86a1689f57910534af21c3cc9f80602fed252c13e275f0699", vRoot["senderPublicKey"].as<const char*>());
    ASSERT_STRNE("", vRoot["signature"].as<const char*>());
    ASSERT_GT(vRoot["timestamp"], 50000000);
    ASSERT_LT(vRoot["timestamp"], 1000000000);
    ASSERT_EQ(vRoot["type"], 3);
};
