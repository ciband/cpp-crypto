#include "transactions/transaction.h"
#include "bcl/Sha256.hpp"
#include "helpers/crypto.h"
#include "helpers/helpers.h"
#include "identities/privatekey.h"
#include "identities/address.h"
#include "enums/types.h"

using namespace Ark::Crypto::Identities;

Ark::Crypto::Transactions::Transaction::Transaction()
{

}

std::string Ark::Crypto::Transactions::Transaction::getId() const
{
    auto bytes = this->toBytes(false, false);
    const auto shaHash = Sha256::getHash(&bytes[0], bytes.size());
    memcpy(&bytes[0], shaHash.value, shaHash.HASH_LEN);
    return BytesToHex(&bytes[0], &bytes[0] + shaHash.HASH_LEN);
}

std::string Ark::Crypto::Transactions::Transaction::sign(const char* passphrase)
{
    PrivateKey privateKey = PrivateKey::fromPassphrase(passphrase);
    this->senderPublicKey = Identities::PublicKey::fromPrivateKey(privateKey).toString();

    const auto bytes = this->toBytes();
    const auto hash = Sha256::getHash(&bytes[0], bytes.size());

    std::vector<uint8_t> buffer;
    cryptoSign(hash, privateKey, buffer);

    this->signature = BytesToHex(buffer.begin(), buffer.end());
    return this->signature;
}

std::string Ark::Crypto::Transactions::Transaction::secondSign(const char* passphrase)
{
    PrivateKey privateKey = PrivateKey::fromPassphrase(passphrase);
    const auto bytes = this->toBytes(false);
    const auto hash = Sha256::getHash(&bytes[0], bytes.size());

    std::vector<uint8_t> buffer;
    cryptoSign(hash, privateKey, buffer);

    this->secondSignature = BytesToHex(buffer.begin(), buffer.end());
    return this->secondSignature;
}

bool Ark::Crypto::Transactions::Transaction::verify() const
{
    return this->internalVerify(this->senderPublicKey, this->toBytes(), this->signature);
}

bool Ark::Crypto::Transactions::Transaction::secondVerify(const char* secondPublicKey) const
{
    return this->internalVerify(secondPublicKey, this->toBytes(false), this->secondSignature);
}

std::vector<uint8_t> Ark::Crypto::Transactions::Transaction::toBytes(bool skipSignature, bool skipSecondSignature) const
{
    std::vector<uint8_t> bytes;

    pack(bytes, this->type);
    pack(bytes, this->timestamp);

    const auto senderKeyBytes = HexToBytes(this->senderPublicKey.c_str());
    bytes.insert(std::end(bytes), std::begin(senderKeyBytes), std::end(senderKeyBytes));

    const auto skipRecipientId = type == Enums::Types::SECOND_SIGNATURE_REGISTRATION || type == Enums::Types::MULTI_SIGNATURE_REGISTRATION;
    if (!this->recipientId.empty() && !skipRecipientId) {
        std::vector<std::uint8_t> recipientIdBytes = Address::bytesFromBase58Check(this->recipientId.c_str());
        bytes.insert(bytes.end(), recipientIdBytes.begin(), recipientIdBytes.end());
    } else {
        std::vector<uint8_t> filler(21, 0);
        bytes.insert(bytes.end(), filler.begin(), filler.end());
    }

    if (!this->vendorField.empty()) {
        bytes.insert(bytes.end(), this->vendorField.begin(), this->vendorField.end());

        size_t diff = 64 - vendorField.length();
        if (diff > 0) {
            std::vector<uint8_t> filler(diff, 0);
            bytes.insert(bytes.end(), filler.begin(), filler.end());
        }

    } else {
        std::vector<uint8_t> filler(64, 0);
        bytes.insert(bytes.end(), filler.begin(), filler.end());
    }

    pack(bytes, this->amount);
    pack(bytes, this->fee);

    if (type == Enums::Types::SECOND_SIGNATURE_REGISTRATION) {
        const auto publicKeyBytes = HexToBytes(this->asset.signature.publicKey.c_str());
        bytes.insert(bytes.end(), publicKeyBytes.begin(), publicKeyBytes.end());

    } else if (type == Enums::Types::DELEGATE_REGISTRATION) {
        bytes.insert(bytes.end(), this->asset.delegate.username.begin(), this->asset.delegate.username.end());

    } else if (type == Enums::Types::VOTE) {
        const auto joined = join(this->asset.votes);
        bytes.insert(bytes.end(), joined.begin(), joined.end());

    } else if (type == Enums::Types::MULTI_SIGNATURE_REGISTRATION) {
        pack(bytes, this->asset.multiSignature.min);
        pack(bytes, this->asset.multiSignature.lifetime);
        const auto joined = join(this->asset.multiSignature.keysgroup);
        bytes.insert(bytes.end(), joined.begin(), joined.end());
    }

    if (!skipSignature && !this->signature.empty()) {
        const auto signatureBytes = HexToBytes(this->signature.c_str());
        bytes.insert(bytes.end(), signatureBytes.begin(), signatureBytes.end());
    }

    if (!skipSecondSignature && !this->secondSignature.empty()) {
        const auto secondSignatureBytes = HexToBytes(this->secondSignature.c_str());
        bytes.insert(bytes.end(), secondSignatureBytes.begin(), secondSignatureBytes.end());
    }

    return bytes;
}

bool Ark::Crypto::Transactions::Transaction::internalVerify(std::string publicKey, std::vector<uint8_t> bytes, std::string signature) const
{
    const auto hash = Sha256::getHash(&bytes[0], bytes.size());
    const auto key = Identities::PublicKey::fromHex(publicKey.c_str());
    auto signatureBytes = HexToBytes(signature.c_str());
    return cryptoVerify(key, hash, signatureBytes);
}

