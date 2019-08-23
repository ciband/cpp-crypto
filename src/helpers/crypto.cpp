
#include "helpers/crypto.h"

#include "bcl/Ecdsa.hpp"
#include "bcl/Sha256.hpp"
#include "bcl/Uint256.hpp"
#include "bip66.h"
#include "helpers/crypto_helpers.h"
#include "identities/privatekey.hpp"
#include "identities/publickey.hpp"
#include "rfc6979/rfc6979.h"
#include "uECC.h"
#include "utils/hex.hpp"

#include "InfInt.h"

void cryptoSignECDSA(
    const Sha256Hash& hash,
    const Ark::Crypto::identities::PrivateKey& privateKey,
    std::vector<uint8_t>& signature) {
  // create r & s-values
  Uint256 r;
  Uint256 s;

  // create the nonce
  uint8_t nonce32[32] = {};
  nonce_function_rfc6979(
      nonce32,
      hash.value,
      privateKey.toBytes().data(),
      nullptr, nullptr, 0);

  // sign the hash using privateKey-bytes and nonce.
  // outputs r & s-values.
  Ecdsa::sign(
      Uint256(privateKey.toBytes().data()),
      hash,
      Uint256(nonce32),
      r, s);

  // create r & s-value uint8_t vector
  std::vector<uint8_t> rValue(PRIVATEKEY_SIZE);
  std::vector<uint8_t> sValue(PRIVATEKEY_SIZE);

  // plate big-endian bytes into r & s-value buffers
  r.getBigEndianBytes(&rValue[0]);
  s.getBigEndianBytes(&sValue[0]);

  // encode r & s-values into a BIP66/DER-encoded signature.
  BIP66::encode(rValue, sValue, signature);
}

/**/

bool cryptoVerifyECDSA(
    const Ark::Crypto::identities::PublicKey& publicKey,
    const Sha256Hash& hash,
    const std::vector<uint8_t>& signature) {
  // Get the Uncompressed PublicKey

  // compressed publicKey bytes (uint8_t*)
  auto publicKeyBytes = publicKey.toBytes();

  // create uncompressed publicKey buffer (uint8_t[64])
  uint8_t uncompressedPublicKey[64] = {};

  // define the curve-type
  const struct uECC_Curve_t* curve = uECC_secp256k1();

  // decompress the key
  uECC_decompress(publicKeyBytes.data(), uncompressedPublicKey, curve);
  if (uECC_valid_public_key(uncompressedPublicKey, curve) == 0) {
    return false;
  };  // validate the uncompressed publicKey

  // Split uncompressed publicKey into (x,y) coordinate buffers
  char xBuffer[65] = "\0";
  char yBuffer[65] = "\0";
  for (int i = 0; i < 32; i++) {
    snprintf(&xBuffer[i * 2], 64, "%02x", uncompressedPublicKey[i]);
    snprintf(&yBuffer[i * 2], 64, "%02x", uncompressedPublicKey[i + 32]);
  }

  // Create curvepoint of uncompressed publicKey(x,y)
  // convert xBuffer & yBuffer to FieldInteger
  FieldInt x(xBuffer);
  FieldInt y(yBuffer);
  CurvePoint curvePoint(x, y);

  /// Decode signature from DER into r & s buffers
  std::vector<uint8_t> rValue(PRIVATEKEY_SIZE);
  std::vector<uint8_t> sValue(PRIVATEKEY_SIZE);
  BIP66::decode(signature, rValue, sValue);

  // create Uint256/BigNumber from r & s-value buffers
  Uint256 r256(rValue.data());
  Uint256 s256(sValue.data());

  // Verify
  return Ecdsa::verify(curvePoint, hash, r256, s256);
}

#if 0
int
bcrypto_schnorr_sign(bcrypto_ecdsa_t *ec,
                     bcrypto_ecdsa_sig_t *sig,
                     const uint8_t *msg,
                     const uint8_t *priv) {
  BIGNUM *a = NULL;
  BIGNUM *k = NULL;
  EC_POINT *R = NULL;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  EC_POINT *A = NULL;
  bcrypto_ecdsa_pubkey_t pub;
  BIGNUM *e = NULL;
  int r = 0;
  int j;

  if (!bcrypto_ecdsa_valid_scalar(ec, priv))
    goto fail;

  // The secret key d: an integer in the range 1..n-1.
  a = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());

  if (a == NULL || BN_is_zero(a) || BN_cmp(a, ec->n) >= 0)
    goto fail;

  // Let k' = int(hash(bytes(d) || m)) mod n
  k = schnorr_hash_am(ec, priv, msg);

  // Fail if k' = 0.
  if (k == NULL || BN_is_zero(k))
    goto fail;

  // Let R = k'*G.
  R = EC_POINT_new(ec->group);

  if (R == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, R, k, NULL, NULL, ec->ctx))
    goto fail;

  x = BN_new();
  y = BN_new();

  if (x == NULL || y == NULL)
    goto fail;

  // Encode x(R).
#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  // Note: should be present with 1.1.1b
  if (!EC_POINT_get_affine_coordinates(ec->group, R, x, y, ec->ctx))
#else
  if (!EC_POINT_get_affine_coordinates_GFp(ec->group, R, x, y, ec->ctx))
#endif
    goto fail;

  assert(BN_bn2binpad(x, sig->r, ec->size) != -1);

  // Encode d*G.
  A = EC_POINT_new(ec->group);

  if (A == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, A, a, NULL, NULL, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, &pub, A))
    goto fail;

  // Let e = int(hash(bytes(x(R)) || bytes(d*G) || m)) mod n.
  e = schnorr_hash_ram(ec, sig->r, &pub, msg);

  if (e == NULL)
    goto fail;

  j = BN_kronecker(y, ec->p, ec->ctx);

  if (j < -1)
    goto fail;

  // Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
  if (j != 1)
    BN_sub(k, ec->n, k);

  // Let S = k + e*d mod n.
  if (!BN_mod_mul(e, e, a, ec->n, ec->ctx))
    goto fail;

  if (!BN_mod_add(e, k, e, ec->n, ec->ctx))
    goto fail;

  assert(BN_bn2binpad(e, sig->s, ec->scalar_size) != -1);

  r = 1;
fail:
  if (a != NULL)
    BN_clear_free(a);

  if (k != NULL)
    BN_clear_free(k);

  if (R != NULL)
    EC_POINT_free(R);

  if (x != NULL)
    BN_free(x);

  if (y != NULL)
    BN_free(y);

  if (A != NULL)
    EC_POINT_free(A);

  if (e != NULL)
    BN_free(e);

  return r;
}

int
bcrypto_schnorr_verify(bcrypto_ecdsa_t *ec,
                       const uint8_t *msg,
                       const bcrypto_ecdsa_sig_t *sig,
                       const bcrypto_ecdsa_pubkey_t *pub) {
  BIGNUM *Rx = NULL;
  BIGNUM *S = NULL;
  EC_POINT *A = NULL;
  BIGNUM *e = NULL;
  EC_POINT *R = NULL;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  BIGNUM *z = NULL;
  int r = 0;

  Rx = BN_bin2bn(sig->r, ec->size, NULL);
  S = BN_bin2bn(sig->s, ec->scalar_size, NULL);
  A = bcrypto_ecdsa_pubkey_to_ec_point(ec, pub);
  e = schnorr_hash_ram(ec, sig->r, pub, msg);
  R = EC_POINT_new(ec->group);

  if (Rx == NULL || S == NULL || A == NULL || e == NULL || R == NULL)
    goto fail;

  // Let R = s*G - e*P.
  if (!BN_is_zero(e)) {
    if (!BN_sub(e, ec->n, e))
      goto fail;
  }

  if (!EC_POINT_mul(ec->group, R, S, A, e, ec->ctx))
    goto fail;

  x = BN_new();
  y = BN_new();
  z = BN_new();

  if (x == NULL || y == NULL || z == NULL)
    goto fail;

  if (!EC_POINT_get_Jprojective_coordinates_GFp(ec->group, R, x, y, z, ec->ctx))
    goto fail;

  // Check for point at infinity.
  if (BN_is_zero(z))
    goto fail;

  // Check for quadratic residue in the jacobian space.
  // Optimized as `jacobi(y(R) * z(R)) == 1`.
  if (!BN_mod_mul(e, y, z, ec->p, ec->ctx))
    goto fail;

  if (BN_kronecker(e, ec->p, ec->ctx) != 1)
    goto fail;

  // Check `x(R) == r` in the jacobian space.
  // Optimized as `x(R) == r * z(R)^2 mod p`.
  if (!BN_mod_sqr(e, z, ec->p, ec->ctx))
    goto fail;

  if (!BN_mod_mul(e, Rx, e, ec->p, ec->ctx))
    goto fail;

  if (BN_ucmp(x, e) != 0)
    goto fail;

  r = 1;
fail:
  if (Rx != NULL)
    BN_free(Rx);

  if (S != NULL)
    BN_free(S);

  if (A != NULL)
    EC_POINT_free(A);

  if (e != NULL)
    BN_free(e);

  if (R != NULL)
    EC_POINT_free(R);

  if (x != NULL)
    BN_free(x);

  if (y != NULL)
    BN_free(y);

  if (z != NULL)
    BN_free(z);

  return r;
}

#endif

static int ecdsa_valid_scalar(const Ark::Crypto::identities::PrivateKey& privateKey) {
  const auto is_mem_zero = [](const uint8_t* const mem, size_t size) -> bool {
    for (auto i = 0u; i < size; ++i) {
      if (mem[i] != 0x00) { return false; }
    }
    return true;
  };

  return !is_mem_zero(privateKey.toBytes().data(), PRIVATEKEY_SIZE) &&
         memcmp(privateKey.toBytes().data(), CurvePoint::ORDER.value, PRIVATEKEY_SIZE) < 0;
}

static Uint256 schnorr_hash_am(const Ark::Crypto::identities::PrivateKey& privateKey, const Sha256Hash& hash) {
  Sha256 hasher;
  hasher.append(privateKey.toBytes().data(), PRIVATEKEY_SIZE);
  hasher.append(hash.value, Sha256Hash::HASH_LEN);
  return Uint256(hasher.getHash().value);
}

static Ark::Crypto::identities::PublicKey ecdsa_pubkey_from_ec_point(CurvePoint& A) {
  if (A == CurvePoint::ZERO) {
    // error
  }
  A.normalize();
  //point to octet string
  std::array<uint8_t, 33> buf;
  //A.toUncompressedPoint(buf);   ??
  A.toCompressedPoint(buf.data());

  //if (buf[0] != 0x04) {
    //error
 // }
  return Ark::Crypto::identities::PublicKey(buf);
  //  auto pub = Ark::Crypto::identities::PublicKey::fromHex();
}

static Uint256 schnorr_hash_ram(const uint8_t sig_r[PRIVATEKEY_SIZE], const Ark::Crypto::identities::PublicKey& pub,
                                const uint8_t* msg) {
  //uint8_t raw[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  //uint8_t out[EVP_MAX_MD_SIZE];
  //EVP_MD_CTX* ctx = NULL;
  //BIGNUM* e = NULL;
  //size_t pub_size;
  //unsigned int hash_size;
  //
  //ctx = EVP_MD_CTX_new();
  //
  //if (ctx == NULL) goto fail;
  //
  //if (!EVP_DigestInit(ctx, ec->hash)) goto fail;
  //
  Sha256 hasher;
  //if (!EVP_DigestUpdate(ctx, r, ec->size)) goto fail;
  hasher.append(sig_r, PRIVATEKEY_SIZE);
  //
  //bcrypto_ecdsa_pubkey_encode(ec, raw, &pub_size, pub, 1);
  //
  //if (!EVP_DigestUpdate(ctx, raw, pub_size)) goto fail;
  hasher.append(pub.toBytes().data(), COMPRESSED_PUBLICKEY_SIZE);
  //
  //if (!EVP_DigestUpdate(ctx, msg, 32)) goto fail;
  hasher.append(msg, 32);

  return Uint256(hasher.getHash().value);
  //
  //if (!EVP_DigestFinal(ctx, out, &hash_size)) goto fail;
  //
  //e = BN_bin2bn(out, hash_size, NULL);
  //
  //if (e == NULL) goto fail;
  //
  //if (!BN_mod(e, e, ec->n, ec->ctx)) {
  //  BN_free(e);
  //  e = NULL;
  //  goto fail;
  //}
  //
//fail:
  //if (ctx != NULL) EVP_MD_CTX_free(ctx);
  //
  //return e;
}


void cryptoSignSchnorr(const Sha256Hash& hash, const Ark::Crypto::identities::PrivateKey& privateKey,
                       std::vector<uint8_t>& signature) {
  //  BIGNUM *a = NULL;
  //  BIGNUM *k = NULL;
  //  EC_POINT *R = NULL;
  //  BIGNUM *x = NULL;
  //  BIGNUM *y = NULL;
  //  EC_POINT *A = NULL;
  //  bcrypto_ecdsa_pubkey_t pub;
  //  BIGNUM *e = NULL;
  //  int r = 0;
  //  int j;
  //

  signature.resize(PRIVATEKEY_SIZE * 2, 0);

  //  if (!bcrypto_ecdsa_valid_scalar(ec, priv)) goto fail;
  if (!ecdsa_valid_scalar(privateKey)) {
    // error
  }

  //
  //  // The secret key d: an integer in the range 1..n-1.
  //  a = BN_bin2bn(priv, ec->scalar_size, BN_secure_new());
  Uint256 a(privateKey.toBytes().data());

  //
  //  if (a == NULL || BN_is_zero(a) || BN_cmp(a, ec->n) >= 0) goto fail;
  if (a == Uint256::ZERO || a >= CurvePoint::ORDER) {
    // error
  }

  //
  //  // Let k' = int(hash(bytes(d) || m)) mod n
  //  k = schnorr_hash_am(ec, priv, msg);
  Uint256 k = schnorr_hash_am(privateKey, hash);
  //
  //  // Fail if k' = 0.
  //  if (k == NULL || BN_is_zero(k)) goto fail;
  if (k == Uint256::ZERO) {
    // error
  }
  //
  //  // Let R = k'*G.
  //  R = EC_POINT_new(ec->group);
  CurvePoint R = CurvePoint::G;
  //
  //  if (R == NULL) goto fail;
  //
  //  if (!EC_POINT_mul(ec->group, R, k, NULL, NULL, ec->ctx)) goto fail;
  R.multiply(k);
  //
  //  x = BN_new();
  //  y = BN_new();
  //
  //  if (x == NULL || y == NULL) goto fail;
  //
  //    // Encode x(R).
  //#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  //  // Note: should be present with 1.1.1b
  //  if (!EC_POINT_get_affine_coordinates(ec->group, R, x, y, ec->ctx))
  //#else
  //  if (!EC_POINT_get_affine_coordinates_GFp(ec->group, R, x, y, ec->ctx))
  //#endif
  //    goto fail;
  R.normalize();
  FieldInt x = R.x;
  FieldInt y = R.y;

  //
  //  assert(BN_bn2binpad(x, sig->r, ec->size) != -1);
  x.getBigEndianBytes(signature.data());
  //
  //  // Encode d*G.
  //  A = EC_POINT_new(ec->group);
  CurvePoint A = CurvePoint::G;
  //
  //  if (A == NULL) goto fail;
  //
  //  if (!EC_POINT_mul(ec->group, A, a, NULL, NULL, ec->ctx)) goto fail;
  A.multiply(a);
  //
  //  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, &pub, A)) goto fail;
  auto pub = ecdsa_pubkey_from_ec_point(A);
  //
  //  // Let e = int(hash(bytes(x(R)) || bytes(d*G) || m)) mod n.
  auto e = schnorr_hash_ram(signature.data(), pub, hash.value);
  //
  //  if (e == NULL) goto fail;
  //
  //  j = BN_kronecker(y, ec->p, ec->ctx);
  FieldInt p2(CurvePoint::P);
  //auto j = y < p2 ? -1 : (y == p2 ? 0 : 1);
  int j = -1;
  uint8_t buf[32] = {};
  y.getBigEndianBytes(buf);
  printf("y=%s\n", BytesToHex(buf, buf + 32).c_str());
  printf("j=%d\n", j);
  //
  //  if (j < -1) goto fail;
  //
  //  // Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
  //  if (j != 1) BN_sub(k, ec->n, k);
  FieldInt k2(k);
  FieldInt n(CurvePoint::ORDER);
  if (j != 1) {
    k.getBigEndianBytes(buf);
    printf("k=%s\n", BytesToHex(buf, buf + 32).c_str());
    n.subtract(k2);
    k2 = n;
    k = Uint256(k2);
    k.getBigEndianBytes(buf);
    printf("result k=%s\n", BytesToHex(buf, buf + 32).c_str());
  }
  //
  //  // Let S = k + e*d mod n.
  //  if (!BN_mod_mul(e, e, a, ec->n, ec->ctx)) goto fail;
  FieldInt e2(e);
  FieldInt a2(a);
  e.getBigEndianBytes(buf);
  printf("e=%s\n", BytesToHex(buf, buf + 32).c_str());
  a.getBigEndianBytes(buf);
  printf("a=%s\n", BytesToHex(buf, buf + 32).c_str());
  e2.multiply(a2);

  e2.getBigEndianBytes(buf);
  InfInt e3(BytesToHex(buf, buf + 32), 16);
  n.getBigEndianBytes(buf);
  InfInt n2(BytesToHex(buf, buf + 32), 16);
  e3 %= n2;
  //e2.mod(n);

  //e2.multiply2();
  e2 = FieldInt(e3.toString(16).c_str());
  //e.reciprocal(CurvePoint::ORDER);
  e2.getBigEndianBytes(buf);
  printf("result e=%s\n", BytesToHex(buf, buf + 32).c_str());
  //
  //  if (!BN_mod_add(e, k, e, ec->n, ec->ctx)) goto fail;
  k = Uint256(k2);
  k.getBigEndianBytes(buf);
  printf("k=%s\n", BytesToHex(buf, buf + 32).c_str());
  e2.add(k2);
  e2.getBigEndianBytes(buf);
  e3 = InfInt(BytesToHex(buf, buf + 32), 16);
  e3 %= n2;
  e2 = FieldInt(e3.toString(16).c_str());
  //
  //  assert(BN_bn2binpad(e, sig->s, ec->scalar_size) != -1);
  e2.getBigEndianBytes(signature.data() + PRIVATEKEY_SIZE);
  //
  //  r = 1;
  // fail:
  //  if (a != NULL) BN_clear_free(a);
  //
  //  if (k != NULL) BN_clear_free(k);
  //
  //  if (R != NULL) EC_POINT_free(R);
  //
  //  if (x != NULL) BN_free(x);
  //
  //  if (y != NULL) BN_free(y);
  //
  //  if (A != NULL) EC_POINT_free(A);
  //
  //  if (e != NULL) BN_free(e);
  //
  //  return r;
}

bool cryptoVerifySchnorr(const Ark::Crypto::identities::PublicKey& publicKey, const Sha256Hash& hash,
                         const std::vector<uint8_t>& signature) {
  return false;
}
