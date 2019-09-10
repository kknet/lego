#include <stdlib.h>
#include <math.h>

#include <iostream>
#include <vector>

#include <gtest/gtest.h>
#include "openssl/aes.h"

#include "common/random.h"
#include "security/schnorr.h"
#include "security/multi_sign.h"
#include "security/ecdh_create_key.h"
#include "security/aes.h"

namespace lego {

namespace security {

namespace test {

class TestMultiSign : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(TestMultiSign, TestCurveSetup) {
    std::cout << "test 1" << std::endl;
    Schnorr& schnorr = *Schnorr::Instance();
    std::cout << "test 2" << std::endl;

    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> a(BN_new(), BN_clear_free);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> b(BN_new(), BN_clear_free);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> p(BN_new(), BN_clear_free);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> h(BN_new(), BN_clear_free);
    std::cout << "test 3" << std::endl;

    const char* order_expected = (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    const char* basept_expected = (
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    const char* p_expected = (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    const char* a_expected = "0";
    const char* b_expected = "07";
    const char* h_expected = "01";
    std::cout << "test 4" << std::endl;

    std::unique_ptr<char, void(*)(void*)> order_actual(
            BN_bn2hex(schnorr.curve().order_.get()),
            free);
    ASSERT_TRUE(strcmp(order_expected, order_actual.get()) == 0);
    std::cout << "test 5" << std::endl;

    std::unique_ptr<char, void(*)(void*)> basept_actual(EC_POINT_point2hex(
            schnorr.curve().group_.get(),
            EC_GROUP_get0_generator(schnorr.curve().group_.get()),
            POINT_CONVERSION_COMPRESSED, NULL),
            free);
    std::cout << "test 6" << std::endl;
    ASSERT_TRUE(strcmp(basept_expected, basept_actual.get()) == 0);

    if ((a != nullptr) && (b != nullptr) && (p != nullptr) && (h != nullptr)) {
        ASSERT_TRUE(EC_GROUP_get_curve_GFp(
                schnorr.curve().group_.get(),
                p.get(),
                a.get(),
                b.get(),
                NULL) != 0);
        ASSERT_TRUE(EC_GROUP_get_cofactor(schnorr.curve().group_.get(), h.get(), NULL) != 0);
        std::cout << "test 7" << std::endl;

        std::unique_ptr<char, void(*)(void*)> p_actual(BN_bn2hex(p.get()), free);
        std::unique_ptr<char, void(*)(void*)> a_actual(BN_bn2hex(a.get()), free);
        std::unique_ptr<char, void(*)(void*)> b_actual(BN_bn2hex(b.get()), free);
        std::unique_ptr<char, void(*)(void*)> h_actual(BN_bn2hex(h.get()), free);
        std::cout << "test 8" << std::endl;

        ASSERT_TRUE(strcmp(p_expected, p_actual.get()) == 0);
        ASSERT_TRUE(strcmp(a_expected, a_actual.get()) == 0);
        ASSERT_TRUE(strcmp(b_expected, b_actual.get()) == 0);
        ASSERT_TRUE(strcmp(h_expected, h_actual.get()) == 0);
    }
    std::cout << "test 9" << std::endl;
}

TEST_F(TestMultiSign, TestKeys) {
    Schnorr& schnorr = *Schnorr::Instance();

    std::unique_ptr<EC_POINT, void(*)(EC_POINT*)> P(EC_POINT_new(
            schnorr.curve().group_.get()),
            EC_POINT_clear_free);
    PrivateKey prikey;
    PublicKey pubkey;
    schnorr.GenPublicKey(prikey, pubkey);

    ASSERT_TRUE(BN_cmp(prikey.bignum().get(), schnorr.curve().order_.get()) == -1);
    ASSERT_TRUE(BN_is_zero(prikey.bignum().get()) != 1);

    ASSERT_TRUE(EC_POINT_mul(
            schnorr.curve().group_.get(),
            P.get(),
            prikey.bignum().get(),
            NULL,
            NULL,
            NULL) != 0);
    ASSERT_TRUE(EC_POINT_cmp(
            schnorr.curve().group_.get(),
            pubkey.ec_point().get(),
            P.get(),
            NULL) == 0);
}

TEST_F(TestMultiSign, TestSignVerif) {
    Schnorr& schnorr = *Schnorr::Instance();
    PrivateKey prikey;
    PublicKey pubkey;
    schnorr.GenPublicKey(prikey, pubkey);

    const uint32_t message_size = 1048576;
    std::string message_rand = common::Random::RandomString(message_size);
    std::string message_1(message_size, 0x01);

    Signature signature;
    ASSERT_TRUE(schnorr.Sign(message_rand, prikey, pubkey, signature));

    ASSERT_TRUE(BN_cmp(signature.challenge().get(), schnorr.curve().order_.get()) == -1);
    ASSERT_TRUE(BN_is_zero(signature.challenge().get()) != 1);
    ASSERT_TRUE(BN_cmp(signature.response().get(), schnorr.curve().order_.get()) == -1);
    ASSERT_TRUE(BN_is_zero(signature.response().get()) != 1);

    ASSERT_TRUE(schnorr.Verify(message_rand, signature, pubkey));
    ASSERT_FALSE(schnorr.Verify(message_1, signature, pubkey));
}

TEST_F(TestMultiSign, TestPerformance) {
    Schnorr& schnorr = *Schnorr::Instance();
    PrivateKey prikey;
    PublicKey pubkey;
    schnorr.GenPublicKey(prikey, pubkey);
    const uint32_t message_sizes[] = {
        128 * 1024,      256 * 1024,       512 * 1024,
        1 * 1024 * 1024, 2 * 1024 * 1024,  4 * 1024 * 1024,
        8 * 1024 * 1024, 16 * 1024 * 1024, 32 * 1024 * 1024 };
    const char* printable_sizes[] = { "128kB", "256kB", "512kB", "1MB", "2MB",
                                     "4MB",   "8MB",   "16MB",  "32MB" };
    const uint32_t num_messages = sizeof(message_sizes) / sizeof(message_sizes[0]);
    for (uint32_t i = 0; i < num_messages; i++) {
        std::string message_rand = common::Random::RandomString(message_sizes[i]);
        Signature signature;
        auto start_time = std::chrono::system_clock::now();
        ASSERT_TRUE(schnorr.Sign(message_rand, prikey, pubkey, signature));
        auto difference1 = std::chrono::system_clock::now() - start_time;
        auto use_time1 = difference1.count();
        std::cout << "Message size  = " << printable_sizes[i] << std::endl;
        std::cout << "Verify (usec) = " << use_time1 << std::endl;

        ASSERT_TRUE(BN_cmp(signature.challenge().get(), schnorr.curve().order_.get()) == -1);
        ASSERT_TRUE(BN_is_zero(signature.challenge().get()) != 1);
        ASSERT_TRUE(BN_cmp(signature.response().get(), schnorr.curve().order_.get()) == -1);
        ASSERT_TRUE(BN_is_zero(signature.response().get()) != 1);

        auto difference = std::chrono::system_clock::now() - start_time;
        auto use_time = difference.count();
        ASSERT_TRUE(schnorr.Verify(message_rand, signature, pubkey));
        std::cout << "Message size  = " << printable_sizes[i] << std::endl;
        std::cout << "Verify (usec) = " << use_time << std::endl;
    }
}

TEST_F(TestMultiSign, SchnorrTestSerialization) {
    Schnorr& schnorr = *Schnorr::Instance();
    PrivateKey prikey;
    PublicKey pubkey;
    schnorr.GenPublicKey(prikey, pubkey);
    const uint32_t message_size = 1048576;
    std::string message = common::Random::RandomString(message_size);
    Signature signature;
    ASSERT_TRUE(schnorr.Sign(message, prikey, pubkey, signature));
    ASSERT_TRUE(schnorr.Verify(message, signature, pubkey));

    std::string privkey_str;
    prikey.Serialize(privkey_str);
    std::string pubkey_str;
    pubkey.Serialize(pubkey_str);
    std::string signature_challenge_str;
    std::string signature_response_str;
    signature.Serialize(signature_challenge_str, signature_response_str);

    PrivateKey privkey1(privkey_str);
    PublicKey pubkey1(pubkey_str);
    Signature signature1(signature_challenge_str, signature_response_str);
    ASSERT_TRUE(prikey == privkey1);
    ASSERT_TRUE(pubkey == pubkey1);
    ASSERT_TRUE(signature == signature1);

    PrivateKey privkey2;
    privkey2 = privkey1;

    PublicKey pubkey2;
    pubkey2 = pubkey1;
    ASSERT_TRUE(!(pubkey2 > pubkey1));

    PrivateKey gen_prikey;
    PublicKey gen_pubkey;
    schnorr.GenPublicKey(gen_prikey, gen_pubkey);
    std::string message_rand = common::Random::RandomString(message_size);
    Signature signature2;
    ASSERT_TRUE(schnorr.Sign(message_rand, gen_prikey, gen_pubkey, signature2));
    ASSERT_TRUE(schnorr.Verify(message_rand, signature2, gen_pubkey));

    gen_prikey.Deserialize(privkey_str);
    gen_pubkey.Deserialize(pubkey_str);
    signature2.Deserialize(signature_challenge_str, signature_response_str);
    ASSERT_TRUE(prikey == gen_prikey);
    ASSERT_TRUE(pubkey == gen_pubkey);
    ASSERT_TRUE(signature == signature2);
}

TEST_F(TestMultiSign, TestErrorDeserializationPubkey) {
    PublicKey pubkey;
    std::string pubkey_bytes_empty;
    int returnValue = pubkey.Deserialize(pubkey_bytes_empty);
    ASSERT_TRUE(returnValue == -1);
}

TEST_F(TestMultiSign, TestErrorDeserializationPrivkey) {
    PrivateKey privkey;
    std::string privkey_bytes_empty;
    int returnValue = privkey.Deserialize(privkey_bytes_empty);
    ASSERT_TRUE(returnValue == -1);
}

TEST_F(TestMultiSign, TestErrorDeserializationSignature) {
    Signature signature;
    std::string sig_challenge_empty;
    std::string sig_response_empty;
    int res = signature.Deserialize(sig_challenge_empty, sig_response_empty);
    ASSERT_TRUE(res == -1);
}

TEST_F(TestMultiSign, TestEcdhCreateKey) {
    PrivateKey prikey;
    PublicKey pubkey(prikey);
    Schnorr::Instance()->set_prikey(std::make_shared<PrivateKey>(prikey));
    Schnorr::Instance()->set_pubkey(std::make_shared<PublicKey>(pubkey));
    ASSERT_TRUE(EcdhCreateKey::Instance()->Init() == kSecuritySuccess);
    std::string sec_key;

    PrivateKey peer_prikey;
    PublicKey peer_pubkey(peer_prikey);
    std::string sec_key1;
    ASSERT_TRUE(EcdhCreateKey::Instance()->CreateKey(
            peer_pubkey,
            sec_key1) == kSecuritySuccess);

    Schnorr::Instance()->set_prikey(std::make_shared<PrivateKey>(peer_prikey));
    Schnorr::Instance()->set_pubkey(std::make_shared<PublicKey>(peer_pubkey));
    std::string sec_key2;
    ASSERT_TRUE(EcdhCreateKey::Instance()->Init() == kSecuritySuccess);
    EcdhCreateKey::Instance()->CreateKey(pubkey, sec_key2);
    std::cout << sec_key1.size() << ":" << common::Encode::HexEncode(sec_key1) << std::endl;
    ASSERT_EQ(sec_key1, sec_key2);

    for (int i = 1; i < 100; ++i) {
//         {
//             std::string test_aes = common::Random::RandomString(i);
//             std::string enc_out;
//             ASSERT_EQ(Aes::Encrypt(test_aes, sec_key1, enc_out), kSecuritySuccess);
//             std::string dec_out;
//             ASSERT_EQ(Aes::Decrypt(enc_out, sec_key1, dec_out), kSecuritySuccess);
//             ASSERT_EQ(test_aes, dec_out);
//         }

        {
            std::string test_aes = common::Random::RandomString(i);
            uint32_t data_size = (i / AES_BLOCK_SIZE) * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
            char* tmp_out_enc = (char*)malloc(data_size);
            memset(tmp_out_enc, 0, data_size);
            ASSERT_EQ(Aes::CfbEncrypt(
                    (char*)test_aes.c_str(),
                    test_aes.size(),
                    (char*)sec_key1.c_str(),
                    sec_key1.size(),
                    tmp_out_enc), kSecuritySuccess);
            std::string enc_out(tmp_out_enc, data_size);
            std::cout << common::Encode::HexEncode(test_aes) << ":" << common::Encode::HexEncode(enc_out) << std::endl;

            memset(tmp_out_enc, 0, data_size);
            ASSERT_EQ(
                    Aes::CfbDecrypt((char*)enc_out.c_str(), i, (char*)sec_key1.c_str(), sec_key1.size(), tmp_out_enc),
                    kSecuritySuccess);
            std::string enc_out2(i, 0);
            memcpy((char*)&enc_out2[0], tmp_out_enc, i);
            std::cout << "enc_out2.size()" << enc_out2.size() << std::endl;
            ASSERT_EQ(test_aes, enc_out2);
            free(tmp_out_enc);
        }
    }
}

TEST_F(TestMultiSign, TestMultisign) {
    using namespace std;
    Schnorr& schnorr = *Schnorr::Instance();
    MultiSign& multisig = *MultiSign::Instance();

    const uint32_t nbsigners = 2000;
    vector<PrivateKey> privkeys;
    vector<PublicKey> pubkeys;
    for (uint32_t i = 0; i < nbsigners; i++) {
        PrivateKey pri_key;
        PublicKey pub_key;
        schnorr.GenPublicKey(pri_key, pub_key);
        privkeys.emplace_back(pri_key);
        pubkeys.emplace_back(pub_key);
    }

    const uint32_t message_size = 1048576;
    std::string message_rand = common::Random::RandomString(message_size);
    std::string message_1(message_size, 0x01);

    shared_ptr<PublicKey> agg_pubkey = MultiSign::AggregatePubKeys(pubkeys);
    ASSERT_TRUE(agg_pubkey != nullptr);

    vector<CommitSecret> secrets(nbsigners);
    vector<CommitPoint> points;
    for (uint32_t i = 0; i < nbsigners; i++) {
        points.emplace_back(secrets.at(i));
    }

    shared_ptr<CommitPoint> agg_commit = MultiSign::AggregateCommits(points);
    ASSERT_TRUE(agg_commit != nullptr);

    Challenge challenge(*agg_commit, *agg_pubkey, message_rand);
    ASSERT_TRUE(challenge.inited());

    Challenge challenge_copy(challenge);
    ASSERT_TRUE(challenge == challenge_copy);

    vector<Response> responses;
    vector<PublicKey> pubkeys_res;
    for (uint32_t i = 0; i < nbsigners; i++) {
        responses.emplace_back(secrets.at(i), challenge, privkeys.at(i));
        ASSERT_TRUE(responses.back().inited());
        pubkeys_res.emplace_back(pubkeys[i]);
    }

    shared_ptr<PublicKey> agg_pubkey_res = MultiSign::AggregatePubKeys(pubkeys_res);
    ASSERT_TRUE(agg_pubkey_res != nullptr);
    shared_ptr<Response> agg_response = MultiSign::AggregateResponses(responses);
    ASSERT_TRUE(agg_response != nullptr);

    shared_ptr<Signature> signature = MultiSign::AggregateSign(challenge, *agg_response);
    ASSERT_TRUE(signature != nullptr);

    ASSERT_TRUE(multisig.MultiSigVerify(
            message_rand,
            *signature,
            *agg_pubkey_res));
    ASSERT_FALSE(multisig.MultiSigVerify(
            message_1,
            *signature,
            *agg_pubkey_res));

    CommitPoint cp_copy;
    cp_copy = *agg_commit;
    ASSERT_TRUE(cp_copy == *agg_commit);

    Challenge challenge_copy1;
    challenge_copy1 = challenge;
    ASSERT_TRUE(challenge_copy1 == challenge);

    Response response_copy;
    response_copy = *agg_response;
    ASSERT_TRUE(response_copy == *agg_response);
}

TEST_F(TestMultiSign, TestSerialization) {
    Schnorr& schnorr = *Schnorr::Instance();
    MultiSign& multisig = *MultiSign::Instance();

    const uint32_t nbsigners = 80;
    std::vector<PrivateKey> privkeys;
    std::vector<PublicKey> pubkeys;
    for (uint32_t i = 0; i < nbsigners; i++) {
        PrivateKey prikey;
        PublicKey pubkey;
        schnorr.GenPublicKey(prikey, pubkey);
        privkeys.emplace_back(prikey);
        pubkeys.emplace_back(pubkey);
    }

    const uint32_t message_size = 1048576;
    std::string message_rand = common::Random::RandomString(message_size);
    std::string message_1(message_size, 0x01);

    std::shared_ptr<PublicKey> agg_pubkey = MultiSign::AggregatePubKeys(pubkeys);
    ASSERT_TRUE(agg_pubkey != nullptr);

    std::vector<CommitSecret> secrets(nbsigners);
    std::vector<CommitPoint> points;
    std::vector<CommitSecret> secrets1;
    std::vector<CommitPoint> points1;
    for (uint32_t i = 0; i < nbsigners; i++) {
        std::string tmp1, tmp2;
        secrets.at(i).Serialize(tmp1);
        secrets1.emplace_back(tmp1);
        points.emplace_back(secrets.at(i));
        points.back().Serialize(tmp2);
        points1.emplace_back(tmp2);
    }

    CommitSecret dummy_secret;
    dummy_secret = secrets.at(0);
    ASSERT_TRUE(dummy_secret == secrets.at(0));

    std::shared_ptr<CommitPoint> agg_commit = MultiSign::AggregateCommits(points);
    ASSERT_TRUE(agg_commit != nullptr);
    std::shared_ptr<CommitPoint> agg_commit1 = MultiSign::AggregateCommits(points1);
    ASSERT_TRUE(*agg_commit == *agg_commit1);

    Challenge challenge(*agg_commit, *agg_pubkey, message_rand);
    ASSERT_TRUE(challenge.inited());
    std::string tmp;
    challenge.Serialize(tmp);
    Challenge challenge2(tmp);
    ASSERT_TRUE(challenge == challenge2);
    tmp.clear();

    std::vector<Response> responses;
    std::vector<Response> responses1;
    for (uint32_t i = 0; i < nbsigners; i++) {
        responses.emplace_back(secrets.at(i), challenge, privkeys.at(i));
        ASSERT_TRUE(responses.back().inited());
        std::string tmp;
        responses.back().Serialize(tmp);
        responses1.emplace_back(tmp);
        ASSERT_TRUE(MultiSign::VerifyResponse(
                responses.at(i),
                challenge,
                pubkeys.at(i),
                points.at(i)));
    }

    std::shared_ptr<Response> agg_res = MultiSign::AggregateResponses(responses);
    ASSERT_TRUE(agg_res != nullptr);
    std::shared_ptr<Response> agg_res1 = MultiSign::AggregateResponses(responses1);
    ASSERT_TRUE(*agg_res == *agg_res1);

    std::shared_ptr<Signature> signature = MultiSign::AggregateSign(challenge, *agg_res);
    ASSERT_TRUE(signature != nullptr);

    /// Verify the signature
    ASSERT_TRUE(multisig.MultiSigVerify(message_rand, *signature, *agg_pubkey));
    ASSERT_FALSE(multisig.MultiSigVerify(message_1, *signature, *agg_pubkey));
}

}  // namespace test

}  // namespace security

}  // namespace lego
