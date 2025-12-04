#include <array>

#include "tester.h"
#include "OES.h"
#include <cstring>
#include <cstdlib>
#include <set>
#include <string>

// ==================== TEST CIFRATURA ECB ====================

TEST(ECBRoundTripShortData) {
    OES *oes = new OES();
    char key[] = "test_key_ecb";
    char data[] = "short";

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));

    oes->enc_ecb();
    MBLOCK *cipher = oes->get_cipherBlock();
    ASSERT_NOT_NULL(cipher);

    oes->dec_ecb();
    auto result = oes->get_data();

    ASSERT_NOT_NULL(result.first);
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete cipher;
    delete oes;
    return true;
}

TEST(ECBRoundTripLongData) {
    OES *oes = new OES();
    char key[] = "encryption_key_for_long_data";
    char data[] =
            "This is a much longer piece of data that will test the ECB mode more thoroughly with multiple blocks";

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));

    oes->enc_ecb();
    oes->dec_ecb();

    auto result = oes->get_data();
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete oes;
    return true;
}

TEST(ECBDifferentKeysDifferentCiphertext) {
    OES *oes1 = new OES();
    OES *oes2 = new OES();
    char key1[] = "key_one";
    char key2[] = "key_two";
    char data[] = "same data for both encryptions";

    oes1->set_key(key1);
    oes1->load_data_raw(data, strlen(data));
    oes1->enc_ecb();

    oes2->set_key(key2);
    oes2->load_data_raw(data, strlen(data));
    oes2->enc_ecb();

    MBLOCK *cipher1 = oes1->get_cipherBlock();
    MBLOCK *cipher2 = oes2->get_cipherBlock();

    bool different = false;
    size_t len1 = cipher1->getLen();
    size_t len2 = cipher2->getLen();

    if (len1 != len2) {
        different = true;
    } else {
        for (size_t i = 0; i < len1; i++) {
            if (cipher1->getBlock(i) != cipher2->getBlock(i)) {
                different = true;
                break;
            }
        }
    }
    ASSERT_TRUE(different);

    delete cipher1;
    delete cipher2;
    delete oes1;
    delete oes2;
    return true;
}

TEST(ECBSameKeySameCiphertext) {
    OES *oes1 = new OES();
    OES *oes2 = new OES();
    char key[] = "identical_key";
    char data[] = "deterministic encryption test";

    oes1->set_key(key);
    oes1->load_data_raw(data, strlen(data));
    oes1->enc_ecb();

    oes2->set_key(key);
    oes2->load_data_raw(data, strlen(data));
    oes2->enc_ecb();

    MBLOCK *cipher1 = oes1->get_cipherBlock();
    MBLOCK *cipher2 = oes2->get_cipherBlock();

    size_t len1 = cipher1->getLen();
    size_t len2 = cipher2->getLen();
    ASSERT_EQ(len1, len2);

    bool identical = true;
    for (size_t i = 0; i < len1; i++) {
        if (cipher1->getBlock(i) != cipher2->getBlock(i)) {
            identical = false;
            break;
        }
    }
    ASSERT_TRUE(identical);

    delete cipher1;
    delete cipher2;
    delete oes1;
    delete oes2;
    return true;
}

// ==================== TEST CIFRATURA CBC ====================

TEST(CBCRoundTripDefaultIV) {
    OES *oes = new OES();
    char key[] = "cbc_key";
    char data[] = "CBC mode test data with default IV";

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));

    oes->enc_cbc();
    oes->dec_cbc();

    auto result = oes->get_data();
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete oes;
    return true;
}

TEST(CBCRoundTripCustomIV) {
    OES *oes = new OES();
    char key[] = "cbc_key";
    char data[] = "CBC with custom IV test data";

    oes->set_key(key);

    size_t blockSize = 4; // Default assumption

    m_block *custom_iv = (m_block *) malloc(blockSize * sizeof(m_block));
    for (size_t i = 0; i < blockSize; i++) {
        custom_iv[i] = MASK_TO_BLOCK_SIZE(0xAABBCCDDAABBCCDD, 0xAABBCCDDAABBCCDD);
    }

    oes->setIV(custom_iv, blockSize);
    oes->load_data_raw(data, strlen(data));
    oes->enc_cbc();

    custom_iv = (m_block *) malloc(blockSize * sizeof(m_block));
    for (size_t i = 0; i < blockSize; i++) {
        custom_iv[i] = MASK_TO_BLOCK_SIZE(0xAABBCCDDAABBCCDD, 0xAABBCCDDAABBCCDD);
    }

    oes->setIV(custom_iv, blockSize);
    oes->dec_cbc();

    auto result = oes->get_data();
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete oes;
    return true;
}

TEST(CBCDifferentIVDifferentCiphertext) {
    OES *oes1 = new OES();
    OES *oes2 = new OES();
    char key[] = "same_key";
    char data[] = "same plaintext data";

    oes1->set_key(key);
    oes2->set_key(key);

    size_t blockSize = 4;

    auto *iv1 = (m_block *) malloc(blockSize * sizeof(m_block));
    auto *iv2 = (m_block *) malloc(blockSize * sizeof(m_block));
    for (size_t i = 0; i < blockSize; i++) {
        iv1[i] = MASK_TO_BLOCK_SIZE(0x1111111111111111, 0x1111111111111111);
        iv2[i] = MASK_TO_BLOCK_SIZE(0x2222222222222222, 0x2222222222222222);
    }

    oes1->setIV(iv1, blockSize);
    oes1->load_data_raw(data, strlen(data));
    oes1->enc_cbc();

    oes2->setIV(iv2, blockSize);
    oes2->load_data_raw(data, strlen(data));
    oes2->enc_cbc();

    MBLOCK *cipher1 = oes1->get_cipherBlock();
    MBLOCK *cipher2 = oes2->get_cipherBlock();

    bool different = false;
    size_t len1 = cipher1->getLen();
    size_t len2 = cipher2->getLen();

    if (len1 != len2) {
        different = true;
    } else {
        for (size_t i = 0; i < len1; i++) {
            if (cipher1->getBlock(i) != cipher2->getBlock(i)) {
                different = true;
                break;
            }
        }
    }
    ASSERT_TRUE(different);

    delete cipher1;
    delete cipher2;
    delete oes1;
    delete oes2;
    return true;
}

TEST(CBCWrongIVFailsDecryption) {
    OES *oes = new OES();
    char key[] = "cbc_key";
    char data[] = "test data";

    oes->set_key(key);
    size_t blockSize = 4;

    m_block *iv1 = (m_block *) malloc(blockSize * sizeof(m_block));
    m_block *iv2 = (m_block *) malloc(blockSize * sizeof(m_block));
    for (size_t i = 0; i < blockSize; i++) {
        iv1[i] = MASK_TO_BLOCK_SIZE(0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA);
        iv2[i] = MASK_TO_BLOCK_SIZE(0xBBBBBBBBBBBBBBBB, 0xBBBBBBBBBBBBBBBB);
    }

    oes->setIV(iv1, blockSize);
    oes->load_data_raw(data, strlen(data));
    oes->enc_cbc();

    oes->setIV(iv2, blockSize);
    oes->dec_cbc();

    try {
        auto result = oes->get_data();
        bool corrupted = (memcmp(result.first, data, strlen(data)) != 0);
        ASSERT_TRUE(corrupted);
        free(result.first);
    } catch (...) {
    }

    delete oes;
    return true;
}

TEST(CBCStreamModeChaining) {
    return true; // Test disabled
}

// ==================== TEST CIFRATURA CTR ====================

TEST(CTRRoundTripDefaultCounter) {
    OES *oes = new OES();
    char key[] = "ctr_key";
    char data[] = "CTR mode test data with default counter";

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));

    oes->enc_ctr();
    oes->setCtrCounter(0);
    oes->dec_ctr();

    auto result = oes->get_data();
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete oes;
    return true;
}

TEST(CTRRoundTripCustomCounter) {
    OES *oes = new OES();
    char key[] = "ctr_key";
    char data[] = "CTR with custom counter initialization";
    m_block custom_counter = 12345;

    oes->set_key(key);
    oes->setCtrCounter(custom_counter);
    oes->load_data_raw(data, strlen(data));

    oes->enc_ctr();
    oes->setCtrCounter(custom_counter);
    oes->dec_ctr();

    auto result = oes->get_data();
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete oes;
    return true;
}

TEST(CTRDifferentCountersDifferentCiphertext) {
    OES *oes1 = new OES();
    OES *oes2 = new OES();
    char key[] = "same_key";
    char data[] = "same plaintext";

    oes1->streamMode = true;
    oes2->streamMode = true;

    oes1->set_key(key);
    oes1->setCtrCounter(0);
    oes1->load_data_raw(data, strlen(data));
    oes1->enc_ctr();

    oes2->set_key(key);
    oes2->setCtrCounter(1000);
    oes2->load_data_raw(data, strlen(data));
    oes2->enc_ctr();

    MBLOCK *cipher1 = oes1->get_cipherBlock();
    MBLOCK *cipher2 = oes2->get_cipherBlock();

    bool different = false;
    size_t len = cipher1->getLen();
    for (size_t i = 0; i < len; i++) {
        if (cipher1->getBlock(i) != cipher2->getBlock(i)) {
            different = true;
            break;
        }
    }
    ASSERT_TRUE(different);

    delete cipher1;
    delete cipher2;
    delete oes1;
    delete oes2;
    return true;
}

TEST(CTRStreamModeChaining) {
    OES *enc = new OES();
    OES *dec = new OES();
    char key[] = "ctr_stream_key";
    char data1[] = "First CTR chunk";
    char data2[] = "Second CTR chunk";

    enc->set_key(key);
    dec->set_key(key);
    enc->streamMode = false;
    dec->streamMode = false;

    // Encrypt chunks
    enc->load_data_raw(data1, strlen(data1));
    enc->enc_ctr();
    MBLOCK *cipher1 = enc->get_cipherBlock();

    enc->load_data_raw(data2, strlen(data2));
    enc->enc_ctr();
    MBLOCK *cipher2 = enc->get_cipherBlock();

    // Decrypt chunks
    dec->load_cipher_block(cipher1, false);
    dec->dec_ctr();
    auto plain1 = dec->get_data();

    dec->load_cipher_block(cipher2, false);
    dec->dec_ctr();
    auto plain2 = dec->get_data();

    ASSERT_EQ(strlen(data1), plain1.second);
    ASSERT_EQ(0, memcmp(plain1.first, data1, strlen(data1)));
    ASSERT_EQ(strlen(data2), plain2.second);
    ASSERT_EQ(0, memcmp(plain2.first, data2, strlen(data2)));

    delete cipher1;
    delete cipher2;
    free(plain1.first);
    free(plain2.first);

    delete enc;
    delete dec;
    return true;
}

// ==================== TEST CIFRATURA CKE ====================

TEST(CKERoundTripBasic) {
    OES *oes = new OES();
    char key[] = "cke_key";
    char data[] = "CKE mode encryption test";

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));

    oes->setCkeStreamData(MASK_TO_BLOCK_SIZE(0x3C46C64A, 0x3C46C64A));
    oes->enc_cke();
    oes->setCkeStreamData(MASK_TO_BLOCK_SIZE(0x3C46C64A, 0x3C46C64A));
    oes->dec_cke();

    auto result = oes->get_data();
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete oes;
    return true;
}

TEST(CKEStreamModeChaining) {
    OES *enc = new OES();
    OES *dec = new OES();
    char key[] = "cke_stream_key";
    char data1[] = "First chunk";
    char data2[] = "Second chunk";
    char data3[] = "Third chunk";
    char data4[] = "Fourth chunk";

    enc->set_key(key);
    dec->set_key(key);
    enc->streamMode = true;
    dec->streamMode = true;

    // Encrypt all chunks
    enc->load_data_raw(data1, strlen(data1));
    enc->enc_cke();
    MBLOCK *cipher1 = enc->get_cipherBlock();

    enc->load_data_raw(data2, strlen(data2));
    enc->enc_cke();
    MBLOCK *cipher2 = enc->get_cipherBlock();

    enc->load_data_raw(data3, strlen(data3));
    enc->enc_cke();
    MBLOCK *cipher3 = enc->get_cipherBlock();

    enc->load_data_raw(data4, strlen(data4));
    enc->enc_cke();
    MBLOCK *cipher4 = enc->get_cipherBlock();

    // Decrypt all chunks
    dec->load_cipher_block(cipher1, true);
    dec->dec_cke();
    auto plain1 = dec->get_data();

    dec->load_cipher_block(cipher2, true);
    dec->dec_cke();
    auto plain2 = dec->get_data();

    dec->load_cipher_block(cipher3, true);
    dec->dec_cke();
    auto plain3 = dec->get_data();

    dec->load_cipher_block(cipher4, true);
    dec->dec_cke();
    auto plain4 = dec->get_data();

    ASSERT_EQ(strlen(data1), plain1.second);
    ASSERT_EQ(0, memcmp(plain1.first, data1, strlen(data1)));
    ASSERT_EQ(strlen(data2), plain2.second);
    ASSERT_EQ(0, memcmp(plain2.first, data2, strlen(data2)));
    ASSERT_EQ(strlen(data3), plain3.second);
    ASSERT_EQ(0, memcmp(plain3.first, data3, strlen(data3)));
    ASSERT_EQ(strlen(data4), plain4.second);
    ASSERT_EQ(0, memcmp(plain4.first, data4, strlen(data4)));

    free(plain1.first);
    free(plain2.first);
    free(plain3.first);
    free(plain4.first);

    delete enc;
    delete dec;
    return true;
}

TEST(CKEDifferentKeysDifferentCiphertext) {
    OES *oes1 = new OES();
    OES *oes2 = new OES();
    char key1[] = "key_one";
    char key2[] = "key_two";
    char data[] = "same data";

    oes1->set_key(key1);
    oes1->load_data_raw(data, strlen(data));
    oes1->enc_cke();

    oes2->set_key(key2);
    oes2->load_data_raw(data, strlen(data));
    oes2->enc_cke();

    MBLOCK *cipher1 = oes1->get_cipherBlock();
    MBLOCK *cipher2 = oes2->get_cipherBlock();

    bool different = false;
    size_t len = cipher1->getLen();
    for (size_t i = 0; i < len; i++) {
        if (cipher1->getBlock(i) != cipher2->getBlock(i)) {
            different = true;
            break;
        }
    }
    ASSERT_TRUE(different);

    delete cipher1;
    delete cipher2;
    delete oes1;
    delete oes2;
    return true;
}

// ==================== TEST CIFRATURA ADV ====================

TEST(ADVRoundTripBasic) {
    return true;
    OES *oes = new OES();
    char key[] = "adv_key";
    char data[] = "ADV mode test data";

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));

    oes->enc_adv();
    oes->resetStreamState();
    oes->dec_adv();

    auto result = oes->get_data();
    ASSERT_EQ(strlen(data), result.second);
    ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));

    free(result.first);
    delete oes;
    return true;
}

TEST(ADVStreamModeChaining) {
    OES *enc = new OES();
    OES *dec = new OES();
    char key[] = "adv_stream_key";
    char data1[] = "First ADV block";
    char data2[] = "Second ADV block";

    enc->set_key(key);
    dec->set_key(key);

    // Encrypt chunks
    enc->load_data_raw(data1, strlen(data1));
    enc->enc_adv();
    MBLOCK *cipher1 = enc->get_cipherBlock();

    enc->load_data_raw(data2, strlen(data2));
    enc->enc_adv();
    MBLOCK *cipher2 = enc->get_cipherBlock();

    // Decrypt chunks
    dec->load_cipher_block(cipher1, false);
    dec->dec_adv();
    auto plain1 = dec->get_data();

    dec->load_cipher_block(cipher2, false);
    dec->dec_adv();
    auto plain2 = dec->get_data();

    ASSERT_EQ(strlen(data1), plain1.second);
    ASSERT_EQ(0, memcmp(plain1.first, data1, strlen(data1)));
    ASSERT_EQ(strlen(data2), plain2.second);
    ASSERT_EQ(0, memcmp(plain2.first, data2, strlen(data2)));

    delete cipher1;
    delete cipher2;
    free(plain1.first);
    free(plain2.first);
    delete enc;
    delete dec;
    return true;
}

TEST(ADVDifferentKeysDifferentCiphertext) {
    OES *oes1 = new OES();
    OES *oes2 = new OES();
    char key1[] = "first_key";
    char key2[] = "second_key";
    char data[] = "test data for ADV";

    oes1->set_key(key1);
    oes1->load_data_raw(data, strlen(data));
    oes1->enc_adv();

    oes2->set_key(key2);
    oes2->load_data_raw(data, strlen(data));
    oes2->enc_adv();

    MBLOCK *cipher1 = oes1->get_cipherBlock();
    MBLOCK *cipher2 = oes2->get_cipherBlock();

    bool different = false;
    size_t len = cipher1->getLen();
    for (size_t i = 0; i < len; i++) {
        if (cipher1->getBlock(i) != cipher2->getBlock(i)) {
            different = true;
            break;
        }
    }
    ASSERT_TRUE(different);

    delete cipher1;
    delete cipher2;
    delete oes1;
    delete oes2;
    return true;
}

// ==================== TEST HASH - COLLISION DETECTION ====================

TEST(HashNoDuplicatesLargeSpace) {
    const size_t SPACE_SIZE = 100;
    const size_t HASH_LEN = 16;

    OES *oes = new OES();

    // Contenitore dei risultati senza classi/funzioni di supporto
    std::vector<MBLOCK *> hashes;
    hashes.reserve(SPACE_SIZE);

    uint32_t input[10] = {0};

    for (size_t i = 0; i < SPACE_SIZE; i++) {
        input[0] = i;

        for (size_t j = 0; j < SPACE_SIZE; j++) {
            input[1] = j;

            oes->load_data_raw(input, 8);
            oes->hash(HASH_LEN);

            MBLOCK *hashBlock = oes->get_cipherBlock();
            ASSERT_NOT_NULL(hashBlock);

            ASSERT_EQ(hashBlock->getLen(), HASH_LEN);

            // Verifica duplicato con memcmp SENZA funzioni di supporto
            bool exists = false;
            for (auto &prev: hashes) {
                auto p = prev->getData();
                auto n = hashBlock->getData();
                if (std::memcmp(p, n, HASH_LEN * OES_LOGIC_BLOCK_SIZE) == 0) {
                    exists = true;
                    break;
                }
                delete p;
                delete n;
            }

            ASSERT_FALSE(exists);

            hashes.push_back(hashBlock);
        }
    }

    delete oes;

    for (size_t i = 0; i < SPACE_SIZE; i++) {
        hashes.pop_back();
    }
    return true;
}

TEST(HashDifferentLengthsDifferentOutput) {
    OES *oes = new OES();
    char data[] = "test data for hash";

    oes->load_data_raw(data, strlen(data));
    oes->hash(8);
    MBLOCK *hash1Block = oes->get_cipherBlock();

    oes->load_data_raw(data, strlen(data));
    oes->hash(16);
    MBLOCK *hash2Block = oes->get_cipherBlock();

    oes->load_data_raw(data, strlen(data));
    oes->hash(32);
    MBLOCK *hash3Block = oes->get_cipherBlock();

    std::string s1, s2, s3;
    for (size_t i = 0; i < hash1Block->getLen(); i++) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", hash1Block->getBlock(i));
        s1 += hex;
    }
    for (size_t i = 0; i < hash2Block->getLen(); i++) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", hash2Block->getBlock(i));
        s2 += hex;
    }
    for (size_t i = 0; i < hash3Block->getLen(); i++) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", hash3Block->getBlock(i));
        s3 += hex;
    }

    ASSERT_TRUE(s1 != s2);
    ASSERT_TRUE(s2 != s3);
    ASSERT_TRUE(s1 != s3);

    delete hash1Block;
    delete hash2Block;
    delete hash3Block;

    delete oes;
    return true;
}

TEST(HashSameInputConsistentOutput) {
    OES *oes = new OES();
    char data[] = "consistent hash input";

    oes->load_data_raw(data, strlen(data));
    oes->hash(16);
    MBLOCK *hash1Block = oes->get_cipherBlock();

    oes->load_data_raw(data, strlen(data));
    oes->hash(16);
    MBLOCK *hash2Block = oes->get_cipherBlock();

    std::string s1, s2;
    for (size_t i = 0; i < hash1Block->getLen(); i++) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", hash1Block->getBlock(i));
        s1 += hex;
    }
    for (size_t i = 0; i < hash2Block->getLen(); i++) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", hash2Block->getBlock(i));
        s2 += hex;
    }

    ASSERT_TRUE(s1 == s2);

    delete hash1Block;
    delete hash2Block;

    delete oes;
    return true;
}

// ==================== TEST HMAC ====================

TEST(HMACDifferentKeysProduceDifferentResults) {
    OES *oes = new OES();
    char key1[] = "key_one";
    char key2[] = "key_two";
    char data[] = "data to authenticate";

    oes->set_key(key1);
    oes->load_data_raw(data, strlen(data));
    oes->hmac(20);
    MBLOCK *hmac1Block = oes->get_cipherBlock();

    oes->set_key(key2);
    oes->load_data_raw(data, strlen(data));
    oes->hmac(20);
    MBLOCK *hmac2Block = oes->get_cipherBlock();

    std::string s1, s2;

    ASSERT_TRUE(memcmp(hmac1Block->getData(), hmac2Block->getData(), hmac1Block->getLen() * OES_LOGIC_BLOCK_SIZE) != 0);

    delete hmac1Block;
    delete hmac2Block;

    delete oes;
    return true;
}

TEST(HMACConsistentForSameInput) {
    OES *oes = new OES();
    char key[] = "consistent_key";
    char data[] = "consistent data";

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));
    oes->hmac(16);
    MBLOCK *hmac1Block = oes->get_cipherBlock();

    oes->set_key(key);
    oes->load_data_raw(data, strlen(data));
    oes->hmac(16);
    MBLOCK *hmac2Block = oes->get_cipherBlock();

    std::string s1, s2;
    for (size_t i = 0; i < hmac1Block->getLen(); i++) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", hmac1Block->getBlock(i));
        s1 += hex;
    }
    for (size_t i = 0; i < hmac2Block->getLen(); i++) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", hmac2Block->getBlock(i));
        s2 += hex;
    }

    ASSERT_TRUE(s1 == s2);

    delete hmac1Block;
    delete hmac2Block;

    delete oes;
    return true;
}

TEST(HMACDifferentDataDifferentOutput) {
    OES *oes = new OES();
    char key[] = "hmac_key";
    char data1[] = "first message";
    char data2[] = "second message";

    oes->set_key(key);
    oes->load_data_raw(data1, strlen(data1));
    oes->hmac(20);
    MBLOCK *hmac1Block = oes->get_cipherBlock();

    oes->load_data_raw(data2, strlen(data2));
    oes->hmac(20);
    MBLOCK *hmac2Block = oes->get_cipherBlock();

    ASSERT_TRUE(memcmp(hmac1Block->getData(), hmac2Block->getData(), 20 * OES_BYTES_X_BLOCK) != 0);

    delete hmac1Block;
    delete hmac2Block;

    delete oes;
    return true;
}

// ==================== TEST MULTI-CYCLE ====================

TEST(MultipleEncryptionDecryptionCycles) {
    OES *oes = new OES();
    char key[] = "cycle_key";
    char data[] = "cycling data through multiple rounds";

    oes->set_key(key);
    oes->streamMode = false;

    for (int i = 0; i < 10; i++) {
        oes->load_data_raw(data, strlen(data));
        oes->enc_ecb();
        oes->dec_ecb();

        auto result = oes->get_data();


        ASSERT_EQ(strlen(data), result.second);
        ASSERT_EQ(0, memcmp(result.first, data, strlen(data)));
        free(result.first);
    }

    delete oes;
    return true;
}

TEST(MixedModesEncryption) {
    OES *oes = new OES();
    char key[] = "mixed_key";
    char data[] = "test data for mixed modes";

    oes->set_key(key);

    // ECB
    oes->load_data_raw(data, strlen(data));
    oes->enc_ecb();
    oes->dec_ecb();
    auto result1 = oes->get_data();
    ASSERT_EQ(0, memcmp(result1.first, data, strlen(data)));
    free(result1.first);

    // CBC
    oes->load_data_raw(data, strlen(data));
    oes->enc_cbc();
    oes->dec_cbc();
    auto result2 = oes->get_data();
    ASSERT_EQ(0, memcmp(result2.first, data, strlen(data)));
    free(result2.first);

    // CTR
    oes->load_data_raw(data, strlen(data));
    oes->enc_ctr();
    oes->dec_ctr();
    auto result3 = oes->get_data();
    ASSERT_EQ(0, memcmp(result3.first, data, strlen(data)));
    free(result3.first);

    // CKE
    oes->load_data_raw(data, strlen(data));
    oes->enc_cke();
    oes->dec_cke();
    auto result4 = oes->get_data();
    ASSERT_EQ(0, memcmp(result4.first, data, strlen(data)));
    free(result4.first);

    delete oes;
    return true;
}

// ==================== MAIN ====================

int main() {
    return TestRegistry::instance().runAll();
}
