#include "Crypto.h"

const uint8_t XOR_KEY[16] = {
    0x4F, 0x62, 0x66, 0x75, 0x73, 0x58, 0x31, 0x32,
    0x33, 0x21, 0x2A, 0x7E, 0x5E, 0x6B, 0x69, 0x74
};

void EncryptBytecode(std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= XOR_KEY[i % 16];
    }
}

void DecryptBytecode(std::vector<uint8_t>& data) {
    EncryptBytecode(data); // XOR는 동일한 방식으로 복호화 가능
}
