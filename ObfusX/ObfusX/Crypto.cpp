#include "Crypto.h"

// 지금은 일단 1 byte의 XOR 키만
constexpr uint8_t xor_key = 0x5A;
// TODO: 여러개의 KEY를 MOD 연산으로 XOR 적용시켜보기

void EncryptBytecode(std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= xor_key;
    }
}

void DecryptBytecode(std::vector<uint8_t>& data) {
    EncryptBytecode(data); // XOR는 동일한 방식으로 복호화 가능
}
