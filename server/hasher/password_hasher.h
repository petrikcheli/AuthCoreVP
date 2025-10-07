#pragma once
#include <sodium.h>
#include <string>
#include <stdexcept>

class password_hasher {
public:

    static void init() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }
    }


    static std::string hash(const std::string &password) {
        char out[crypto_pwhash_STRBYTES];


        //TODO: нужно вывести ошибку создания пользователя, а не завершать программу
        if (crypto_pwhash_str(
                out,
                password.c_str(),
                password.size(),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
            throw std::runtime_error("Failed to hash password");
        }

        return std::string(out);
    }

    // Проверка пароля. Возвращает true, если пароль совпадает с хэшем
    static bool verify(const std::string &password, const std::string &hashed) {
        return crypto_pwhash_str_verify(
                   hashed.c_str(),
                   password.c_str(),
                   password.size()) == 0;
    }
};
