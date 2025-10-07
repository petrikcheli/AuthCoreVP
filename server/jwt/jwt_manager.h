#pragma once
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <string>
#include <chrono>

class jwt_manager {
public:
    jwt_manager(const std::string& secretKey)
        : secret(secretKey) {}


    std::string create_token(const std::string& username, int expireSeconds = 3600) {
        auto now = std::chrono::system_clock::now();
        auto exp = now + std::chrono::seconds(expireSeconds);

        nlohmann::json usernameClaim = username;

        return jwt::create<jwt::traits::nlohmann_json>()
            .set_issuer("my_app")
            .set_type("JWS")
            .set_issued_at(now)
            .set_expires_at(exp)
            .set_payload_claim("username", usernameClaim)
            .sign(jwt::algorithm::hs256{ secret });
    }


    bool verify_token(const std::string& token) {
        try {
            auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);

            auto verifier = jwt::verify<jwt::traits::nlohmann_json>()
                                .allow_algorithm(jwt::algorithm::hs256{ secret })
                                .with_issuer("my_app");

            verifier.verify(decoded);

            // Проверка истечения времени через метод get_expires_at()
            auto exp = decoded.get_expires_at(); // возвращает std::chrono::system_clock::time_point
            return std::chrono::system_clock::now() <= exp;
        } catch (...) {
            return false;
        }
    }


    std::string get_username(const std::string& token) {
        try {
            auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);
            return decoded.get_payload_claim("username").as_string();
        } catch (...) {
            return "";
        }
    }

private:
    std::string secret;
};
