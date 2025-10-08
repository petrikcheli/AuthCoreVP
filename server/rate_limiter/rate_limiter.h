#pragma once
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <string>

struct ip_record {
    int attempts = 0;
    std::chrono::steady_clock::time_point first_attempt;
    std::chrono::steady_clock::time_point last_attempt;
    int block_level = 0;
    std::chrono::steady_clock::time_point blocked_until = std::chrono::steady_clock::time_point::min();
};

class simple_rate_limiter {
public:
    simple_rate_limiter(int max_attempts = 5,
                      int window_seconds = 60,
                      int base_block_seconds = 60);

    bool allow(const std::string& ip);               // проверка, разрешен ли IP
    bool add_failure(const std::string& ip);         // регистрируем неудачную попытку
    void add_success(const std::string& ip);        // успешный вход
    void cleanup_old(std::chrono::seconds older_than = std::chrono::seconds(600)); // опционально

private:
    std::unordered_map<std::string, ip_record> map_;
    std::mutex mutex_;
    const int MAX_ATTEMPTS;
    const std::chrono::seconds WINDOW;
    const std::chrono::seconds BASE_BLOCK;
};
