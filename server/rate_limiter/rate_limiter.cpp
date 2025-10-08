#include "rate_limiter.h"

simple_rate_limiter::simple_rate_limiter(int max_attempts, int window_seconds, int base_block_seconds)
    : MAX_ATTEMPTS(max_attempts),
    WINDOW(std::chrono::seconds(window_seconds)),
    BASE_BLOCK(std::chrono::seconds(base_block_seconds)) {}

bool simple_rate_limiter::allow(const std::string& ip) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    auto &rec = map_[ip];

    if (rec.blocked_until > now)
        return false;

    if (rec.attempts == 0 || now - rec.first_attempt > WINDOW) {
        rec.attempts = 0;
        rec.first_attempt = now;
    }

    return true;
}

bool simple_rate_limiter::add_failure(const std::string& ip) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    auto &rec = map_[ip];

    if (rec.attempts == 0 || now - rec.first_attempt > WINDOW) {
        rec.attempts = 1;
        rec.first_attempt = now;
        rec.last_attempt = now;
    } else {
        rec.attempts++;
        rec.last_attempt = now;
    }

    if (rec.attempts > MAX_ATTEMPTS) {
        auto block_for = BASE_BLOCK * (1 << rec.block_level);
        rec.blocked_until = now + block_for;
        rec.block_level++;
        rec.attempts = 0;
        return true;
    }

    return false;
}

void simple_rate_limiter::add_success(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    map_.erase(ip);
}

void simple_rate_limiter::cleanup_old(std::chrono::seconds older_than) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    for(auto it = map_.begin(); it != map_.end(); ) {
        if (now - it->second.last_attempt > older_than && it->second.blocked_until <= now)
            it = map_.erase(it);
        else
            ++it;
    }
}
