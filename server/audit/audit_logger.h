// audit_logger.h
#pragma once
#include <fstream>
#include <chrono>
#include <iomanip>
#include <string>

inline void audit_admin_action(const std::string& admin, const std::string& action, const std::string& target = "") {
    std::ofstream log("admin_audit.log", std::ios::app);
    if (!log.is_open()) return;

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);

    log << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S")
        << " | admin: " << admin
        << " | action: " << action;
    if (!target.empty())
        log << " | target: " << target;
    log << "\n";
}
