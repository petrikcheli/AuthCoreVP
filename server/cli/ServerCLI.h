#pragma once
#include <boost/program_options.hpp>
#include <string>
#include <thread>
#include <atomic>
#include "data_base.h"
#include "jwt_manager.h"

class ServerCLI {
public:
    ServerCLI(data_base& db, jwt_manager& jwt);
    ~ServerCLI();

    // Запустить CLI в отдельном потоке
    void start();
    // Остановить CLI
    void stop();

private:
    data_base& db_;
    jwt_manager& jwt_;
    std::atomic<bool> running_{false};
    std::thread cli_thread_;

    std::string current_user_;
    std::string token_;

    void cli_loop();
    bool login();
    void change_admin_password();
    void handle_command(const std::string& input);

    // Команды
    void list_users();
    void add_user(const std::string& args);
    void delete_user(const std::string& args);
    void list_controllers();
    void add_controller(const std::string& args);
    void delete_controller(const std::string& args);
    void grant_access(const std::string& args);
    void revoke_access(const std::string& args);
    void help();
};
