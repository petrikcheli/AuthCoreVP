#include "ServerCLI.h"
#include <iostream>
#include <sstream>
#include <iomanip>

using namespace boost::program_options;

ServerCLI::ServerCLI(data_base& db, jwt_manager& jwt)
    : db_(db), jwt_(jwt) {}

ServerCLI::~ServerCLI() {
    stop();
}

void ServerCLI::start() {
    running_ = true;
    cli_thread_ = std::thread(&ServerCLI::cli_loop, this);
}

void ServerCLI::stop() {
    running_ = false;
    if (cli_thread_.joinable())
        cli_thread_.join();
}

void ServerCLI::cli_loop() {
    if (!login()) return;

    std::cout << "\nType 'help' to see available commands.\n";
    while (running_) {
        std::cout << "\nCLI> ";
        std::string input;
        if (!std::getline(std::cin, input))
            break;

        if (input == "exit" || input == "quit") {
            std::cout << "Exiting CLI...\n";
            break;
        }

        try {
            handle_command(input);
        } catch (std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
        }
    }
}

bool ServerCLI::login() {
    std::string username, password;
    std::cout << "=== CLI Authentication ===\n";
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    auto user = db_.authenticate(username, password);
    if (!user) {
        std::cerr << "Invalid credentials.\n";
        return false;
    }

    current_user_ = username;
    token_ = jwt_.create_token(username, 3600);

    if (username == "admin" && password == "admin123") {
        std::cout << "Warning! You need to change the default admin password.\n";
        change_admin_password();
    }

    std::cout << "Authentication successful.\n";
    return true;
}

void ServerCLI::change_admin_password() {
    std::string new_pass1, new_pass2;
    do {
        std::cout << "Enter new password: ";
        std::getline(std::cin, new_pass1);
        std::cout << "Repeat new password: ";
        std::getline(std::cin, new_pass2);
    } while (new_pass1 != new_pass2 || new_pass1.empty());

    db_.update_password(1, new_pass1);
    std::cout << "Admin password successfully changed.\n";
}

void ServerCLI::handle_command(const std::string& input) {
    std::istringstream iss(input);
    std::string command;
    iss >> command;

    if (command == "help") help();
    else if (command == "list-users") list_users();
    else if (command == "add-user") add_user(input);
    else if (command == "delete-user") delete_user(input);
    else if (command == "list-controllers") list_controllers();
    else if (command == "add-controller") add_controller(input);
    else if (command == "delete-controller") delete_controller(input);
    else if (command == "grant-access") grant_access(input);
    else if (command == "revoke-access") revoke_access(input);
    else std::cout << "Unknown command. Type 'help' for the list of commands.\n";
}

void ServerCLI::list_users() {
    std::vector<User> users;
    db_.get_all_users(users);
    std::cout << std::left << std::setw(5) << "ID" << std::setw(15) << "Username"
              << std::setw(20) << "Full Name" << "Role\n";
    for (auto& u : users)
        std::cout << std::setw(5) << u.id << std::setw(15) << u.username
                  << std::setw(20) << u.full_name << u.role << "\n";
}

void ServerCLI::add_user(const std::string& args) {
    namespace po = boost::program_options;

    po::options_description desc("add-user options");
    desc.add_options()
        ("username", po::value<std::string>()->required(), "Username")
        ("full_name", po::value<std::string>()->required(), "Full Name")
        ("password", po::value<std::string>()->required(), "Password")
        ("role", po::value<std::string>()->default_value("operator"), "Role");

    std::istringstream iss(args);
    std::vector<std::string> args_vec;
    std::string token;
    while (iss >> token)
        args_vec.push_back(token);

    std::vector<const char*> argv;
    argv.reserve(args_vec.size());
    for (const auto& a : args_vec)
        argv.push_back(a.c_str());

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(static_cast<int>(argv.size()), argv.data(), desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Argument parsing error: " << e.what() << "\n";
        return;
    }

    bool ok = db_.add_user(
        vm["username"].as<std::string>(),
        vm["full_name"].as<std::string>(),
        vm["password"].as<std::string>(),
        vm["role"].as<std::string>()
        );

    std::cout << (ok ? "User added.\n" : "Error adding user.\n");
}

void ServerCLI::delete_user(const std::string& args) {
    int id;
    std::cout << "Enter user ID to delete: ";
    std::cin >> id;
    std::cin.ignore();
    bool ok = db_.delete_user(id);
    std::cout << (ok ? "Deleted.\n" : "Error.\n");
}

void ServerCLI::list_controllers() {
    std::vector<Controller> ctrls;
    db_.get_all_controllers(ctrls);
    std::cout << std::left << std::setw(5) << "ID"
              << std::setw(25) << "Name" << "Serial\n";
    for (auto& c : ctrls)
        std::cout << std::setw(5) << c.id
                  << std::setw(25) << c.name << c.serial_number << "\n";
}

void ServerCLI::add_controller(const std::string& args) {
    std::string name, serial;
    std::cout << "Controller name: ";
    std::getline(std::cin, name);
    std::cout << "Serial number: ";
    std::getline(std::cin, serial);

    bool ok = db_.add_controller(name, serial);
    std::cout << (ok ? "Added.\n" : "Error.\n");
}

void ServerCLI::delete_controller(const std::string& args) {
    int id;
    std::cout << "Controller ID: ";
    std::cin >> id;
    std::cin.ignore();
    bool ok = db_.delete_controller(id);
    std::cout << (ok ? "Deleted.\n" : "Error.\n");
}

void ServerCLI::grant_access(const std::string& args) {
    int user_id, ctrl_id;
    std::cout << "User ID: "; std::cin >> user_id;
    std::cout << "Controller ID: "; std::cin >> ctrl_id;
    std::cin.ignore();

    bool ok = db_.grant_access(user_id, ctrl_id);
    std::cout << (ok ? "Access granted.\n" : "Error.\n");
}

void ServerCLI::revoke_access(const std::string& args) {
    int user_id, ctrl_id;
    std::cout << "User ID: "; std::cin >> user_id;
    std::cout << "Controller ID: "; std::cin >> ctrl_id;
    std::cin.ignore();

    bool ok = db_.revoke_access(user_id, ctrl_id);
    std::cout << (ok ? "Access revoked.\n" : "Error.\n");
}

void ServerCLI::help() {
    std::cout << R"(
=== Available commands ===
help                      - Show this help
list-users                - List all users
add-user --username u --full_name "Name" --password p [--role r]
delete-user               - Delete a user
list-controllers          - List all controllers
add-controller            - Add a controller
delete-controller         - Delete a controller
grant-access              - Grant user access to a controller
revoke-access             - Revoke user access
exit / quit               - Exit the CLI
)";
}
