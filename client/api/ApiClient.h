#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

struct User {
    int id;
    std::string username;
    std::string role;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(User, id, username, role)

struct Controller {
    int id;
    std::string name;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Controller, id, name)

class ApiClient {
public:
    ApiClient(const std::string& base_url);

    // Auth
    bool login(const std::string& username, const std::string& password, std::string& token_out);

    // Users
    std::vector<User> getUsers(const std::string& token, std::string& err);
    bool addUser(const std::string& token, const User& u, const std::string& password, std::string& err);
    bool updateUser(const std::string& token, const User& u, const std::string& err);

    // Controllers
    std::vector<Controller> getControllers(const std::string& token, std::string& err);

    // Roles
    bool createRole(const std::string& token, const nlohmann::json& roleSpec, std::string& err);

    // Access
    bool grantAllControllers(const std::string& token, int userId, std::string& err);
    bool revokeAllControllers(const std::string& token, int userId, std::string& err);

private:
    std::string baseUrl;
};
