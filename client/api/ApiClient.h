#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

struct User {
    int id;
    std::string username;
    std::string role;
    std::string full_name; // если сервер возвращает это поле
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(User, id, username, role, full_name)

struct Controller {
    int id;
    std::string name;
    std::string serial_number;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Controller, id, name, serial_number)

class ApiClient {
public:
    explicit ApiClient(const std::string& base_url);

    // Аутентификация
    bool login(const std::string& username, const std::string& password, std::string& token_out);

    // Взаимодействие с пользователями
    std::vector<User> getUsers(const std::string& token, std::string& err);
    bool addUser(const std::string& token, const User& u, const std::string& password, std::string& err);
    bool updateUser(const std::string& token, const User& u, std::string& err);
    bool deleteUser(const std::string& token, int id, std::string& err);
    
    // Работа с контроллерами
    std::vector<Controller> getControllers(const std::string& token, std::string& err);
    bool addController(const std::string& token, const Controller& c, std::string& err);
    bool deleteController(const std::string& token, int id, std::string& err);

    // Роли
    bool createRole(const std::string& token, const nlohmann::json& roleSpec, std::string& err);

    // Доступ к контроллерам
    bool grantAllControllers(const std::string& token, int userId, std::string& err);
    bool revokeAllControllers(const std::string& token, int userId, std::string& err);

    std::vector<nlohmann::json> getRoles(const std::string& token, std::string& err);
    bool updateRole(const std::string& token, const nlohmann::json& roleSpec, std::string& err);

private:
    std::string baseUrl;
    void isFullName(const nlohmann::json& j, User& u);
};
