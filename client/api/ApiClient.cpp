#include "ApiClient.h"
#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static std::string postJson(const std::string& url, const std::string& jsonStr, const std::vector<std::string>& headers = {}) {
    curlpp::Easy request;
    std::ostringstream response;
    request.setOpt(new curlpp::options::Url(url));
    request.setOpt(new curlpp::options::PostFields(jsonStr));
    request.setOpt(new curlpp::options::PostFieldSize(jsonStr.size()));

    std::list<std::string> curlHeaders(headers.begin(), headers.end());
    curlHeaders.push_back("Content-Type: application/json");
    request.setOpt(new curlpp::options::HttpHeader(curlHeaders));
    request.setOpt(new curlpp::options::WriteStream(&response));
    request.perform();
    return response.str();
}

static std::string getJson(const std::string& url, const std::vector<std::string>& headers = {}) {
    curlpp::Easy request;
    std::ostringstream response;
    request.setOpt(new curlpp::options::Url(url));

    if (!headers.empty()) {
        std::list<std::string> curlHeaders(headers.begin(), headers.end());
        request.setOpt(new curlpp::options::HttpHeader(curlHeaders));
    }

    request.setOpt(new curlpp::options::WriteStream(&response));
    request.perform();
    return response.str();
}

ApiClient::ApiClient(const std::string& base_url)
    : baseUrl(base_url)
{
    curlpp::initialize();
}

// Авторизация администратора
bool ApiClient::login(const std::string& username, const std::string& password, std::string& token_out) {
    json body = {{"username", username}, {"password", password}};
    try {
        auto resp = postJson(baseUrl + "/api/admin/login", body.dump());
        auto j = json::parse(resp);
        if (j.contains("token")) {
            token_out = j["token"].get<std::string>();
            return true;
        }
    } catch (...) {}
    return false;
}

// Получение списка пользователей
std::vector<User> ApiClient::getUsers(const std::string& token, std::string& err) {
    std::vector<User> res;
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = getJson(baseUrl + "/api/admin/users", {header});
        auto j = json::parse(resp);
        
        for (const auto& it : j)
            res.push_back(it.get<User>());
            
    } catch (std::exception& e) {
        err = e.what();
    }
    return res;
}

// Добавление пользователя
bool ApiClient::addUser(const std::string& token, const User& u, const std::string& password, std::string& err) {
    json body = {
        {"username", u.username},
        {"password", password},
        {"role", u.role},
        {"full_name", u.full_name}
    };
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = postJson(baseUrl + "/api/admin/add-user", body.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

// Удаление пользователя
bool ApiClient::deleteUser(const std::string& token, int id, std::string& err) {
    json body = {{"id", id}};
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = postJson(baseUrl + "/api/admin/delete-user", body.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

// Получить список контроллеров
std::vector<Controller> ApiClient::getControllers(const std::string& token, std::string& err) {
    std::vector<Controller> res;
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = getJson(baseUrl + "/api/admin/controllers", {header});
        auto j = json::parse(resp);
        for (auto& c : j)
            res.push_back(c.get<Controller>());
    } catch (std::exception& e) {
        err = e.what();
    }
    return res;
}

// Добавить контроллер
bool ApiClient::addController(const std::string& token, const Controller& c, std::string& err) {
    json body = {{"name", c.name}, {"serial", c.serial_number}};
    try {
        std::string header = "Authorization: Bearer " + token;
        postJson(baseUrl + "/api/admin/add-controller", body.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

// Удалить контроллер
bool ApiClient::deleteController(const std::string& token, int id, std::string& err) {
    json body = {{"id", id}};
    try {
        std::string header = "Authorization: Bearer " + token;
        postJson(baseUrl + "/api/admin/delete-controller", body.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

bool ApiClient::updateUser(const std::string& token, const User& u, std::string& err) {
    nlohmann::json body = {
        {"id", u.id},
        {"username", u.username},
        {"role", u.role},
        {"full_name", u.full_name}
    };

    try {
        std::string header = "Authorization: Bearer " + token;
        postJson(baseUrl + "/api/admin/update-user", body.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

bool ApiClient::createRole(const std::string& token, const nlohmann::json& roleSpec, std::string& err) {
    try {
        std::string header = "Authorization: Bearer " + token;
        postJson(baseUrl + "/api/admin/create-role", roleSpec.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

bool ApiClient::grantAllControllers(const std::string& token, int userId, std::string& err) {
    nlohmann::json body = {{"user_id", userId}};
    try {
        std::string header = "Authorization: Bearer " + token;
        postJson(baseUrl + "/api/admin/grant-all-controllers", body.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

bool ApiClient::revokeAllControllers(const std::string& token, int userId, std::string& err) {
    nlohmann::json body = {{"user_id", userId}};
    try {
        std::string header = "Authorization: Bearer " + token;
        postJson(baseUrl + "/api/admin/revoke-all-controllers", body.dump(), {header});
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}
