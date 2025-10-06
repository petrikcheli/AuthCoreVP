#include "ApiClient.h"
#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Инициализирует базовый URL для запросов к серверу и инициализирует curlpp
ApiClient::ApiClient(const std::string& base_url)
    : baseUrl(base_url)
{
    curlpp::initialize();
}

// Выполнение POST запроса с JSON телом
// url - адрес
// jsonStr - строка JSON
// headers - дополнительные HTTP-заголовки (по умолчанию Content-Type: application/json
static std::string postJson(const std::string& url, const std::string& jsonStr, const std::vector<std::string>& headers={}) {
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

// Выполнение GET запроса с опциональными заголовками
static std::string getJson(const std::string& url, const std::vector<std::string>& headers={}) {
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


// Авторизация пользователя, возвращает токен через token_out
bool ApiClient::login(const std::string& username, const std::string& password, std::string& token_out) {
    json body = { {"username", username}, {"password", password} };
    try {
        auto resp = postJson(baseUrl + "/api/login", body.dump());
        auto j = json::parse(resp);
        if (j.contains("token")) {
            token_out = j["token"].get<std::string>();
            return true;
        }
    } catch (...) {}
    return false;
}

// Получение списка пользователей с сервера
std::vector<User> ApiClient::getUsers(const std::string& token, std::string& err) {
    std::vector<User> res;
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = getJson(baseUrl + "/api/users", {header});
        auto j = json::parse(resp);
        for (auto &it : j) res.push_back(it.get<User>());
    } catch (std::exception &e) { err = e.what(); }
    return res;
}

// Добавление нового пользователя на сервер
bool ApiClient::addUser(const std::string& token, const User& u, const std::string& password, std::string& err) {
    json body = { {"username", u.username}, {"password", password}, {"role", u.role} };
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = postJson(baseUrl + "/api/users", body.dump(), {header});
        auto j = json::parse(resp);
        return true; // предполагаем, что успешный статус от сервера — 200-201
    } catch (std::exception &e) { err = e.what(); return false; }
}


bool ApiClient::updateUser(const std::string& token, const User& u, const std::string& err_out) {
    json body = { {"id", u.id}, {"username", u.username}, {"role", u.role} };
    try {
        std::string header = "Authorization: Bearer " + token;
        std::string resp = postJson(baseUrl + "/api/users/" + std::to_string(u.id), body.dump(), {header});
        return true;
    } catch (...) { return false; }
}

std::vector<Controller> ApiClient::getControllers(const std::string& token, std::string& err) {
    std::vector<Controller> res;
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = getJson(baseUrl + "/api/controllers", {header});
        auto j = json::parse(resp);
        for (auto &it : j) res.push_back(it.get<Controller>());
    } catch (std::exception &e) { err = e.what(); }
    return res;
}

bool ApiClient::createRole(const std::string& token, const json& roleSpec, std::string& err) {
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = postJson(baseUrl + "/api/roles", roleSpec.dump(), {header});
        return true;
    } catch (std::exception &e) { err = e.what(); return false; }
}

bool ApiClient::grantAllControllers(const std::string& token, int userId, std::string& err) {
    json body = { {"user_id", userId} };
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = postJson(baseUrl + "/api/access/grant_all", body.dump(), {header});
        return true;
    } catch (std::exception &e) { err = e.what(); return false; }
}

bool ApiClient::revokeAllControllers(const std::string& token, int userId, std::string& err) {
    json body = { {"user_id", userId} };
    try {
        std::string header = "Authorization: Bearer " + token;
        auto resp = postJson(baseUrl + "/api/access/revoke_all", body.dump(), {header});
        return true;
    } catch (std::exception &e) { err = e.what(); return false; }
}
