#include "crow.h"
#include "password_hasher.h"
#include "data_base.h"
#include "jwt_manager.h"

#include <nlohmann/json.hpp>

std::optional<std::string> verify_jwt_from_cookie(const crow::request& req, jwt_manager& jwt) {
    auto cookie = req.get_header_value("Cookie");
    std::string token_prefix = "token=";
    auto pos = cookie.find(token_prefix);
    if (pos == std::string::npos) return std::nullopt;

    auto end = cookie.find(";", pos);
    std::string token = cookie.substr(pos + token_prefix.size(),
                                      (end == std::string::npos) ? std::string::npos : end - pos - token_prefix.size());

    if (!jwt.verify_token(token)) return std::nullopt;

    return jwt.get_username(token);
}

std::optional<std::string> verify_jwt_from_header(const crow::request& req, jwt_manager& jwt) {
    auto auth = req.get_header_value("Authorization");
    if(auth.rfind("Bearer ", 0) != 0) return std::nullopt;
    std::string token = auth.substr(7);
    if(!jwt.verify_token(token)) return std::nullopt;
    return jwt.get_username(token);
}

int main() {
    password_hasher::init();
    data_base db("auth.db");
    jwt_manager jwt("super_secret_key");
    // crow::logger::setLogLevel(crow::LogLevel::Debug); // для более подробного логирования
    crow::SimpleApp app;

    // ---------- AUTH ----------
    CROW_ROUTE(app, "/admin/login").methods("GET"_method)([](){
        return crow::mustache::load("login.html").render();
    });

    // api/admin/login
    // api/admin/users
    // api/admin/add-user
    // api/admin/delete-user
    // api/admin/controllers
    // api/admin/add-controller
    // api/admin/delete-controller
    // api/admin/grant-access
    // api/admin/revoke-access
    // api/admin/grant-access-all
    // api/admin/revoke-access-all

    CROW_ROUTE(app, "/admin/login").methods("POST"_method)(
        [&db, &jwt](const crow::request& req){
            std::string username;
            std::string password;

            // Если Content-Type application/json
            if(req.get_header_value("Content-Type").find("application/json") != std::string::npos){
                auto body = nlohmann::json::parse(req.body, nullptr, false);
                if(body.is_discarded()) return crow::response(400, "Invalid JSON");
                username = body.value("username", "");
                password = body.value("password", "");
            } else { // Для формы
                auto args = crow::query_string(req.body);
                username = args.get("username") ? args.get("username") : "";
                password = args.get("password") ? args.get("password") : "";
            }

            // CROW_LOG_INFO << "Parsed username=" << username << " password=" << password;

            auto user = db.authenticate(username, password);
            if(!user || user->role != "admin")
                return crow::response(401, "Unauthorized");

            std::string token = jwt.create_token(username, 3600);
            crow::response res(302);
            res.set_header("Location", "/admin/panel");
            res.add_header("Set-Cookie", "token=" + token + "; HttpOnly; Path=/");
            return res;
        });

    CROW_ROUTE(app, "/admin/logout").methods("GET"_method)([](const crow::request&){
        crow::response res(302);
        res.set_header("Location", "/admin/login");
        res.add_header("Set-Cookie", "token=; Max-Age=0; Path=/");
        return res;
    });

    // ---------- ADMIN PANEL ----------
    CROW_ROUTE(app, "/admin/panel").methods("GET"_method)([&jwt](const crow::request& req){
        std::string cookie = req.get_header_value("Cookie");
        if(cookie.find("token=") == std::string::npos)
            return crow::response(401, "Unauthorized");

        std::string token = cookie.substr(cookie.find("token=") + 6);
        if(!jwt.verify_token(token))
            return crow::response(401, "Unauthorized");

        return crow::response(crow::mustache::load("admin_panel.html").render());
    });

    // ---------- USERS ----------
    CROW_ROUTE(app, "/admin/users").methods("GET"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        std::vector<User> users;
        db.get_all_users(users);

        crow::mustache::context ctx;
        std::vector<crow::mustache::context> list;
        for(auto& u : users)
            list.push_back({{"id", std::to_string(u.id)}, {"username", u.username}, {"role", u.role}});
        ctx["users"] = std::move(list);

        return crow::response(crow::mustache::load("users.html").render(ctx));
    });

    CROW_ROUTE(app, "/admin/add-user").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if(body.is_discarded()) return crow::response(400, "Invalid JSON");

        std::string username = body.value("username", "");
        std::string full_name = body.value("full_name", "");
        std::string password = body.value("password", "");
        std::string role = body.value("role", "operator");

        if(username.empty() || full_name.empty() || password.empty())
            return crow::response(400, "Missing fields");

        bool ok = db.add_user(username, full_name, password, role);
        return ok ? crow::response(200, "User added") : crow::response(400, "Failed");
    });

    CROW_ROUTE(app, "/admin/delete-user").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if(body.is_discarded()) return crow::response(400, "Invalid JSON");

        int user_id = body.value("id", 0);
        if(user_id == 0) return crow::response(400, "Invalid id");

        bool ok = db.delete_user(user_id);
        return ok ? crow::response(200, "User deleted") : crow::response(400, "Failed");
    });

    // ---------- CONTROLLERS ----------
    CROW_ROUTE(app, "/admin/controllers").methods("GET"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        std::vector<Controller> ctrls;
        db.get_all_controllers(ctrls);

        crow::mustache::context ctx;
        std::vector<crow::mustache::context> list;
        for(auto& c : ctrls)
            list.push_back({{"id", std::to_string(c.id)}, {"name", c.name}, {"serial", c.serial_number}});
        ctx["controllers"] = std::move(list);

        return crow::response(crow::mustache::load("controllers.html").render(ctx));
    });

    CROW_ROUTE(app, "/admin/add-controller").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if(body.is_discarded()) return crow::response(400, "Invalid JSON");

        std::string name = body.value("name", "");
        std::string serial = body.value("serial", "");
        if(name.empty() || serial.empty()) return crow::response(400, "Missing fields");

        bool ok = db.add_controller(name, serial);
        return ok ? crow::response(200, "Controller added") : crow::response(400, "Failed");
    });

    CROW_ROUTE(app, "/admin/delete-controller").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if(body.is_discarded()) return crow::response(400, "Invalid JSON");

        int ctrl_id = body.value("id", 0);
        if(ctrl_id == 0) return crow::response(400, "Invalid id");

        bool ok = db.delete_controller(ctrl_id);
        return ok ? crow::response(200, "Controller deleted") : crow::response(400, "Failed");
    });

    // ---------- ACCESS ----------

    CROW_ROUTE(app, "/admin/access").methods("GET"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if(!username_opt)
            return crow::response(401, "Unauthorized");

        std::vector<User> users;
        std::vector<Controller> controllers;
        db.get_all_users(users);
        db.get_all_controllers(controllers);

        crow::mustache::context ctx;

        std::vector<crow::mustache::context> users_list;
        for(auto& u : users) {
            crow::mustache::context u_ctx;
            u_ctx["id"] = std::to_string(u.id);
            u_ctx["username"] = u.username;
            users_list.push_back(std::move(u_ctx));  // <-- move вместо копирования
        }

        std::vector<crow::mustache::context> controllers_list;
        for(auto& c : controllers) {
            crow::mustache::context c_ctx;
            c_ctx["id"] = std::to_string(c.id);
            c_ctx["name"] = c.name;
            controllers_list.push_back(std::move(c_ctx)); // <-- move
        }

        ctx["users"] = std::move(users_list);
        ctx["controllers"] = std::move(controllers_list);

        return crow::response(crow::mustache::load("access.html").render(ctx));
    });



    CROW_ROUTE(app, "/admin/grant-access").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int user_id = body.value("user_id", 0);
        int controller_id = body.value("controller_id", 0);
        if(user_id == 0 || controller_id == 0) return crow::response(400, "Invalid fields");

        bool ok = db.grant_access(user_id, controller_id);
        return ok ? crow::response(200, "Access granted") : crow::response(400, "Failed");
    });

    CROW_ROUTE(app, "/admin/revoke-access").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int user_id = body.value("user_id", 0);
        int controller_id = body.value("controller_id", 0);
        if(user_id == 0 || controller_id == 0) return crow::response(400, "Invalid fields");

        bool ok = db.revoke_access(user_id, controller_id);
        return ok ? crow::response(200, "Access revoked") : crow::response(400, "Failed");
    });


    CROW_ROUTE(app, "/admin/grant-access-all").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if(!username_opt) return crow::response(401);

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        bool ok = db.grant_all_access(body["user_id"]);
        return ok ? crow::response(200, "Access granted") : crow::response(400, "Failed");
    });

    CROW_ROUTE(app, "/admin/revoke-access-all").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_cookie(req, jwt);
        if(!username_opt) return crow::response(401);

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        bool ok = db.revoke_all_access(body["user_id"]);
        return ok ? crow::response(200, "Access revoked") : crow::response(400, "Failed");
    });

    CROW_ROUTE(app, "/admin/login/api").methods("POST"_method)(
        [&db, &jwt](const crow::request& req){
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if(body.is_discarded())
                return crow::response(400, "Invalid JSON");

            std::string username = body.value("username", "");
            std::string password = body.value("password", "");

            auto user_opt = db.authenticate(username, password);
            if(!user_opt || user_opt->role != "admin") {
                return crow::response(401, "Unauthorized");
            }

            std::string token = jwt.create_token(username, 3600);
            nlohmann::json res;
            res["token"] = token;
            return crow::response(res.dump());
        }
    );

    CROW_ROUTE(app, "/admin/register/api").methods("POST"_method)(
        [&db, &jwt](const crow::request& req){
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if(body.is_discarded())
                return crow::response(400, "Invalid JSON");

            std::string admin_token = body.value("token", "");
            if(!jwt.verify_token(admin_token))
                return crow::response(401, "Unauthorized");

            std::string username = body.value("username", "");
            std::string full_name = body.value("full_name", "");
            std::string password = body.value("password", "");
            std::string role = body.value("role", "operator");

            bool ok = db.add_user(username, full_name, password, role);
            if(!ok) return crow::response(400, "Failed to create user");

            return crow::response(200, "User created");
        }
    );


    //API
    // Авторизация администратора
    CROW_ROUTE(app, "/api/admin/login").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded())
            return crow::response(400, "Invalid JSON");

        std::string username = body.value("username", "");
        std::string password = body.value("password", "");

        auto user = db.authenticate(username, password);
        if (!user || user->role != "admin")
            return crow::response(401, "Unauthorized");

        std::string token = jwt.create_token(username, 3600 * 24); // сутки
        nlohmann::json res = {{"token", token}, {"username", username}};
        return crow::response(res.dump());
    });


    // Получить список всех пользователей
    CROW_ROUTE(app, "/api/admin/users").methods("GET"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        std::vector<User> users;
        db.get_all_users(users);

        nlohmann::json arr = nlohmann::json::array();
        for (auto& u : users)
            arr.push_back({{"id", u.id}, {"username", u.username}, {"role", u.role}});

        return crow::response(arr.dump());
    });


    // Добавить пользователя
    CROW_ROUTE(app, "/api/admin/add-user").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) return crow::response(400, "Invalid JSON");

        std::string username = body.value("username", "");
        std::string full_name = body.value("full_name", "");
        std::string password = body.value("password", "");
        std::string role = body.value("role", "operator");

        if (username.empty() || full_name.empty() || password.empty())
            return crow::response(400, "Missing fields");

        bool ok = db.add_user(username, full_name, password, role);
        return ok ? crow::response(200, "User added") : crow::response(400, "Failed to add user");
    });


    // Удалить пользователя
    CROW_ROUTE(app, "/api/admin/delete-user").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int user_id = body.value("id", 0);
        if (user_id == 0) return crow::response(400, "Invalid user ID");

        bool ok = db.delete_user(user_id);
        return ok ? crow::response(200, "User deleted") : crow::response(400, "Failed to delete user");
    });


    // Получить список всех контроллеров
    CROW_ROUTE(app, "/api/admin/controllers").methods("GET"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        std::vector<Controller> ctrls;
        db.get_all_controllers(ctrls);

        nlohmann::json arr = nlohmann::json::array();
        for (auto& c : ctrls)
            arr.push_back({{"id", c.id}, {"name", c.name}, {"serial", c.serial_number}});

        return crow::response(arr.dump());
    });


    // Добавить контроллер
    CROW_ROUTE(app, "/api/admin/add-controller").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string name = body.value("name", "");
        std::string serial = body.value("serial", "");

        if (name.empty() || serial.empty())
            return crow::response(400, "Missing fields");

        bool ok = db.add_controller(name, serial);
        return ok ? crow::response(200, "Controller added") : crow::response(400, "Failed to add controller");
    });


    // Удалить контроллер
    CROW_ROUTE(app, "/api/admin/delete-controller").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int ctrl_id = body.value("id", 0);
        if (ctrl_id == 0) return crow::response(400, "Invalid controller ID");

        bool ok = db.delete_controller(ctrl_id);
        return ok ? crow::response(200, "Controller deleted") : crow::response(400, "Failed to delete controller");
    });


    // Выдать доступ пользователю к контроллеру
    CROW_ROUTE(app, "/api/admin/grant-access").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int user_id = body.value("user_id", 0);
        int controller_id = body.value("controller_id", 0);
        if (user_id == 0 || controller_id == 0)
            return crow::response(400, "Invalid fields");

        bool ok = db.grant_access(user_id, controller_id);
        return ok ? crow::response(200, "Access granted") : crow::response(400, "Failed to grant access");
    });


    // Удалить доступ пользователя к контроллеру
    CROW_ROUTE(app, "/api/admin/revoke-access").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int user_id = body.value("user_id", 0);
        int controller_id = body.value("controller_id", 0);
        if (user_id == 0 || controller_id == 0)
            return crow::response(400, "Invalid fields");

        bool ok = db.revoke_access(user_id, controller_id);
        return ok ? crow::response(200, "Access revoked") : crow::response(400, "Failed to revoke access");
    });


    // Выдать доступ пользователю ко всем контроллерам
    CROW_ROUTE(app, "/api/admin/grant-access-all").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int user_id = body.value("user_id", 0);
        if (user_id == 0) return crow::response(400, "Invalid user ID");

        bool ok = db.grant_all_access(user_id);
        return ok ? crow::response(200, "Access granted to all") : crow::response(400, "Failed");
    });


    // Удалить доступ пользователя ко всем контроллерам
    CROW_ROUTE(app, "/api/admin/revoke-access-all").methods("POST"_method)([&db, &jwt](const crow::request& req){
        auto username_opt = verify_jwt_from_header(req, jwt);
        if (!username_opt) return crow::response(401, "Unauthorized");

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int user_id = body.value("user_id", 0);
        if (user_id == 0) return crow::response(400, "Invalid user ID");

        bool ok = db.revoke_all_access(user_id);
        return ok ? crow::response(200, "Access revoked from all") : crow::response(400, "Failed");
    });


    app.port(18080).multithreaded().run();
}
