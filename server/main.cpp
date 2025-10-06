#include "crow.h"
#include "password_hasher.h"
#include "data_base.h"
#include "jwt_manager.h"
#include <nlohmann/json.hpp>

int main() {
    password_hasher::init();
    data_base bd("auth.db");
    jwt_manager jwt("super_secret_key");
    crow::SimpleApp app;

    CROW_ROUTE(app, "/admin/login/api").methods("POST"_method)(
        [&bd, &jwt](const crow::request& req){
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if(body.is_discarded())
                return crow::response(400, "Invalid JSON");

            std::string username = body.value("username", "");
            std::string password = body.value("password", "");

            auto user_opt = bd.authenticate(username, password);
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
        [&bd, &jwt](const crow::request& req){
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

            bool ok = bd.add_user(username, full_name, password, role);
            if(!ok) return crow::response(400, "Failed to create user");

            return crow::response(200, "User created");
        }
    );


    CROW_ROUTE(app, "/admin/change-password/api").methods("POST"_method)(
        [&bd, &jwt](const crow::request& req){
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if(body.is_discarded())
                return crow::response(400, "Invalid JSON");

            std::string admin_token = body.value("token", "");
            if(!jwt.verify_token(admin_token))
                return crow::response(401, "Unauthorized");

            int user_id = body.value("user_id", 0);
            std::string new_password = body.value("new_password", "");

            bool ok = bd.update_password(user_id, new_password);
            if(!ok) return crow::response(400, "Failed to change password");

            return crow::response(200, "Password changed");
        }
    );


    CROW_ROUTE(app, "/admin/delete/api").methods("POST"_method)(
        [&bd, &jwt](const crow::request& req){
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if(body.is_discarded())
                return crow::response(400, "Invalid JSON");

            std::string admin_token = body.value("token", "");
            if(!jwt.verify_token(admin_token))
                return crow::response(401, "Unauthorized");

            int user_id = body.value("user_id", 0);

            if(!bd.delete_user(user_id))
                return crow::response(400, "Failed to delete user");

            return crow::response(200, "User deleted");
        }
    );

    app.port(18080).multithreaded().run();
}
