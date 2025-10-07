#include "crow.h"
#include "password_hasher.h"
#include "data_base.h"
#include "jwt_manager.h"
#include "routes.h"

#include <nlohmann/json.hpp>

int main() {
    password_hasher::init();
    data_base db("auth.db");
    jwt_manager jwt("super_secret_key");
    crow::logger::setLogLevel(crow::LogLevel::Info); // для более подробного логирования
    crow::SimpleApp app;

    routes(app, db, jwt);

    app.port(18080).multithreaded().run();
}
