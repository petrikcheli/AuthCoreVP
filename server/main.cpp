#include "crow.h"
#include "password_hasher.h"
#include "data_base.h"
#include "jwt_manager.h"
#include "routes.h"
#include "ServerCLI.h"

#include <nlohmann/json.hpp>

#ifdef _WIN32
    #include <windows.h>
#endif

int main() {
    #ifdef _WIN32
        SetConsoleCP(65001);
        SetConsoleOutputCP(65001);
    #endif
    password_hasher::init();
    data_base db("auth.db");
    jwt_manager jwt("super_secret_key");
    crow::logger::setLogLevel(crow::LogLevel::Info); // для более подробного логирования
    crow::SimpleApp app;

    routes(app, db, jwt);

    ServerCLI cli(db, jwt);
    cli.start();
    app.port(18080).multithreaded().run();
}
