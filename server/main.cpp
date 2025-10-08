#include "crow.h"
#include "password_hasher.h"
#include "data_base.h"
#include "jwt_manager.h"
#include "routes.h"
#include "ServerCLI.h"

#include <nlohmann/json.hpp>

int main() {
    //инициализируем библиотку sodium
    password_hasher::init();
    //подключаемся к базе данных auth.db (Она лежит у исполнительного файла)
    data_base db("auth.db");
    //при внедрении в проект нужно будет српятать ключ и поменять его
    jwt_manager jwt("super_secret_key");
    //доступ к логированию, можно будет писать логи crow
    crow::logger::setLogLevel(crow::LogLevel::Info);
    //web-server crow
    crow::SimpleApp app;

    //обработчики
    routes(app, db, jwt);

    //cli для сервера
    ServerCLI cli(db, jwt);
    cli.start();

    // запускаем на порту 18080
    app.port(18080).multithreaded().run();
}
