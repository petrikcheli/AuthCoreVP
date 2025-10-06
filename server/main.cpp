#include "crow.h"


int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/").methods("GET"_method)([](const crow::request& req) {
        auto page = crow::mustache::load("login.html");
        return page.render();
    });

    app.port(18080).multithreaded().run();
}
