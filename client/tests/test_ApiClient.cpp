#include <gtest/gtest.h>
#include "ApiClient.h"

// Заглушка URL (тест без реального сервера)
TEST(ApiClientTest, LoginFailInvalidServer) {
    ApiClient api("http://127.0.0.1:9999"); // заведомо неверный порт
    std::string token;
    bool ok = api.login("user", "pass", token);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(token.empty());
}

// Пример заглушки для проверки конструирования
TEST(ApiClientTest, ConstructApiClient) {
    ApiClient api("http://localhost:8080");
    EXPECT_NO_THROW({
        std::string token;
        (void)token;
    });
}
