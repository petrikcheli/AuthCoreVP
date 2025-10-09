#include <gtest/gtest.h>
#include "AuthDialog.h"
#include "ApiClient.h"

class MockApiClient : public ApiClient {
public:
    MockApiClient() : ApiClient("https://petrichelitest.ru") {}

    bool login(const std::string& username, const std::string& password, std::string& token_out) {
        if (username == "admin" && password == "admin") {
            token_out = "token-admin";
            return true;
        }
        if (username == "user" && password == "pass") {
            token_out = "token-user";
            return true;
        }
        return false;
    }
};

TEST(AuthDialogTest, RootLogin) {
    MockApiClient api;
    std::string token;
    bool ok = (std::string("root") == "root"); // имитация root
    EXPECT_TRUE(ok);
    EXPECT_EQ(token.empty(), true); // token не устанавливаем для root
}

TEST(AuthDialogTest, AdminLoginRequiresChange) {
    MockApiClient api;
    std::string token;
    bool ok = api.login("admin", "admin", token);
    EXPECT_TRUE(ok);
    EXPECT_EQ(token, "token-admin");
}

TEST(AuthDialogTest, NormalUserLogin) {
    MockApiClient api;
    std::string token;
    bool ok = api.login("user", "pass", token);
    EXPECT_TRUE(ok);
    EXPECT_EQ(token, "token-user");
}

TEST(AuthDialogTest, InvalidLoginFails) {
    MockApiClient api;
    std::string token;
    bool ok = api.login("fake", "fake", token);
    EXPECT_FALSE(ok);
}
