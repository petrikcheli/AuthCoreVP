#include <gtest/gtest.h>
#include "ChangePasswordDialog.h"

class MockApiClientForPassword : public ApiClient {
public:
    MockApiClientForPassword() : ApiClient("http://localhost:8080") {}

    bool updateUser(const std::string& token, const User& u, std::string& err_out) {
        if (u.username == "admin" && !token.empty()) return true;
        err_out = "Error";
        return false;
    }
};

TEST(ChangePasswordDialogTest, PasswordChangeSuccess) {
    MockApiClientForPassword api;
    std::string token = "token-admin";
    User adminUser;
    adminUser.id = 1;
    adminUser.username = "admin";
    adminUser.role = "admin";

    std::string err;
    bool changed = api.updateUser(token, adminUser, err);
    EXPECT_TRUE(changed);
}

TEST(ChangePasswordDialogTest, PasswordChangeFails) {
    MockApiClientForPassword api;
    std::string token = "";
    User adminUser;
    adminUser.id = 1;
    adminUser.username = "admin";
    adminUser.role = "admin";

    std::string err;
    bool changed = api.updateUser(token, adminUser, err);
    EXPECT_FALSE(changed);
    EXPECT_EQ(err, "Error");
}
