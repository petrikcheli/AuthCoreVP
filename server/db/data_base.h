#pragma once
#include <string>
#include <vector>
#include <optional>
#include <sqlite_modern_cpp.h>

#include "password_hasher.h"

struct User {
    int id;
    std::string username;
    std::string full_name;
    std::string role;
};

struct Controller {
    int id;
    std::string name;
    std::string serial_number;
};

struct Access {
    int user_id;
    int controller_id;
};

struct AuthenticatedUser {
    int id;
    std::string username;
    std::string role;
};

struct SimpleRole {
    int id;
    std::string name;
    bool controller_access;
    bool user_list_access;
};


class data_base {
public:
    explicit data_base(const std::string& filename);

    bool add_user(const std::string& username,
                  const std::string& full_name,
                  const std::string& password,
                  const std::string& role);

    std::optional<AuthenticatedUser> authenticate(const std::string& username,
                                                  const std::string& password);

    bool update_password(int user_id, const std::string& new_password);
    bool delete_user(int id);
    void get_all_users(std::vector<User>& users);

    // --- Контроллеры ---
    bool add_controller(const std::string& name, const std::string& description);
    bool delete_controller(int id);
    void get_all_controllers(std::vector<Controller>& controllers);

    // --- Доступы ---
    bool grant_access(int user_id, int controller_id);
    bool revoke_access(int user_id, int controller_id);
    bool grant_all_access(int user_id);
    bool revoke_all_access(int user_id);

    void get_all_simple_roles(std::vector<SimpleRole> &roles);
    bool role_has_controller_access(const std::string &role_name);
    bool role_has_user_list_access(const std::string &role_name);
    bool add_simple_role(const std::string &name, bool controller_access, bool user_list_access);
    bool update_simple_role(const std::string &name, bool controller_access, bool user_list_access);
    bool delete_simple_role(const std::string &name);
private:
    sqlite::database db_;
    void init_tables();

    bool mark_user_must_change_password(const std::string& username);
    bool must_change_password(const std::string& username);

    bool ensure_default_admin();
};
