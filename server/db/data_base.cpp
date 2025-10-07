#include "data_base.h"
#include <iostream>

data_base::data_base(const std::string& filename)
    : db_(filename)
{
    init_tables();
}

void data_base::init_tables() {
    db_ <<
        "CREATE TABLE IF NOT EXISTS users ("
        "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   username TEXT UNIQUE,"
        "   full_name TEXT,"
        "   password_hash TEXT,"
        "   role TEXT"
        ");";

    db_ <<
        "CREATE TABLE IF NOT EXISTS controllers ("
        "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   name TEXT UNIQUE,"
        "   description TEXT"
        ");";

    db_ <<
        "CREATE TABLE IF NOT EXISTS access ("
        "   user_id INTEGER,"
        "   controller_id INTEGER,"
        "   UNIQUE(user_id, controller_id)"
        ");";
}

bool data_base::add_user(const std::string& username,
                         const std::string& full_name,
                         const std::string& password,
                         const std::string& role)
{
    try {
        std::string hash = password_hasher::hash(password);
        db_ << "INSERT INTO users (username, full_name, password_hash, role) VALUES (?, ?, ?, ?);"
            << username << full_name << hash << role;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "add_user error: " << e.what() << "\n";
        return false;
    }
}

std::optional<AuthenticatedUser> data_base::authenticate(const std::string& username,
                                                         const std::string& password)
{
    try {
        std::string hash;
        int id;
        std::string role;

        bool found = false;
        db_ << "SELECT id, password_hash, role FROM users WHERE username = ?;"
            << username
            >> [&](int uid, std::string h, std::string r) {
                  id = uid;
                  hash = h;
                  role = r;
                  found = true;
              };

        if (!found) return std::nullopt;

        if (!password_hasher::verify(password, hash))
            return std::nullopt;

        return AuthenticatedUser{id, username, role};

    } catch (const std::exception& e) {
        std::cerr << "authenticate error: " << e.what() << "\n";
        return std::nullopt;
    }
}

bool data_base::update_password(int user_id, const std::string& new_password) {
    try {
        std::string new_hash = password_hasher::hash(new_password);
        db_ << "UPDATE users SET password_hash = ? WHERE id = ?;"
            << new_hash << user_id;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "update_password error: " << e.what() << "\n";
        return false;
    }
}

bool data_base::delete_user(int id) {
    try {
        db_ << "DELETE FROM users WHERE id = ?;" << id;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "delete_user error: " << e.what() << "\n";
        return false;
    }
}

void data_base::get_all_users(std::vector<User>& users) {
    try {
        users.clear();
        db_ << "SELECT id, username, full_name, role FROM users;"
            >> [&](int id, std::string username, std::string full_name, std::string role) {
                  users.push_back({id, username, full_name, role});
              };
    } catch (const std::exception& e) {
        std::cerr << "get_all_users error: " << e.what() << "\n";
    }
}

// ---------------- Контроллеры ----------------

bool data_base::add_controller(const std::string& name, const std::string& description) {
    try {
        db_ << "INSERT INTO controllers (name, description) VALUES (?, ?);"
            << name << description;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "add_controller error: " << e.what() << "\n";
        return false;
    }
}

bool data_base::delete_controller(int id) {
    try {
        db_ << "DELETE FROM controllers WHERE id = ?;" << id;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "delete_controller error: " << e.what() << "\n";
        return false;
    }
}

void data_base::get_all_controllers(std::vector<Controller>& controllers) {
    try {
        controllers.clear();
        db_ << "SELECT id, name, description FROM controllers;"
            >> [&](int id, std::string name, std::string description) {
                  controllers.push_back({id, name, description});
              };
    } catch (const std::exception& e) {
        std::cerr << "get_all_controllers error: " << e.what() << "\n";
    }
}

// ---------------- Доступы ----------------

bool data_base::grant_access(int user_id, int controller_id) {
    try {
        db_ << "INSERT OR IGNORE INTO access (user_id, controller_id) VALUES (?, ?);"
            << user_id << controller_id;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "grant_access error: " << e.what() << "\n";
        return false;
    }
}

bool data_base::revoke_access(int user_id, int controller_id) {
    try {
        db_ << "DELETE FROM access WHERE user_id = ? AND controller_id = ?;"
            << user_id << controller_id;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "revoke_access error: " << e.what() << "\n";
        return false;
    }
}

bool data_base::grant_all_access(int user_id) {
    try {
        std::vector<int> controller_ids;
        db_ << "SELECT id FROM controllers;"
            >> [&](int id) { controller_ids.push_back(id); };

        for (int cid : controller_ids) {
            db_ << "INSERT OR IGNORE INTO access (user_id, controller_id) VALUES (?, ?);"
                << user_id << cid;
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "grant_all_access error: " << e.what() << "\n";
        return false;
    }
}

bool data_base::revoke_all_access(int user_id) {
    try {
        db_ << "DELETE FROM access WHERE user_id = ?;" << user_id;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "revoke_all_access error: " << e.what() << "\n";
        return false;
    }
}
