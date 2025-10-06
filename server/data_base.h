#pragma once
#include <sqlite_modern_cpp.h>
#include <string>
#include <optional>
#include <vector>
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

class data_base {
public:
    explicit data_base(const std::string& path)
        : db_(path) {
        init();
    }

    void init() {
        db_ <<
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "username TEXT UNIQUE NOT NULL,"
            "full_name TEXT NOT NULL,"
            "password_hash TEXT NOT NULL,"
            "role TEXT NOT NULL CHECK (role IN ('admin', 'engineer', 'operator'))"
            ");";

        db_ <<
            "CREATE TABLE IF NOT EXISTS controllers ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "name TEXT UNIQUE NOT NULL,"
            "serial_number TEXT UNIQUE NOT NULL"
            ");";

        db_ <<
            "CREATE TABLE IF NOT EXISTS access_policies ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "user_id INTEGER NOT NULL,"
            "controller_id INTEGER NOT NULL,"
            "access_type TEXT NOT NULL CHECK (access_type IN ('read', 'write')),"
            "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,"
            "FOREIGN KEY(controller_id) REFERENCES controllers(id) ON DELETE CASCADE,"
            "UNIQUE(user_id, controller_id)"
            ");";
    }

    bool add_user(const std::string& username,
                  const std::string& full_name,
                  const std::string& password,
                  const std::string& role) {
        std::string hash = password_hasher::hash(password);
        try {
            db_ << "INSERT INTO users (username, full_name, password_hash, role) VALUES (?, ?, ?, ?);"
                << username << full_name << hash << role;
            return true;
        } catch (...) {
            return false;
        }
    }


    std::optional<User> authenticate(const std::string& username,
                                     const std::string& password) {
        std::string hash;
        User user;

        bool found = false;
        db_ << "SELECT id, username, full_name, password_hash, role FROM users WHERE username = ?;"
            << username >>
            [&](int id, std::string uname, std::string fname, std::string phash, std::string role) {
                user = {id, uname, fname, role};
                hash = phash;
                found = true;
            };

        if (!found)
            return std::nullopt;

        if (password_hasher::verify(hash, password))
            return user;

        return std::nullopt;
    }


    bool update_password(int user_id, const std::string& new_password) {
        std::string new_hash = password_hasher::hash(new_password);
        try {
            db_ << "UPDATE users SET password_hash = ? WHERE id = ?;"
                << new_hash << user_id;
            return true;
        } catch (...) {
            return false;
        }
    }


    bool add_controller(const std::string& name, const std::string& serial) {
        try {
            db_ << "INSERT INTO controllers (name, serial_number) VALUES (?, ?);"
                << name << serial;
            return true;
        } catch (...) {
            return false;
        }
    }


    bool set_access(int user_id, int controller_id, const std::string& access_type) {
        try {
            db_ << "INSERT OR REPLACE INTO access_policies (user_id, controller_id, access_type) VALUES (?, ?, ?);"
                << user_id << controller_id << access_type;
            return true;
        } catch (...) {
            return false;
        }
    }


    bool has_access(const std::string& username,
                    const std::string& controller_name,
                    const std::string& access_type) {
        int count = 0;
        db_ <<
                "SELECT COUNT(*) FROM access_policies "
                "JOIN users ON access_policies.user_id = users.id "
                "JOIN controllers ON access_policies.controller_id = controllers.id "
                "WHERE users.username = ? AND controllers.name = ? AND access_policies.access_type = ?;"
            << username << controller_name << access_type >> count;
        return count > 0;
    }


    bool delete_user(int user_id) {
        try {
            db_ << "DELETE FROM users WHERE id = ?;" << user_id;
            return true;
        } catch (...) {
            return false;
        }
    }


private:
    sqlite::database db_;
};
