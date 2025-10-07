#pragma once
#include "crow.h"
#include "data_base.h"
#include "jwt_manager.h"
#include <nlohmann/json.hpp>

void routes(crow::SimpleApp& app, data_base& db, jwt_manager& jwt);
