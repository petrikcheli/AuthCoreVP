#include "MainWindow.h"
#include "ApiClient.h"

#include <QWidget>
#include <QComboBox>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QStackedWidget>
#include <QLabel>
#include <QLineEdit>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>
#include <QInputDialog>

// Основное окно приложения
// Верхняя панель: выпадающие списки пользователей и контроллеров, кнопка выхода
// Нижняя часть (QStackedWidget) — разные формы в зависимости от выбора пользователя
// Каждая форма обрабатывает взаимодействие с ApiClient
MainWindow::MainWindow(ApiClient* api, const QString& token, QWidget* parent)
    : QMainWindow(parent), api_(api), token_(token)
{
    buildUi();
    loadTopCombos();
}

void MainWindow::setToken(const QString& token) { token_ = token; }

// Создание UI и подключение сигналов
void MainWindow::buildUi() {
    auto central = new QWidget(this);
    auto v = new QVBoxLayout(central);

    // Верхняя панель
    auto top = new QHBoxLayout();
    usersCombo_ = new QComboBox();
    // usersCombo_->addItem("Пользователи:");
    usersCombo_->addItem("Добавить пользователя");
    usersCombo_->addItem("Посмотреть всех пользователей");
    usersCombo_->addItem("Изменить пользователя");
    usersCombo_->addItem("Создание роли");
    usersCombo_->addItem("Добавить доступ сотруднику ко всем контроллерам");
    usersCombo_->addItem("Удалить доступ сотруднику от всех контроллеров");

    controllersCombo_ = new QComboBox();
    controllersCombo_->addItem("Контроллеры:");

    logoutBtn_ = new QPushButton("Выйти");

    top->addWidget(usersCombo_);
    top->addWidget(controllersCombo_);
    top->addStretch();
    top->addWidget(logoutBtn_);

    v->addLayout(top);

    // Освновной виджет
    mainStack_ = new QStackedWidget();
    // Добавление пользователей
    addUserWidget_ = new QWidget();
    {
        auto lay = new QVBoxLayout(addUserWidget_);
        lay->addWidget(new QLabel("Добавить пользователя"));
        auto username = new QLineEdit();
        username->setPlaceholderText("Имя");
        auto password = new QLineEdit();
        password->setPlaceholderText("Пароль");
        auto role = new QLineEdit();
        role->setPlaceholderText("Роль");
        auto btn = new QPushButton("Создать");
        lay->addWidget(username);
        lay->addWidget(password);
        lay->addWidget(role);
        lay->addWidget(btn);
        connect(btn, &QPushButton::clicked, this, [this, username, password, role]() {
            User u;
            u.username = username->text().toStdString();
            u.role = role->text().toStdString();
            std::string err;
            if (api_->addUser(token_.toStdString(), u, password->text().toStdString(), err)) {
                QMessageBox::information(this, "ОК", "Пользователь создан");
            } else {
                QMessageBox::warning(this, "Ошибка", QString::fromStdString(err));
            }
        });
    }
    mainStack_->addWidget(addUserWidget_);

    // --- viewUsersWidget_
    viewUsersWidget_ = new QWidget();
    {
        auto lay = new QVBoxLayout(viewUsersWidget_);
        auto refresh = new QPushButton("Обновить список");
        auto table = new QTableWidget();

        // Скрываем левый вертикальный заголовок и угол
        table->verticalHeader()->setVisible(false);
        table->setCornerButtonEnabled(false);
        
        table->setColumnCount(3);
        table->setHorizontalHeaderLabels({"ID","Имя","Роль"});
        table->horizontalHeader()->setStretchLastSection(true);
        lay->addWidget(refresh);
        lay->addWidget(table);
        connect(refresh, &QPushButton::clicked, this, [this, table]() {
            std::string err;
            auto users = api_->getUsers(token_.toStdString(), err);
            if (!err.empty()) {
                QMessageBox::warning(this, "Ошибка", QString::fromStdString(err));
                return;
            }
            table->setRowCount((int)users.size());
            for (int i=0;i<(int)users.size();++i) {
                table->setItem(i,0,new QTableWidgetItem(QString::number(users[i].id)));
                table->setItem(i,1,new QTableWidgetItem(QString::fromStdString(users[i].username)));
                table->setItem(i,2,new QTableWidgetItem(QString::fromStdString(users[i].role)));
            }
        });
    }
    mainStack_->addWidget(viewUsersWidget_);

    // Изменение пользователя
    editUserWidget_ = new QWidget();
    {
        auto lay = new QVBoxLayout(editUserWidget_);
        auto refresh = new QPushButton("Загрузить всех пользователей");
        auto list = new QTableWidget();
        list->setColumnCount(3);
        list->setHorizontalHeaderLabels({"ID","Имя","Роль"});
        list->horizontalHeader()->setStretchLastSection(true);
        lay->addWidget(refresh);
        lay->addWidget(list);
        connect(refresh, &QPushButton::clicked, this, [this, list]() {
            std::string err;
            auto users = api_->getUsers(token_.toStdString(), err);
            if (!err.empty()) { QMessageBox::warning(this, "Ошибка", QString::fromStdString(err)); return; }
            list->setRowCount((int)users.size());
            for (int i=0;i<(int)users.size();++i) {
                list->setItem(i,0,new QTableWidgetItem(QString::number(users[i].id)));
                list->setItem(i,1,new QTableWidgetItem(QString::fromStdString(users[i].username)));
                list->setItem(i,2,new QTableWidgetItem(QString::fromStdString(users[i].role)));
            }
        });
        connect(list, &QTableWidget::cellDoubleClicked, this, [this, list](int row, int col){
            Q_UNUSED(col);
            auto idItem = list->item(row,0);
            if (!idItem) return;
            int id = idItem->text().toInt();
            // запрос данных одного пользователя — в этом примере мы снова загрузим всех и найдем по id
            std::string err;
            auto users = api_->getUsers(token_.toStdString(), err);
            if (!err.empty()) { QMessageBox::warning(this, "Ошибка", QString::fromStdString(err)); return; }
            for (auto &u : users) {
                if (u.id == id) {
                    // show edit dialog (reuse add form)
                    QDialog dlg(this);
                    dlg.setWindowTitle("Редактировать пользователя");
                    auto lay2 = new QVBoxLayout(&dlg);
                    auto username = new QLineEdit(QString::fromStdString(u.username));
                    auto role = new QLineEdit(QString::fromStdString(u.role));
                    auto btn = new QPushButton("Сохранить");
                    lay2->addWidget(new QLabel("Имя:"));
                    lay2->addWidget(username);
                    lay2->addWidget(new QLabel("Роль:"));
                    lay2->addWidget(role);
                    lay2->addWidget(btn);
                    connect(btn, &QPushButton::clicked, &dlg, [&dlg, this, &u, username, role]() mutable {
                        u.username = username->text().toStdString();
                        u.role = role->text().toStdString();
                        std::string err2;
                        if (api_->updateUser(token_.toStdString(), u, err2)) {
                            QMessageBox::information(&dlg, "ОК", "Сохранено");
                            dlg.accept();
                        } else {
                            QMessageBox::warning(&dlg, "Ошибка", QString::fromStdString(err2));
                        }
                    });
                    dlg.exec();
                    // после закрытия можно обновить таблицу
                    break;
                }
            }
        });
    }
    mainStack_->addWidget(editUserWidget_);

    // Создание ролей
    createRoleWidget_ = new QWidget();
    {
        auto lay = new QVBoxLayout(createRoleWidget_);
        lay->addWidget(new QLabel("Создание роли (укажи JSON с доступами к контроллерам)"));
        auto jsonEdit = new QLineEdit();
        jsonEdit->setPlaceholderText(R"({"name":"role_name","permissions":["ctrl1","ctrl2"]})");
        auto btn = new QPushButton("Создать роль");
        lay->addWidget(jsonEdit);
        lay->addWidget(btn);
        connect(btn, &QPushButton::clicked, this, [this, jsonEdit]() {
            try {
                auto j = nlohmann::json::parse(jsonEdit->text().toStdString());
                std::string err;
                if (api_->createRole(token_.toStdString(), j, err)) {
                    QMessageBox::information(this, "ОК", "Роль создана");
                } else {
                    QMessageBox::warning(this, "Ошибка", QString::fromStdString(err));
                }
            } catch (std::exception& e) {
                QMessageBox::warning(this, "Ошибка JSON", e.what());
            }
        });
    }
    mainStack_->addWidget(createRoleWidget_);

    // Выбор сотрудника и выдача доступа ко всем контроллерам 
    grantWidget_ = new QWidget();
    {
        auto lay = new QVBoxLayout(grantWidget_);
        auto btnLoad = new QPushButton("Загрузить сотрудников");
        auto list = new QTableWidget();
        list->setColumnCount(3);
        list->setHorizontalHeaderLabels({"ID","Имя","Роль"});
        auto btnGrant = new QPushButton("Предоставить доступ ко всем контроллерам выбранному сотруднику");
        lay->addWidget(btnLoad);
        lay->addWidget(list);
        lay->addWidget(btnGrant);
        connect(btnLoad, &QPushButton::clicked, this, [this, list]() {
            std::string err;
            auto users = api_->getUsers(token_.toStdString(), err);
            if (!err.empty()) { QMessageBox::warning(this, "Ошибка", QString::fromStdString(err)); return; }
            list->setRowCount((int)users.size());
            for (int i=0;i<(int)users.size();++i) {
                list->setItem(i,0,new QTableWidgetItem(QString::number(users[i].id)));
                list->setItem(i,1,new QTableWidgetItem(QString::fromStdString(users[i].username)));
                list->setItem(i,2,new QTableWidgetItem(QString::fromStdString(users[i].role)));
            }
        });
        connect(btnGrant, &QPushButton::clicked, this, [this, list]() {
            auto items = list->selectedItems();
            if (items.empty()) { QMessageBox::warning(this, "Ошибка", "Выберите сотрудника"); return; }
            int row = items.first()->row();
            int id = list->item(row,0)->text().toInt();
            auto confirm = QMessageBox::question(this, "Подтвердить", "Дать доступ ко всем контроллерам пользователю ID=" + QString::number(id) + "?");
            if (confirm == QMessageBox::Yes) {
                std::string err;
                if (api_->grantAllControllers(token_.toStdString(), id, err)) {
                    QMessageBox::information(this, "ОК", "Доступ предоставлен");
                } else {
                    QMessageBox::warning(this, "Ошибка", QString::fromStdString(err));
                }
            }
        });
    }
    mainStack_->addWidget(grantWidget_);

    // Выбор сотрудника и удаление доступа всех контроллеров
    revokeWidget_ = new QWidget();
    {
        auto lay = new QVBoxLayout(revokeWidget_);
        auto btnLoad = new QPushButton("Загрузить сотрудников");
        auto list = new QTableWidget();
        list->setColumnCount(3);
        list->setHorizontalHeaderLabels({"ID","Имя","Роль"});
        auto btnRevoke = new QPushButton("Удалить доступ ко всем контроллерам у выбранного сотрудника");
        lay->addWidget(btnLoad);
        lay->addWidget(list);
        lay->addWidget(btnRevoke);
        connect(btnLoad, &QPushButton::clicked, this, [this, list]() {
            std::string err;
            auto users = api_->getUsers(token_.toStdString(), err);
            if (!err.empty()) { QMessageBox::warning(this, "Ошибка", QString::fromStdString(err)); return; }
            list->setRowCount((int)users.size());
            for (int i=0;i<(int)users.size();++i) {
                list->setItem(i,0,new QTableWidgetItem(QString::number(users[i].id)));
                list->setItem(i,1,new QTableWidgetItem(QString::fromStdString(users[i].username)));
                list->setItem(i,2,new QTableWidgetItem(QString::fromStdString(users[i].role)));
            }
        });
        connect(btnRevoke, &QPushButton::clicked, this, [this, list]() {
            auto items = list->selectedItems();
            if (items.empty()) { QMessageBox::warning(this, "Ошибка", "Выберите сотрудника"); return; }
            int row = items.first()->row();
            int id = list->item(row,0)->text().toInt();
            auto confirm = QMessageBox::question(this, "Подтвердить", "Удалить доступ ко всем контроллерам у пользователя ID=" + QString::number(id) + "?");
            if (confirm == QMessageBox::Yes) {
                std::string err;
                if (api_->revokeAllControllers(token_.toStdString(), id, err)) {
                    QMessageBox::information(this, "ОК", "Доступ удален");
                } else {
                    QMessageBox::warning(this, "Ошибка", QString::fromStdString(err));
                }
            }
        });
    }
    mainStack_->addWidget(revokeWidget_);

    v->addWidget(mainStack_);
    central->setLayout(v);
    setCentralWidget(central);

    // connect signals
    connect(usersCombo_, QOverload<int>::of(&QComboBox::activated), this, &MainWindow::onUsersComboChanged);
    connect(controllersCombo_, QOverload<int>::of(&QComboBox::activated), this, &MainWindow::onControllersComboChanged);
    connect(logoutBtn_, &QPushButton::clicked, this, &MainWindow::onLogout);
}

void MainWindow::loadTopCombos() {
    // controllersCombo_ можно заполнить с сервера
    std::string err;
    auto ctrls = api_->getControllers(token_.toStdString(), err);
    controllersCombo_->clear();
    controllersCombo_->addItem("Контроллеры:");
    for (auto &c : ctrls) {
        controllersCombo_->addItem(QString::fromStdString(c.name));
    }
}

// 0 - Добавить; 1 - Посмотреть всех; 2 - Изменить; 3 - Создание роли; 4 - Добавить доступ; 5 - Удалить доступ
void MainWindow::onUsersComboChanged(int idx) {
    switch (idx) {
        case 0: mainStack_->setCurrentWidget(addUserWidget_); break;
        case 1: mainStack_->setCurrentWidget(viewUsersWidget_); break;
        case 2: mainStack_->setCurrentWidget(editUserWidget_); break;
        case 3: mainStack_->setCurrentWidget(createRoleWidget_); break;
        case 4: mainStack_->setCurrentWidget(grantWidget_); break;
        case 5: mainStack_->setCurrentWidget(revokeWidget_); break;
        default: break;
        }
}

void MainWindow::onControllersComboChanged(int idx) {
    Q_UNUSED(idx);
    // можно реализовать отображение данных контроллера в основной области
}

void MainWindow::onLogout() {
    emit logoutRequested();
}

void MainWindow::showAddUserForm() {}
void MainWindow::showViewUsers() {}
void MainWindow::showEditUserFlow() {}
void MainWindow::showCreateRoleForm() {}
void MainWindow::showGrantAllControllers() {}
void MainWindow::showRevokeAllControllers() {}
