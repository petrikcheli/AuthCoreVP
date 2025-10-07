#include "AuthDialog.h"
#include "ApiClient.h"
#include "ChangePasswordDialog.h"
#include <QVBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QInputDialog>

// Диалог авторизации
// Если root/root — локальный вход без сервера
// Если admin/admin — требует смену пароля
// В остальных случаях — проверка через сервер (ApiClient)
AuthDialog::AuthDialog(ApiClient* api, QWidget* parent)
    : QDialog(parent), api_(api)
{
    setWindowTitle("Авторизация");
    auto layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Имя:"));
    username_ = new QLineEdit(this);
    layout->addWidget(username_);

    layout->addWidget(new QLabel("Пароль:"));
    password_ = new QLineEdit(this);
    password_->setEchoMode(QLineEdit::Password);
    layout->addWidget(password_);

    loginBtn_ = new QPushButton("Войти", this);
    layout->addWidget(loginBtn_);

    connect(loginBtn_, &QPushButton::clicked, this, &AuthDialog::onLoginClicked);

    setLayout(layout);
}

void AuthDialog::onLoginClicked() {
    QString user = username_->text();
    QString pass = password_->text();

    if (user == "root" && pass == "root") {
        token_ = "root-local-token";
        accept();
        emit loggedIn();
        return;
    }

    std::string token;
    bool ok = api_->login(user.toStdString(), pass.toStdString(), token);
    if (!ok) {
        QMessageBox::warning(this, "Ошибка", "Неверные данные или сервер недоступен");
        return;
    }

    // admin/admin — обязательная смена пароля
    if (user == "admin" && pass == "admin123") {
        ChangePasswordDialog dlg(token, api_, this);
        if (dlg.exec() != QDialog::Accepted) {
            QMessageBox::information(this, "Смена пароля", "Вы должны сменить пароль перед входом.");
            return;
        }
    }

    token_ = QString::fromStdString(token);
    accept();
    emit loggedIn();
}
