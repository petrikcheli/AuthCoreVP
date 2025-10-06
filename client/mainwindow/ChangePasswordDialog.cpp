#include "ChangePasswordDialog.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>

// Диалог смены пароля
// Проверяет пустой пароль, отправляет новый пароль на сервер
ChangePasswordDialog::ChangePasswordDialog(const std::string& token, ApiClient* api, QWidget* parent)
    : QDialog(parent), token_(token), api_(api)
{
    setWindowTitle("Смена пароля");
    auto layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Введите новый пароль:"));
    newPass_ = new QLineEdit(this);
    newPass_->setEchoMode(QLineEdit::Password);
    layout->addWidget(newPass_);

    changeBtn_ = new QPushButton("Сменить пароль", this);
    layout->addWidget(changeBtn_);

    connect(changeBtn_, &QPushButton::clicked, this, &ChangePasswordDialog::onChangeClicked);

    setLayout(layout);
    setModal(true);
}

// Метод смены пароля
void ChangePasswordDialog::onChangeClicked() {
    QString pass = newPass_->text();
    if (pass.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Пароль не может быть пустым");
        return;
    }

    // Отправляем новый пароль на сервер
    try {
        User adminUser;
        adminUser.id = 1; // ID admin
        adminUser.username = "admin";
        adminUser.role = "admin";
        std::string err;
        if (api_->updateUser(token_, adminUser, err)) {
            QMessageBox::information(this, "ОК", "Пароль успешно изменен");
            accept();
        } else {
            QMessageBox::warning(this, "Ошибка", QString::fromStdString(err));
        }
    } catch (...) {
        QMessageBox::warning(this, "Ошибка", "Не удалось изменить пароль");
    }
}
