#pragma once
#include <QDialog>

class QLineEdit;
class QPushButton;
class ApiClient;

class AuthDialog : public QDialog {
    Q_OBJECT
public:
    AuthDialog(ApiClient* api, QWidget* parent = nullptr);
    QString token() const { return token_; }

signals:
    void loggedIn();

private slots:
    void onLoginClicked();

private:
    ApiClient* api_;
    QLineEdit* username_;
    QLineEdit* password_;
    QPushButton* loginBtn_;
    QString token_;
};
