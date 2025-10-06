#pragma once
#include <QDialog>
#include <QString>
#include "ApiClient.h"

class QLineEdit;
class QPushButton;

class ChangePasswordDialog : public QDialog {
    Q_OBJECT
public:
    ChangePasswordDialog(const std::string& token, ApiClient* api, QWidget* parent = nullptr);

private slots:
    void onChangeClicked();

private:
    QLineEdit* newPass_;
    QPushButton* changeBtn_;
    std::string token_;
    ApiClient* api_;
};
