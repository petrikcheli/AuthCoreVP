#pragma once
#include <QMainWindow>
#include <memory>

class ApiClient;
class QComboBox;
class QPushButton;
class QStackedWidget;
class QTableWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(ApiClient* api, const QString& token, QWidget* parent = nullptr);
    void setToken(const QString& token);

signals:
    void logoutRequested();

private slots:
    void onUsersComboChanged(int idx);
    void onControllersComboChanged(int idx);
    void onLogout();

    void showAddUserForm();
    void showViewUsers();
    void showEditUserFlow();
    void showCreateRoleForm();
    void showGrantAllControllers();
    void showRevokeAllControllers();

private:
    void buildUi();
    void loadTopCombos();

private:
    ApiClient* api_;
    QString token_;
    QComboBox* usersCombo_;
    QComboBox* controllersCombo_;
    QPushButton* logoutBtn_;
    QStackedWidget* mainStack_;
    // helper widgets
    QWidget* addUserWidget_;
    QWidget* viewUsersWidget_;
    QWidget* editUserWidget_;
    QWidget* createRoleWidget_;
    QWidget* grantWidget_;
    QWidget* revokeWidget_;
};
