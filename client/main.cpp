#include <QApplication>
#include "ApiClient.h"
#include "AuthDialog.h"
#include "MainWindow.h"

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    ApiClient api("http://localhost:8080"); // нужно поменять базовый URL на другой

    while (true) {
        AuthDialog auth(&api);
        if (auth.exec() == QDialog::Accepted) {
            QString token = auth.token();
            MainWindow w(&api, token);
            QObject::connect(&w, &MainWindow::logoutRequested, [&]() {
                w.close();
            });
            w.show();
            app.exec(); // запускаем главный цикл — после выхода из main window вернёмся к авторизации
            // когда окно закрылось, продолжаем цикл: снова показываем диалог
        } else {
            // пользователь отменил логин — завершаем приложение
            break;
        }
    }

    return 0;
}
