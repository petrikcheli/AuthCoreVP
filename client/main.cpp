#include <QApplication>
#include "ApiClient.h"
#include "AuthDialog.h"
#include "MainWindow.h"
#include "QFile"

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    QFile styleFile("style/style.qss");

    if(styleFile.open(QFile::ReadOnly)) {
        QString style = styleFile.readAll();
        app.setStyleSheet(style); // применяем стиль ко всему приложению
    }

    ApiClient api("http://127.0.0.1:18080"); 
    QString token;

    AuthDialog auth(&api);
    if (auth.exec() != QDialog::Accepted) {
        return 0;
    }

    token = auth.token();

    MainWindow w(&api, token);
    QObject::connect(&w, &MainWindow::logoutRequested, [&]() {
        // при выходе можно показать диалог заново
        AuthDialog auth2(&api);
        if (auth2.exec() == QDialog::Accepted) {
            w.setToken(auth2.token());
        } else {
            w.close(); // если отмена — закрываем приложение
        }
    });

    w.show();
    return app.exec(); // единственный раз запускаем цикл событий
}

