#ifndef NONWINDOW_H
#define NONWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class NoNWindow;
}
QT_END_NAMESPACE

class NoNWindow : public QMainWindow
{
    Q_OBJECT

public:
    NoNWindow(QWidget *parent = nullptr);
    ~NoNWindow();

private:
    Ui::NoNWindow *ui;
};
#endif // NONWINDOW_H
