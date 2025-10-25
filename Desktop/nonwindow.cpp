#include "nonwindow.h"
#include "./ui_nonwindow.h"

NoNWindow::NoNWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::NoNWindow)
{
    ui->setupUi(this);
}

NoNWindow::~NoNWindow()
{
    delete ui;
}
