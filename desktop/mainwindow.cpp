#include "mainwindow.h"
#include "../src/NoNProtocol.hpp"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    this->setMinimumWidth(1100);
    this->setMinimumHeight(750);
    this->setWindowTitle("NoNode");
    this->setStyleSheet("*{ background-color: #0C0C0C;}");
    this->setWindowIcon(QPixmap("/home/enty/project/NoNode/desktop/Icon/NoLogo.png"));

    central_widget = new QWidget(this);
    this->setCentralWidget(central_widget);

    // Shapka components
    shapka_widget = new QWidget(central_widget);
    shapka_widget->setStyleSheet("*{background-color: #2D2D2D;"
                                 "border-bottom: 1px solid black;}");
    shapka_widget->setMaximumHeight(100);

    h_spacer = new QSpacerItem(10, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    search_edit = new QLineEdit(shapka_widget);
    search_edit->setMinimumHeight(50);
    search_edit->setMinimumWidth(700);
    search_edit->setMaximumWidth(1500);
    search_edit->setStyleSheet("*{border: 1px solid #353535;"
                               "border-radius: 8px;"
                               "background-color: #0C0C0C;"
                               "padding: 8px;"
                               "color: white;"
                               "font-size: 16px;}");
    search_edit->setPlaceholderText("Search...");

    menu_button = new QPushButton(shapka_widget);
    menu_button->setStyleSheet("*{border: none;"
                               "background: none;}");
    menu_button->setIcon(QPixmap("/home/enty/project/NoNode/desktop/Icon/Component 10.png"));
    menu_button->setIconSize(QSize(160, 160));
    menu_button->setCursor(Qt::PointingHandCursor);

    user_button = new QPushButton(shapka_widget);
    user_button->setStyleSheet("*{border: none;"
                               "background: none;}");
    user_button->setIcon(QPixmap("/home/enty/project/NoNode/desktop/Icon/user_4_fill.png"));
    user_button->setIconSize(QSize(48,48));
    user_button->setCursor(Qt::PointingHandCursor);

    search_button = new QPushButton(shapka_widget);
    search_button->setStyleSheet("*{border: none;"
                                 "background: none;}");
    search_button->setIcon(QPixmap("/home/enty/project/NoNode/desktop/Icon/search_line.png"));
    search_button->setIconSize(QSize(32, 32));
    search_button->setCursor(Qt::PointingHandCursor);

    chats_button = new QPushButton(shapka_widget);
    chats_button->setStyleSheet("*{border: none;"
                                "background: none;}");
    chats_button->setIcon(QPixmap("/home/enty/project/NoNode/desktop/Icon/chat_3_fill.png"));
    chats_button->setIconSize(QSize(32, 32));
    chats_button->setCursor(Qt::PointingHandCursor);

    hbox_layout = new QHBoxLayout(shapka_widget);
    hbox_layout->addWidget(menu_button);
    hbox_layout->addSpacing(20);
    hbox_layout->addWidget(chats_button);
    hbox_layout->addSpacerItem(h_spacer);
    hbox_layout->addWidget(search_edit);
    hbox_layout->addWidget(search_button);
    hbox_layout->addSpacerItem(h_spacer);
    hbox_layout->addWidget(user_button);


    // Main components
    main_widget = new QWidget(central_widget);
    main_widget->setStyleSheet("*{background-color: 11111;}");

    search_widget = new QWidget(main_widget);
    search_widget->setStyleSheet("*{background-color: #2D2D2D;}");
    search_widget->setMinimumSize(700, 500);
    search_widget->setHidden(true);

    // chats widget
    users_widget = new QWidget(main_widget);
    users_widget->setStyleSheet("*{background-color: #2D2D2D;}");
    users_widget->setMaximumWidth(350);

    chats_scroll = new QScrollArea();
    chats_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    chatsvbox_layout = new QVBoxLayout(users_widget);
    chatsvbox_layout->setAlignment(Qt::AlignTop);
    chatsvbox_layout->setSpacing(5);

    chats_scroll->setWidget(users_widget);

    users_widget->setHidden(true);

    mvbox_layout = new QVBoxLayout(main_widget);
    mvbox_layout->addWidget(users_widget);
    mvbox_layout->setContentsMargins(0,0,0,0);

    // Connections
    connect(search_edit, &QLineEdit::returnPressed, this, &MainWindow::search_data);
    connect(search_button, &QPushButton::clicked, this, &MainWindow::search_data);
    connect(chats_button, &QPushButton::clicked, this, &MainWindow::open_chats);
    connect(menu_button, &QPushButton::clicked, this, &MainWindow::open_main);

    //Central widget layout
    vbox_layout = new QVBoxLayout(central_widget);
    vbox_layout->addWidget(shapka_widget);
    vbox_layout->addWidget(main_widget);
    vbox_layout->setContentsMargins(0,0,0,0);
    vbox_layout->setSpacing(0);
}

void MainWindow::addchat(){

}

void MainWindow::removechat(int index){

}

void MainWindow::removeallchats(){

}

void MainWindow::search_data(){
    if(search_edit->text() != nullptr){
        if(search_widget->isHidden()){
            search_widget->setHidden(false);
            if (isMaximized() || isFullScreen()) search_widget->move((main_widget->width() + search_widget->width()) / 4 + 20, 0);
            else search_widget->move(main_widget->width() / 4, 0);
        }
        search_edit->setPlaceholderText("Search...");
    }else search_edit->setPlaceholderText("Please enter something...");
}

void MainWindow::open_chats(){
    if(users_widget->isHidden()) users_widget->setHidden(false);
}

void MainWindow::open_main(){
    if(users_widget->isVisible()) users_widget->setHidden(true);
}

MainWindow::~MainWindow() {}
