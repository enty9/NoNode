#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QPixmap>
#include <QHBoxLayout>
#include <QBoxLayout>
#include <QWidget>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QSize>
#include <QCursor>
#include <Qt>
#include <QMouseEvent>
#include <QSpacerItem>
#include <QMenu>
#include <iostream>
#include <vector>
#include <string>
#include <QScrollArea>

using namespace std;

class ChatsWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    QPushButton *menu_button;
    QPushButton *user_button;
    QPushButton *chats_button;
    QPushButton *search_button;

    QHBoxLayout *hbox_layout;
    QVBoxLayout *vbox_layout;
    QVBoxLayout *mvbox_layout;
    QVBoxLayout *chatsvbox_layout;

    QWidget *shapka_widget;
    QWidget *main_widget;
    QWidget *users_widget;
    QWidget *chat_widget;
    QWidget *search_widget;
    QWidget *person_widget;

    QWidget *central_widget;
    QLineEdit *search_edit;
    QSpacerItem *h_spacer;
    QScrollArea *chats_scroll;

    vector<ChatsWidget> *chats_widgetsArray;
    vector<string> datachats;
    void refreshChats();

    bool isFullscreen;

    void close(){
        if(!search_widget->isHidden()){
            search_widget->setHidden(true);
        }
    }

private slots:
    void search_data();
    void open_chats();
    void open_main();

    // for work with chats_array
    void addchat();
    void removechat(int index);
    void removeallchats();

protected:
    void mousePressEvent(QMouseEvent *event) override{
        if(event->button() == Qt::LeftButton){
            close();
        }
        QMainWindow::mousePressEvent(event);
    }
    void resizeEvent(QResizeEvent *e){
        QWidget::resizeEvent(e);

        if(search_widget->isVisible()) search_widget->hide();
    }

};

class ChatsWidget : public QWidget{
    Q_OBJECT
public:
    explicit ChatsWidget(const string& data, int index, QWidget *parent = nullptr);

signals:
    void removedata(int index);
    void updatedata(int index, const std::string& newdata);

private:
    int widgetIndex;
    string widgetData;
};

#endif // MAINWINDOW_H
