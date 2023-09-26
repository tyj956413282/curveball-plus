/*************************************************************************
        > File Name: head.h
        > Author: Teng Yajun
        > Mail: tengyajun@iie.ac.cn
        > Created Time: Tue 15 Feb 2022 06:16:38 PM CST
 ************************************************************************/

#ifndef _COLOR_H
#define _COLOR_H

#define NONE  "\e[0m"           //�����ɫ����֮��Ĵ�ӡΪ���������֮ǰ�Ĳ���Ӱ��
#define BLACK  "\e[0;30m"  //���
#define L_BLACK  "\e[1;30m" //���ڣ�ƫ�Һ�
#define RED   "\e[0;31m" //��죬����
#define L_RED  "\e[1;31m" //�ʺ�
#define GREEN  "\e[0;32m" //���̣�����
#define L_GREEN   "\e[1;32m" //����
#define BROWN "\e[0;33m" //��ƣ�����
#define YELLOW "\e[1;33m" //�ʻ�
#define BLUE "\e[0;34m" //����������
#define L_BLUE "\e[1;34m" //������ƫ�׻�
#define PINK "\e[0;35m" //��ۣ����ۣ�ƫ����
#define L_PINK "\e[1;35m" //���ۣ�ƫ�׻�
#define CYAN "\e[0;36m" //����ɫ
#define L_CYAN "\e[1;36m" //������ɫ
#define GRAY "\e[0;37m" //��ɫ
#define WHITE "\e[1;37m" //��ɫ�������һ�㣬�������󣬱�boldС
#define BOLD "\e[1m" //��ɫ������
#define UNDERLINE "\e[4m" //�»��ߣ���ɫ��������С
#define BLINK "\e[5m" //��˸����ɫ��������С
#define REVERSE "\e[7m" //��ת�������屳��Ϊ��ɫ������Ϊ��ɫ
#define HIDE "\e[8m" //����
#define CLEAR "\e[2J" //���
#define CLRLINE "\r\e[K" //�����

#include <Windows.h>

#define SET_YELLOW \
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_RED);

#define SET_CLEAR \
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE);

#define SET_CUSTUM(x) \
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), x);

#endif