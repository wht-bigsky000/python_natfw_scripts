#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re

def service_set():
    port = input('请输入服务端口,多个端口用空格分隔: ')
    #去掉结尾空格
    port = port.rstrip()
    #以空格分隔
    port = port.split(' ')
    script = ''
    for num in port:
        while True:
            if re.fullmatch(r'^\d{1,5}$',num):
                script = f'{script}ip service-set TCP_dst_{num} type object\n service 0 protocol tcp source-port 0 to 65535 destination-port {num}\nq\n'
                break
            else:
                num = input('端口号格式错误,请重新输入，格式1～65535: ')
    return script