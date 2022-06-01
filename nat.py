#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'wanghaotian' 

import re
import xlwings as xw
from service_set import service_set

# excel文件
xlsx_file = 'ip.xlsx'

# 策略组
group = 'packet-filter'

# 信息类，用于存储策略信息
class Policy_info:

    def __init__(self, external_ip,cloud_ip,external_port,cloud_port,external_domain):
        self.external_ip = external_ip
        self.cloud_ip = cloud_ip
        self.external_port = external_port
        self.cloud_port = cloud_port
        self.external_domain = external_domain
    def display(self):
        print('self.external_ip=',self.external_ip)
        print('self.cloud_ip=',self.cloud_ip)
        print('self.external_port=',self.external_port)
        print('self.cloud_port=',self.cloud_port)
        print('self.external_domain=',self.external_domain)

#初始化函数，读出文件中的ip和端口信息，返回Policy_info_list列表
def init_file(xlsx_file):
    app = xw.App(visible=True,add_book=False)
    app.display_alerts=False
    app.screen_updating=False

    wb=app.books.open(xlsx_file)

    Policy_info_list = []
    for sheet in wb.sheets:
        rg = sheet.range('A2:D100')
        colunm_id = 0
        external_ip_list  = []
        external_port_list = []
        cloud_ip_list = []
        cloud_port_list = []
        external_domain_list = []
        for column in rg.columns:
            for value in column.options(numbers=str).value:
                if value != None:
                    # 初始化外部ip
                    if colunm_id == 0:
                        try:
                            external_ip_list.append(value.strip())
                        except:
                            print(type(value))
                        else:
                            continue
                    # 初始化外部端口
                    elif colunm_id == 1:
                        external_port_list.append(value.strip())
                    # 初始化云内ip
                    elif colunm_id == 2:
                        cloud_ip_list.append(value.strip())
                    # 初始化云内端口
                    elif colunm_id == 3:
                        # 替换结尾的.0
                        value = value.replace('.0',' ')
                        cloud_port_list.append(value.strip())
                    # 初始化外部域名
                    elif colunm_id == 4:
                        external_domain_list.append(value.strip())
                else:
                    colunm_id += 1
                    break
        Policy_info_list.append(Policy_info(external_ip_list,cloud_ip_list,external_port_list,cloud_port_list,external_domain_list))
    wb.close()
    app.quit()
    return Policy_info_list

# 生成防火墙策略  
# 参数1:策略方向，参数2:rule name编号，参数3:信息类
def nat_policy(direction,rule_num,Policy_info) -> str:
    # external_ip_list,cloud_ip_list,external_port_list,external_port_list,cloud_port_list,external_domain_list = init_file(xlsx_file)
    #初始化总体脚本
    all_script = ''
    #入云方向
    if direction == 'in' :
        for dest_ip in Policy_info.cloud_ip:
            #rule名字
            rule_name = f'rule name in-{dest_ip}-{rule_num}\n'
            #策略组
            parent_group = ''
            if group:
                parent_group = f'parent-group {group}\n'
            #策略方向
            zone = 'source-zone untrust\ndestination-zone trust\n'
            #源地址
            source_address = ''
            for source_ip in Policy_info.external_ip :
                #地址段的/替换为空格
                try:
                    source_ip = re.sub(r'/',' ',source_ip)
                except:
                    print("源地址替换失败")
                else:
                    #以空格分隔
                    source_ip = source_ip.split(' ')
                    # 网段加掩码模式
                    if len(source_ip) == 2 :
                        mask = source_ip[1]
                        # 如果掩码是xxx.xxx.xxx.xxx格式
                        if re.fullmatch(r'^((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$',mask) :
                            source_address = f'{source_address}source-address {source_ip[0]} mask {mask}\n'
                        # 如果掩码是十进制格式
                        elif re.fullmatch(r'^(\d)|(1\d)|(2\d)|(3[0-2])$',mask) :
                            source_address = f'{source_address}source-address {source_ip[0]} {mask}\n'
                        # 格式错误
                        else :
                            raise ValueError('external mask format error!')                    
                    # host模式
                    elif len(source_ip) == 1 :
                        source_address = f'{source_address}source-address {source_ip[0]} mask 255.255.255.255\n'
                    #格式错误
                    else :
                        raise ValueError('external ip format error!')
            #目的地址
            dest_address = f'destination-address {dest_ip} mask 255.255.255.255\n'
            #目的端口
            service = ''
            if Policy_info.cloud_port :
                for dest_port in Policy_info.cloud_port :
                    # 数字格式的非常见端口，命名为TCP_dst_port
                    if re.fullmatch(r'\d+',dest_port) :
                        service = f'{service}service TCP_dst_{dest_port}\n'
                    # 英文格式的常见端口
                    elif re.fullmatch(r'[A-Za-z]+',dest_port) :
                        service = f'{service}service {dest_port}\n'
                    else :
                        raise ValueError('cloud port format error!')
            #生成一条rule
            rule_script = f'{rule_name}{parent_group}{zone}{source_address}{dest_address}{service}action permit\nq\n'
            #将rule添加到总体脚本
            all_script = f'{all_script}{rule_script}'
    #出云方向
    elif direction == 'out' :
        for source_ip in Policy_info.cloud_ip:
            #rule名字
            rule_name = f'rule name out-{source_ip}-{rule_num}\n'
            #策略组
            parent_group = ''
            if group:
                parent_group = f'parent-group {group}\n'
            #策略方向
            zone = 'source-zone trust\ndestination-zone untrust\n'
            #源地址
            source_address = f'source-address {source_ip} mask 255.255.255.255\n'
            #目的地址
            dest_address = ''
            if Policy_info.external_ip:
                for dest_ip in Policy_info.external_ip :
                    #地址段的/替换为空格
                    try:
                        dest_ip = re.sub(r'/',' ',dest_ip)
                    except:
                        print("目的地址替换失败")
                    else:
                        #以空格分隔
                        dest_ip = dest_ip.split(' ')
                        # 网段加掩码模式
                        if len(dest_ip) == 2 :
                            mask = dest_ip[1]
                            # 如果掩码是xxx.xxx.xxx.xxx格式
                            if re.fullmatch(r'^((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$',mask) :
                                dest_address = f'{dest_address}destination-address {dest_ip[0]} mask {mask}\n'
                            # 如果掩码是十进制格式
                            elif re.fullmatch(r'^\d|1\d|2\d|3[0-2]$',mask) :
                                dest_address = f'{dest_address}destination-address {dest_ip[0]} {mask}\n'
                            # 格式错误
                            else :
                                raise ValueError('external mask format error!')
                        # host模式
                        elif len(dest_ip) == 1 :
                            dest_address = f'{dest_address}destination-address {dest_ip[0]} mask 255.255.255.255\n'
                        # 格式错误
                        else :
                            raise ValueError('external ip format error!')
            #目的域名
            dest_domain = ''
            if Policy_info.external_domain:
                for domain in Policy_info.external_domain :
                    dest_domain = f'{dest_domain}profile url-filter {domain}\n'            
            #目的端口
            service = ''
            if Policy_info.external_port :
                for dest_port in Policy_info.external_port :
                    # 数字格式的非常见端口，命名为TCP_des_port
                    if re.fullmatch(r'\d+',dest_port) :
                        service = f'{service}service TCP_dst_{dest_port}\n'
                    # 英文格式的常见端口
                    elif re.fullmatch(r'[A-Za-z]+',dest_port) :
                        service = f'{service}service {dest_port}\n'
                    else :
                        raise ValueError('cloud port format error!')
            #生成一条rule
            rule_script = f'{rule_name}{parent_group}{zone}{source_address}{dest_address}{dest_domain}{service}action permit\nq\n'
            #将rule添加到总体脚本
            all_script = f'{all_script}{rule_script}'
    return all_script

# 删除策略中的地址、端口  
# 参数1:策略方向，参数2:rule name编号,参数3:信息类
def nat_policy_undo(direction,rule_num,Policy_info) -> str:
    # external_ip_list,cloud_ip_list,external_port_list,external_port_list,cloud_port_list,external_domain_list = init_file(xlsx_file)
    #初始化总体脚本
    all_script = ''
    #入云方向
    if direction == 'in' :
        for dest_ip in Policy_info.cloud_ip:
            #rule名字
            rule_name = f'rule name in-{dest_ip}-{rule_num}\n'
            #源地址
            source_address = ''
            for source_ip in Policy_info.external_ip :
                source_ip = re.sub(r'/',' ',source_ip)
                source_ip = source_ip.split(' ')
                # 网段加掩码模式
                if len(source_ip) == 2 :
                    mask = source_ip[1]
                    # 如果掩码是xxx.xxx.xxx.xxx格式
                    if re.fullmatch(r'^((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$',mask) :
                        source_address = f'{source_address}undo source-address {source_ip[0]} mask {mask}\n'
                    # 如果掩码是十进制格式
                    elif re.fullmatch(r'^(\d)|(1\d)|(2\d)|(3[0-2])$',mask) :
                        source_address = f'{source_address}undo source-address {source_ip[0]} {mask}\n'
                    # 格式错误
                    else :
                        raise ValueError('external mask format error!')                    
                # host模式
                elif len(source_ip) == 1 :
                    source_address = f'{source_address}undo source-address {source_ip[0]} mask 255.255.255.255\n'
                #格式错误
                else :
                    raise ValueError('external ip format error!')
            #目的端口
            service = ''
            if Policy_info.cloud_port :
                for dest_port in Policy_info.cloud_port :
                    # 数字格式的非常见端口，命名为TCP_des_port
                    if re.fullmatch(r'\d+',dest_port) :
                        service = f'{service}undo service TCP_dst_{dest_port}\n'
                    # 英文格式的常见端口
                    elif re.fullmatch(r'[A-Za-z]+',dest_port) :
                        service = f'{service}undo service {dest_port}\n'
                    else :
                        raise ValueError('cloud port format error!')
            #生成一条rule
            rule_script = f'{rule_name}{source_address}{service}\nq\n'
            #将rule添加到总体脚本
            all_script = f'{all_script}{rule_script}'
    #出云方向
    elif direction == 'out' :
        for source_ip in Policy_info.cloud_ip:
            #rule名字
            rule_name = f'rule name out-{source_ip}-{rule_num}\n'
            #源地址
            source_address = f'source-address {source_ip} mask 255.255.255.255\n'
            #目的地址
            dest_address = ''
            if Policy_info.external_ip:
                for dest_ip in Policy_info.external_ip :
                    dest_ip = re.sub(r'/',' ',dest_ip)
                    dest_ip = dest_ip.split(' ')
                    # 网段加掩码模式
                    if len(dest_ip) == 2 :
                        mask = dest_ip[1]
                        # 如果掩码是xxx.xxx.xxx.xxx格式
                        if re.fullmatch(r'^((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$',mask) :
                            dest_address = f'{dest_address}undo destination-address {dest_ip[0]} mask {mask}\n'
                        # 如果掩码是十进制格式
                        elif re.fullmatch(r'^\d|1\d|2\d|3[0-2]$',mask) :
                            dest_address = f'{dest_address}undo destination-address {dest_ip[0]} {mask}\n'
                        # 格式错误
                        else :
                            raise ValueError('external mask format error!')
                    # host模式
                    elif len(dest_ip) == 1 :
                        dest_address = f'{dest_address}undo destination-address {dest_ip[0]} mask 255.255.255.255\n'
                    # 格式错误
                    else :
                        raise ValueError('external ip format error!')
            #目的域名
            dest_domain = ''
            if Policy_info.external_domain:
                for domain in Policy_info.external_domain :
                    dest_domain = f'{dest_domain}undo profile url-filter {domain}\n'            
            #目的端口
            service = ''
            if Policy_info.external_port :
                for dest_port in Policy_info.external_port :
                    # 数字格式的非常见端口，命名为TCP_des_port
                    if re.fullmatch(r'\d+',dest_port) :
                        service = f'{service}undo service TCP_dst_{dest_port}\n'
                    # 英文格式的常见端口
                    elif re.fullmatch(r'[A-Za-z]+',dest_port) :
                        service = f'{service}undo service {dest_port}\n'
                    else :
                        raise ValueError('cloud port format error!')
            #生成一条rule
            rule_script = f'{rule_name}{source_address}{dest_address}{dest_domain}{service}\nq\n'
            #将rule添加到总体脚本
            all_script = f'{all_script}{rule_script}'
    return all_script

# 生成总脚本函数
def script_gen(direction,rule_num,file_name = xlsx_file,undo = 0) -> str:
    Policy_info_list = init_file(file_name)
    script = ''
    for Policy_info in Policy_info_list:
        if undo == 0:        
            script = f'{script}{nat_policy(direction,rule_num,Policy_info)}'
        else:
            script = f'{script}{nat_policy_undo(direction,rule_num,Policy_info)}'
    return script

if __name__ == '__main__':
    long_banner = '1.生成入向脚本\n2.生成出向脚本\n3.生成出入向脚本\n4.生成入向删除脚本\n5.生成出向删除脚本\n6.生成service-set脚本\nq.退出程序\n请输入: '
    short_banner = '1.生成入向脚本 2.生成出向脚本 3.生成出入向脚本 \n4.生成入向删除脚本 5.生成出向删除脚本 6.生成service-set脚本\nq.退出程序\n请输入: '
    a = input(long_banner)
    while True :
        if a == '1':
            num=input('输入入向策略编号,格式01～999: ')
            while True:
                if re.fullmatch(r'^\d{2,3}$',num) :
                    script = script_gen('in',num)
                    break
                else :
                    num=input('策略编号格式错误,请重新输入，格式01～999: ')
            with open('nat_script.txt','w+') as f:
                f.write(script)
            print('Done')
            a = input(short_banner)
        elif a == '2':
            num=input('输入出向策略编号,格式01～999: ')
            while True:
                if re.fullmatch(r'^\d{2,3}$',num) :
                    script = script_gen('out',num)
                    break
                else :
                    num=input('策略编号格式错误,请重新输入，格式01～999: ')
            with open('nat_script.txt','w+') as f:
                f.write(script)
            print('Done')
            a = input(short_banner )
        elif a == '3':
            num=input('输入入向策略编号,格式01～999: ')
            while True:
                if re.fullmatch(r'^\d{2,3}$',num) :
                    inscript = script_gen('in',num)
                    break
                else :
                    num=input('策略编号格式错误,请重新输入，格式01～999: ')
            num=input('输入出向策略编号,格式01～999: ')
            while True:
                if re.fullmatch(r'^\d{2,3}$',num) :
                    outscript = script_gen('out',num)
                    break
                else :
                    num=input('策略编号格式错误,请重新输入，格式01～999: ')
            with open('nat_script.txt','w+') as f:
                f.write(inscript)
                f.write(outscript)
            print('Done')
            a = input(short_banner)
        elif a == '4':
            num=input('输入入向策略编号,格式01～999: ')
            while True:
                if re.fullmatch(r'^\d{2,3}$',num) :
                    script = script_gen(direction='in',rule_num=num,undo=1)
                    break
                else :
                    num=input('策略编号格式错误,请重新输入，格式01～999: ')                    
            with open('nat_script.txt','w+') as f:
                f.write(script)
            print('Done')
            a = input(short_banner )
        elif a == '5':
            num=input('输入出向策略编号,格式01～999: ')
            while True:
                if re.fullmatch(r'^\d{2,3}$',num) :
                    script = script_gen(direction='out',rule_num=num,undo=1)
                    break
                else :
                    num=input('策略编号格式错误,请重新输入，格式01～999: ')  
            with open('nat_script.txt','w+') as f:
                f.write(script)
            print('Done')
            a = input(short_banner )
        elif a == '6':
            service_set_script = service_set()
            with open('nat_script.txt','w+') as f:
                f.write(service_set_script)
            print('Done')
            a = input(short_banner )
        elif a == 'q' :
            print('Quit')
            break
        else :
            a = input('输入错误，请输入1-7、q: ')