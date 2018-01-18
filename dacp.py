#! /usr/bin/env python
# -*- coding:utf-8 -*-
'''
Created on 2017年7月10日

@author: errorre
'''



import os
import re

print("'''此工具为基本要求测评表：主机安全（S3A3G3）——linux主机v0.2.xlsx辅助工具'''\
    需要用ROOT权限运行\
    -------------------------------------------------------------------------------------")

def quanxian(yinru,filename):
    jishu = 0
    quanxian1,quanxian2,quanxian3 = 0,0,0
    for i in yinru:
        if jishu > 0 and jishu < 4:
            if i == 'r':
                quanxian1 += 4
            elif i == 'w':
                quanxian1 += 2
            elif i == 'x':
                quanxian1 += 1
            else:
                quanxian1 += 0
        elif jishu > 3 and jishu < 7:
            if i == 'r':
                quanxian2 += 4
            elif i == 'w':
                quanxian2 += 2
            elif i == 'x':
                quanxian2 += 1
            else:
                quanxian1 += 0
        elif jishu > 6 and jishu < 10:
            if i == 'r':
                quanxian3 += 4
            elif i == 'w':
                quanxian3 += 2
            elif i == 'x':
                quanxian3 += 1
            else:
                quanxian1 += 0
        else:
            pass      
        jishu += 1
    print("%s文件权限为：%d%d%d" %(filename,quanxian1,quanxian2,quanxian3))

#查看是否有空账号
sfjb_a = os.popen('''awk -F: '($2 == "") { print $1 }' /etc/shadow''').read()
if sfjb_a != '':
    print('测评表第8行 空口令账户为：'+sfjb_a)
    print('')
else:
    print('测评表第8行 不存在空口令账户')

#查看/etc/login.defs 文件内参数
sfjb_b = os.popen("more /etc/login.defs").read()
sfjb_b_max = re.findall(r'PASS_MAX_DAYS\s(\d+)',sfjb_b)
sfjb_b_min = re.findall(r'PASS_MIN_DAYS\s(\d+)',sfjb_b)
sfjb_b_len = re.findall(r'PASS_MIN_LEN\s(\d+)',sfjb_b)
sfjb_b_age = re.findall(r'PASS_WARN_AGE\s(\d+)',sfjb_b)
print("测评表第9行 ")
try:
    print('PASS_MAX_DAYS：'+sfjb_b_max[0])
except:
    print('PASS_MAX_DAYS不存在该值')

try:
    print('PASS_MIN_DAYS：'+sfjb_b_min[0])
except:
    print('PASS_MIN_DAYS不存在该值')

try:
    print('PASS_MIN_LEN：'+sfjb_b_len[0])
except:
    print('PASS_MIN_LEN不存在该值')

try:
    print('PASS_WARN_AGE：'+sfjb_b_age[0])
except:
    print('ASS_WARN_AGE不存在该值')

#查看/etc/pam.d/system-auth文件内配置
sfjb_c = os.popen("cat /etc/pam.d/system-auth").read()
sfjb_c_lib = re.search(r'/lib/security/pam_tally.so',sfjb_c)
print("测评表第10行")
if sfjb_c_lib != None:
    print('已启用非法登录限制，请自己手动查看')
else:
    print('未启用非法登录限制')

#查看UID重复情况
print("测评表第12行")
list_uid = []
panduan = 0
sfjb_e = os.popen("cat /etc/passwd").readlines()
for i in sfjb_e:
    uid = re.findall(r'\S+?:\S+?:(\d*):',i)
    if uid[0] not in list_uid:
        list_uid.append(uid[0])
    else:
        panduan = 1
        print('重复的UID为'+uid[0]+',详情请查看文件')
if panduan == 0:
    print("没有重复的UID")
else:
    pass


#查看passwd，shadow，rc3.d，profile文件权限
print("测评表第14行")
fwkz_a_passwd = os.popen("ls -l /etc/passwd").read()
fwkz_a_shadow = os.popen("ls -l /etc/shadow").read()
fwkz_a_rc3 = os.popen("ls -l /etc/rc.d|grep rc3.d").read()
fwkz_a_profile = os.popen("ls -l /etc/profile").read()
fwkz_a_profile2 = os.popen("ls -l /etc|grep profile.d").read()
quanxian(fwkz_a_passwd,"passwd")
quanxian(fwkz_a_shadow,"shadow")
quanxian(fwkz_a_rc3,"rc3.d")
quanxian(fwkz_a_profile,"profile")
quanxian(fwkz_a_profile2,"profile.d")

#查看home目录下权限
print("测评表第15行")
fwkz_b = os.popen("ls -l /home/").read()
print("home文件夹下的目录权限为："+fwkz_b)

#查看是否有未禁用的系统默认账户
print("测评表第17行")
fwkz_d = os.popen("cat /etc/passwd").readlines()
zhanghu = ''
for i in fwkz_d:
    nologin = i[-8:-1]
    if nologin == "nologin" or nologin == "n/false":
        pass
    else:
        a = i.find(":")
        b = i[0:a]
        zhanghu +=  b+" "
print("该系统未被禁用的账户为："+zhanghu)

#查看日志和审计服务是否开启
print("测评表第21行")
aqsj_a = os.popen("service --status-all|grep running").read()
aqsj_a2 = os.popen("service --status-all|grep 正在运行").read()
if "syslog" in aqsj_a or "syslog" in aqsj_a2:
    print("日志服务正在运行")
else:
    print("日志服务没有运行")
if "audit" in aqsj_a or "audit" in aqsj_a2:
    print("审计服务正在运行,您需要手动查看以下审计相关选项")
else:
    print("审计服务没有运行")

print("测评表第31行")
print("正在运行的服务有："+aqsj_a+aqsj_a2)

#查看系统补丁安装情况
rqff_c = os.popen("rpm -qa|grep patch").read()
print("补丁情况："+rqff_c)

#查看登录地址限制策略
print("测评表第35行")
zykz_a = os.popen("cat /etc/hosts.deny").read()
if "ALL:ALL" in zykz_a:
    print("已配置登录地址限制策略")
else:
    print("未配置登录地址限制策略")

#查看连接超时环境变量
print("测评表第36行")
zykz_b = os.popen("cat /etc/profile").read()
zykz_b2 = os.popen("cat ~/.bash_profile").read()
if "TMOUT" in zykz_b or "TMOUT" in zykz_b2:
    print("已配置连接超时退出时间，请手动查看，查看命令为Cat /etc/proflie cat ~/.bash_profile")
else:
    print("未配置连接超时退出时间")

#查看系统资源限度
print("测评表第38行")
zykz_d = os.popen("cat /etc/security/limits.conf").read()
if "#@student" and "#*soft" and "#*hard" and "#@faculty" in zykz_d:
    print("系统资源没有限制")
else:
    print("对系统资源有做限制，请手动查看,参考命令：cat /etc/security/limits.conf")

os.popen("rm -f dacp.py")
print("本脚本运行后自动删除\
---------------------------------------\
删除成功！")