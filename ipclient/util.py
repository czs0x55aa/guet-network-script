# coding=utf8
import binascii
import commands
import netifaces as ni

def to_hex(byte_arr):
    """ 输出十六进制数据 用于调试 """
    hex_str = binascii.hexlify(byte_arr)
    hex_str_list = ['0x' + hex_str[i: i+2] for i in range(0, len(hex_str), 2)]
    for i in range(0, len(hex_str_list), 16):
        print(' '.join(hex_str_list[i: i+16]))

def hex_equal(source, target):
    """ 判断数据是否相等 """
    if len(source) != len(target):
        return False
    for a, b in zip(source, target):
        if a != b:
            return False
    return True

def execute_cmd(cmd_str):
    """ 执行shell """
    try:
        return commands.getstatusoutput(cmd_str)
    except Exception as e:
        print e

def try_to_ping(target_host):
    """ 测试网络连通性 """
    try:
        (ping_state, res) = execute_cmd('ping %s -c 2' % target_host)
        # ping_state == 0 when ping is success
        return True if ping_state == 0 else False
    except Exception as e:
        return False

# def get_local_ip(device_name):
#     """ 获取本地IP地址 """
#     if device_name in ni.interfaces():
#         device_info = ni.ifaddresses(device_name)
#         if ni.AF_INET in device_info:
#             local_ip = device_info[ni.AF_INET][0]['addr']
#             return True
#     return False
