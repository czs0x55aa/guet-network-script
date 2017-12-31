# coding=utf-8
import socket, time
import hashlib, os
import sys
import binascii

# 读取配置信息

pack_template = bytearray([0x82, 0x23, 0x21, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
                    0x00, 0x39, 0x67, 0x64, 0x74, 0x34, 0x33, 0x37,
                    0x34, 0x35, 0x77, 0x72, 0x77, 0x71, 0x72, 0x1e,
                    0x00, 0x00, 0x00, 0xFF, 0x74, 0x34, 0x33, 0x37,
                    0x35, 0x42, 0x38, 0x32, 0x35, 0x37, 0x44, 0x44,
                    0x31, 0x35, 0x30, 0x45, 0xFF, 0x44, 0x37, 0x36,
                    0x44, 0x31, 0x35, 0x46, 0x33, 0x35, 0x46, 0x30,
                    0x44, 0x11, 0x00, 0x00, 0x00, 0x31, 0x31, 0x3a,
                    0x32, 0x32, 0x3a, 0x33, 0x33, 0x3a, 0x34, 0x34,
                    0x3a, 0x35, 0x35, 0x3a, 0x36, 0x36, 0x2d, 0x1f,
                    0xd6, 0x03, 0xcc, 0xf2, 0x24, 0x00, 0x0a, 0x00,
                    0x00, 0x00, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79,
                    0x75, 0x69, 0x6f, 0x70])

def to_hex(byte_arr):
    hex_str = binascii.hexlify(byte_arr)
    hex_str_list = ['0x' + hex_str[i: i+2] for i in range(0, len(hex_str), 2)]
    for i in range(0, len(hex_str_list), 16):
        print(' '.join(hex_str_list[i: i+16]))

def hex_equal(source, target):
    if len(source) != len(target):
        return False
    for a, b in zip(source, target):
        if a != b:
            return False
    return True

class ClientAgent(object):
    def __init__(self):
        self.addr = ('172.16.1.1', 5300)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def handshake(self, username, password):
        print('Sending Handshake Packet...')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(self.addr)

        sock.send(self._get_0x1f(username))
        _0x20 = sock.recv(1024)
        _0x20 = bytearray(_0x20)
        # 校验控制字段
        if hex_equal(_0x20[:3], [0x82, 0x23, 0x20]) is True:
            print('Receiving key packet...')
            _0x21 = self._get_0x21(_0x20, username, password)
            sock.send(self._get_0x21(_0x20, username, password))
            _0x22 = sock.recv(1024)
            _0x22 = bytearray(_0x22)
            to_hex(_0x22)
            if hex_equal(_0x22[:4], [0x82, 0x23, 0x22, 0x00]):
                # 开放成功
                return True
        # 连接失败
        return False

    def _get_0x1f(self, username):
        hex_pack = bytearray(300)
        # 0x82 0x23 -控制字段, 0x1f -请求开放IP
        for i, val in enumerate([0x82, 0x23, 0x1f]):
            hex_pack[i] = val
        hex_pack[0x0b] = len(username)  # 用户名长度
        # 用户名ASCII偏移
        for i, val in enumerate(username):
            hex_pack[0x0f+i] = ord(val) - 0x0a
        # 填充
        filler = [0x0b, 0x00, 0x00, 0x00, 0x21, 0x40, 0x23, 0x24, 0x25, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29, 0x07, 0x00, 0x00,
        0x00, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x39, 0x30, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x41, 0x53, 0x44, 0x46, 0x47, 0x48]
        for i, val in enumerate(filler):
            hex_pack[0x19+i] = val
        return hex_pack

    def _get_0x21(self, _0x20, username, password):
        key =  (_0x20[0x34] << 8) + _0x20[0x33] # 处理小端数据
        key = key - 0x0d10
        self.livekey = key + 1500   # 心跳包中使用
        src = str(key) + password
        md5_1 = hashlib.md5(src).hexdigest().upper()
        src = md5_1[:5] + username
        md5_2 = hashlib.md5(src).hexdigest().upper()
        ciphertext = bytearray(md5_2[:30])  # 取前30个字符

        hex_pack = bytearray(300)
        for i, val in enumerate(pack_template):
            hex_pack[i] = pack_template[i]
        for i, val in enumerate(ciphertext):
            hex_pack[0x21+i] = val
        return hex_pack

class LiveAgent(object):
    def __init__(self, username, livekey):
        self.addr = ('172.16.1.1', 5301)
        self.pack = self._get_livepack(username, livekey)

    def _get_livepack(self, username, livekey):
        livepack = bytearray(500)
        mid = [0xe4, 0x3e, 0x86, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x5c, 0x8f, 0xc2, 0xf5, 0xf0, 0xa9, 0xdf, 0x40]
        # 0x1e 心跳包
        for i, val in enumerate([0x82, 0x23, 0x1e]):
            livepack[i] = val
        # 转化为小端格式
        livepack[0x03] = (livekey & 0xff00) >> 8;
        livepack[0x04] = (livekey & 0x00ff)
        # 这一段不明含义
        for i in range(15):
            livepack[0x0b + i] = mid[i]
        # 用户名
        for i, val in enumerate(username):
            livepack[0x1f + i] = ord(val)
        # ??
        pos = 31 + len(username) - 1
        spider = bytearray([0x09, 0x00, 0x00, 0x00, 0x53, 0x70, 0x69, 0x64, 0x65, 0x72, 0x6d, 0x61, 0x6e])
        for i in range(0, 13):
            livepack[pos + i + 1] = spider[i]
        return livepack

    def cast_coins(self):
        # 持续发送心跳
        while True:
            time.sleep(60)
            ret = self.sock.sendto(self.livepack, self.addr)
            # 检查网络状态 无法连通则结束循环
            if True:
                return False
            # 分析账号余额


def get_account():
    account_list = [
        ('1501111111', '123456'),
        ('1501111111', '123456'),
        ('1501111111', '123456'),
    ]
    while True:
        # 无限循环账号列表
        for username, passwd in account_list:
            yield username, passwd

if __name__ == '__main__':
    client_agent = ClientAgent()
    while True:
        # 获取一个新的账号
        username, password = get_account()
        login_flag = False
        # 开放出校器
        while True:
            try:
                login_flag = client_agent.handshake(username, password)
                # 完成一次连接过程
                break
            except socket.error:
                # 网络错误 等待重试
                # 判断是否能够获取到IP
                if True:
                    time.sleep(60)
                else:
                    # 获取不到ip 长时等待
                    time.sleep(60 * 10)
                continue
        # 判断登陆状态
        if login_flag is True:
            # 登陆成功
            live_agent = LiveAgent(username, client_agent.livekey)
            live_agent.cast_coins()
            # 外网连接出现问题 进入下一次循环
