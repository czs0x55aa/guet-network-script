# coding=utf8
import socket
import hashlib
import util

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

def accounts_generator(accounts):
    account_list = [(x['username'], x['password']) for x in accounts]
    while True:
        # 无限循环账号列表
        for username, passwd in account_list:
            yield username, passwd

class ClientAgent(object):
    def __init__(self, addr, port):
        self.addr = (addr, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)

    def handshake(self, username, password):
        print('Sending Handshake Packet...')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(self.addr)

        sock.send(self._get_0x1f(username))
        _0x20 = sock.recv(1024)
        _0x20 = bytearray(_0x20)
        # 校验控制字段
        if util.hex_equal(_0x20[:3], [0x82, 0x23, 0x20]) is True:
            print('Receiving key packet...')
            _0x21 = self._get_0x21(_0x20, username, password)
            sock.send(self._get_0x21(_0x20, username, password))
            _0x22 = sock.recv(1024)
            _0x22 = bytearray(_0x22)
            if util.hex_equal(_0x22[:4], [0x82, 0x23, 0x22, 0x00]):
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
    def __init__(self, addr, port):
        self.addr = (addr, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)

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

    def cast_coins(self, username, livekey):
        live_pack = self._get_livepack(username, livekey)
        # 发送心跳包
        try:
            ret = self.sock.sendto(live_pack, self.addr)
            print('send live packet.')
            # TODO 分析账号余额...
            return True
        except socket.error:
            return False
