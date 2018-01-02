# coding=utf-8
import socket, time
import json

import util
from ipclient import ClientAgent, LiveAgent, accounts_generator

# 读取配置信息
with open('./config.json') as config_file:
    config = json.load(config_file)

# 网络出错时的等待时长
wait_sec = config['wait_sec']

def main():
    client_agent = ClientAgent(config['open_server']['addr'], config['open_server']['port'])
    live_agent = LiveAgent(config['live_server']['addr'], config['live_server']['port'])
    accounts = accounts_generator(config['accounts'])
    while True:
        # 获取一个账号
        username, password = accounts.next()
        print('get account')
        connect_status = False
        # 开放出校器
        while True:
            try:
                connect_status = client_agent.handshake(username, password)
                # 完成一次连接过程
                break
            except socket.error:
                # 网络错误 等待重试
                # 判断是否能够ping通服务器
                if util.try_to_ping(config['open_server']['addr']) is True:
                    # ping通 等待一分钟
                    time.sleep(wait_sec)
                else:
                    # ping不通服务器 长时等待
                    time.sleep(wait_sec * 10)
                continue

        # 判断登陆状态
        if connect_status is True:
            # 登陆成功 进入心跳状态
            print('%s connect success.' % username)
            ping_error = 0
            while True:
                time.sleep(60)  # 心跳包每隔60s发送
                if live_agent.cast_coins(username, client_agent.livekey) is False:
                    # 心跳包发送失败
                    ping_error += 1
                if util.try_to_ping(config['test_server']['addr']) is False:
                    # 外网连通性测试失败
                    ping_error += 1
                else:
                    # 能够连接外网 清除出错次数
                    ping_error = 0

                if ping_error > 6:
                    # 出错达到一定次数 结束心跳状态 重新拨号连接
                    break
            # 出校器连接出现问题 进入下一次循环
        else:
            # 登陆失败后等待一会 避免频繁登陆被服务器屏蔽
            print('%s connect fail.' % username)
            time.sleep(wait_sec)

if __name__ == '__main__':
    main()
    pass
