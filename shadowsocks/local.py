#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
本地(客户端)运行的程序
'''

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import utils, daemon, encrypt, eventloop, tcprelay, udprelay, \
    asyncdns

# local是本地的proxy
def main():
    # 检查python版本
    utils.check_python()

    # fix py2exe
    # 应该是专门为py2exe检查当前执行路径用的
    if hasattr(sys, "frozen") and sys.frozen in \
            ("windows_exe", "console_exe"):
        p = os.path.dirname(os.path.abspath(sys.executable))
        os.chdir(p)
        
    # 形参是is_local=True
    config = utils.get_config(True)

    # linux系统：执行守护进程
    daemon.daemon_exec(config)
    # 显示当前的ss版本号
    utils.print_shadowsocks()
    # 创建加密器类的实例
    encrypt.try_cipher(config['password'], config['method'])
    
    try:
        logging.info("starting local at %s:%d" % 
                     (config['local_address'], config['local_port']))

        # dns只是tcp上面的一个应用，所以没有自己的bind
        # 新建dns_resolver
        dns_resolver = asyncdns.DNSResolver()
        tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
        udp_server = udprelay.UDPRelay(config, dns_resolver, True)
        # 创建时间循环的类实例
        loop = eventloop.EventLoop()
        # dns请求报文发出去了之后要监测响应报文
        dns_resolver.add_to_loop(loop)    # client发远程网站地址给proxy，proxy去查找DNS
        tcp_server.add_to_loop(loop)    # 递送tcp数据
        udp_server.add_to_loop(loop)    # 递送udp数据

        # 定义退出信号捕获处理函数
        def handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            # 　连带关闭socket（因为next = true）
            tcp_server.close(next_tick = True)
            udp_server.close(next_tick = True)
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)
        
        # 进程终止
        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        # 运行事件循环，思想还是挺高端的
        loop.run()
    
    # 按下 Ctrl+c 退出
    except (KeyboardInterrupt, IOError, OSError) as e:
        logging.error(e)
        if config['verbose']:
            import traceback
            traceback.print_exc()
        os._exit(1)

if __name__ == '__main__':
    main()
