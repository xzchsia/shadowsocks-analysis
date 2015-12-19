#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
服务端
ps:我是先看完local.py再看server.py;
发现：除了多用户的思路判断，别的代码思路是一致的，部分没有注释，可以回去翻翻local.py
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


def main():
    utils.check_python()

    # is_local=false
    config = utils.get_config(False)

    daemon.daemon_exec(config)

    utils.print_shadowsocks()

    # 支持多客户端
    if config['port_password']:
        if config['password']:
            logging.warn('warning: port_password should not be used with '
                         'server_port and password. server_port and password '
                         'will be ignored')
    else:
        config['port_password'] = {}
        server_port = config['server_port']
        # 若发现有多用户配置：采用‘端口->密码’的映射方式。
        if type(server_port) == list:
            for a_server_port in server_port:
                config['port_password'][a_server_port] = config['password']
        else:
            config['port_password'][str(server_port)] = config['password']

    # Create an instance of the cipher class 
    encrypt.try_cipher(config['password'], config['method'])
    tcp_servers = []
    udp_servers = []
    dns_resolver = asyncdns.DNSResolver()
    
    # 一个服务器端可以打开多个端口
    # 对于每个端口，都要新建一个对应的处理器
    for port, password in config['port_password'].items():
        a_config = config.copy()
        a_config['server_port'] = int(port)
        a_config['password'] = password
        logging.info("starting server at %s:%d" % 
                     (a_config['server'], int(port)))
        # 逐一加到tcp、udp列表
        tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False))
        udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False))

    def run_server():    
        # 收到退出信号的处理函数，关闭所有socket释放资源。
        def child_handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            # 关闭所有的socket，一句话搞定，好厉害，跪拜ing
            # map(function, sequence[, sequence, ...]) -> list
            # Return a list of the results of applying the function to the items of the argument sequence(s).  
            list(map(lambda s: s.close(next_tick = True),
                     tcp_servers + udp_servers))
            
        # 收到退出信号，调用child_handler进行自杀。
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM),
                      child_handler)
        
        # 收到退出信号，调用int_handler进行自杀。
        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        try:
            loop = eventloop.EventLoop()
            dns_resolver.add_to_loop(loop)
            # 把所有的监听端口添加到时间循环中，一句话搞定，好厉害，跪拜ing
            list(map(lambda s: s.add_to_loop(loop), tcp_servers + udp_servers))
            loop.run()
        except (KeyboardInterrupt, IOError, OSError) as e:
            logging.error(e)
            if config['verbose']:
                import traceback
                traceback.print_exc()
            os._exit(1)

    # Shadowsocks supports spawning child processes like nginx.
    # You can use --workers to specify how many workers to use.
    # This argument is only supported on Unix and ssserver.
    # Currently UDP relay does not work well on multiple workers.
    # 支持像nginx多进程，可以在config中指定worker的数量。仅在linux下生效。
    # 目前的bug：worker设为大于1时，udp转发有可能工作不正常
    if int(config['workers']) > 1:
        if os.name == 'posix':
            children = []
            is_child = False
            for i in range(0, int(config['workers'])):
                r = os.fork()
                if r == 0:
                    logging.info('worker started')
                    is_child = True
                    run_server()
                    break
                else:
                    children.append(r)
            if not is_child:
                def handler(signum, _):
                    for pid in children:
                        try:
                            os.kill(pid, signum)
                            os.waitpid(pid, 0)
                        except OSError:    # child may already exited
                            pass
                    sys.exit()
                signal.signal(signal.SIGTERM, handler)
                signal.signal(signal.SIGQUIT, handler)
                signal.signal(signal.SIGINT, handler)

                # master
                for a_tcp_server in tcp_servers:
                    a_tcp_server.close()
                for a_udp_server in udp_servers:
                    a_udp_server.close()
                dns_resolver.close()

                for child in children:
                    os.waitpid(child, 0)
        else:
            logging.warn('worker is only available on Unix/Linux')
            run_server()
    else:
        run_server()


if __name__ == '__main__':
    main()
