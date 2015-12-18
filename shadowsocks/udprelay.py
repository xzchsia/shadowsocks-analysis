#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
实现udp的转达，用于local端处理local和 客户器端的SOCKS5协议通信，用于local端和远程端Shadowsocks协议的通信；用于远程端与local端Shadowsocks协议的通信，用于远程端和dest端(destination)的通信
'''

# SOCKS5是基于UDP的，所以有这个UDPrelay，用来返回给browser的报文??
# sock5: RFC 1928
# SOCKS5用于browser和proxy协商用

# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+
# The fields in the UDP request header are:
#  o RSV Reserved X’0000’
#  o FRAG Current fragment number
#  o ATYP address type of following addresses:
#      o IP V4 address: X’01’
#      o DOMAINNAME: X’03’
#      o IP V6 address: X’04’
#  o DST.ADDR desired destination address
#  o DST.PORT desired destination port
#  o DATA user data

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks用于proxy和remote远程沟通用，所以要加密
# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import socket
import logging
import struct
import errno
import random

from shadowsocks import encrypt, eventloop, lru_cache, common
from shadowsocks.common import parse_header, pack_addr


BUF_SIZE = 65536


def client_key(a, b, c, d):
    return '%s:%s:%s:%s' % (a, b, c, d)

# 我是先读tcprelay.py然后读udprelay.py，可以参考tcprelay的注释
# udp比tcp协议更精简。毕竟是不可靠的报文
class UDPRelay(object):
    def __init__(self, config, dns_resolver, is_local):
        self._config = config
        # 本地和远程采用同一份config文件，所以要区分
        if is_local:
            self._listen_addr = config['local_address']
            self._listen_port = config['local_port']
            self._remote_addr = config['server']
            self._remote_port = config['server_port']
        else:
            self._listen_addr = config['server']
            self._listen_port = config['server_port']
            self._remote_addr = None
            self._remote_port = None
        self._dns_resolver = dns_resolver
        self._password = config['password']
        self._method = config['method']
        self._timeout = config['timeout']
        self._is_local = is_local
        # 这个字典是lrucache，存放callback。
        self._cache = lru_cache.LRUCache(timeout = config['timeout'],
                                         close_callback = self._close_client)
        self._client_fd_to_server_addr = \
            lru_cache.LRUCache(timeout = config['timeout'])
        self._eventloop = None
        self._closed = False
        self._last_time = time.time()
        # set集合，用于存放fielno()，见_handle_server()方法
        self._sockets = set()

        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" % 
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)

        # server_socket是自己的socket
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        self._server_socket = server_socket

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if type(server_port) == list:
            server_port = random.choice(server_port)
        logging.debug('chosen server: %s:%d', server, server_port)
        # TODO support multiple server IP
        return server, server_port

    def _close_client(self, client):
        if hasattr(client, 'close'):
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            client.close()
        else:
            # just an address
            pass

    # 作为server的处理函数，包括【本地端收到进程的udp】和【服务端收到本地端发送的加密udp】
    # 对于local，得到的是本地监听1080的数据，要加密后向服务端发
    # 对于服务端，得到的是本地发送的已加密数据，解密后向dest直接发送
    def _handle_server(self):
        server = self._server_socket
        # r_addr是发送者的地址
        data, r_addr = server.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_server: data is empty')
            
        # 若本地端从监听1080端口收到本机应用进程（例如chrome）的数据，进行切除header
        if self._is_local:
            # ord:输入char返回Ascii
            frag = common.ord(data[2])
            # this is no classic UDP
            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +----+------+------+----------+----------+----------+
            # | 2  |  1   |  1   | Variable |    2     | Variable |
            # +----+------+------+----------+----------+----------+
            if frag != 0:
                logging.warn('drop a message since frag is not 0')
                return
            else:
                data = data[3:]
                # [3:]之后变成
                # +------+----------+----------+----------+
                # | ATYP | DST.ADDR | DST.PORT |   DATA   |
                # +------+----------+----------+----------+
                # |  1   | Variable |    2     | Variable |
                # +------+----------+----------+----------+
                # 就是shadowsocks那段
                
        # 如果是服务端收到本地端发出的udp数据，先进行解密
        else:
            data = encrypt.encrypt_all(self._password, self._method, 0, data)            
            if not data:
                logging.debug('UDP handle_server: data is empty after decrypt')
                return
        # 处理header
        header_result = parse_header(data)
        if header_result is None:
            return
        addrtype, dest_addr, dest_port, header_length = header_result

        if self._is_local:
            # 如果是local收到，则server_addr server_port都是远程的
            server_addr, server_port = self._get_a_server()
        else:
            # 如果远程收到，则将server_addr这些改成dest_addr dest_port，方便操作
            # dest就是最终目标，例如 www.youtube.com:443
            server_addr, server_port = dest_addr, dest_port
        # r_addr[]是接收到的数据
        key = client_key(r_addr[0], r_addr[1], dest_addr, dest_port)
        client = self._cache.get(key, None)
        # 若callback字典中没有相关记录，进行注册字典
        if not client:
            # TODO async getaddrinfo
            # 根据server_addr, server_port等的类型决定选用的协议类型
            # Translate the host/port argument into a sequence of 5-tuples
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if addrs:
                af, socktype, proto, canonname, sa = addrs[0]
                # 根据上面的server_addr, server_port建立相应的连接，一环扣一环
                # 这里是主动发出请求，所以要新建一个socket
                # 这里根据上面得到的不同的端口类型就新建不同类型的socket：用于tcp的和同于udp的
                client = socket.socket(af, socktype, proto)
                client.setblocking(False)
                self._cache[key] = client
                self._client_fd_to_server_addr[client.fileno()] = r_addr
            else:
                # drop
                return
            # sockets是一个set集合
            self._sockets.add(client.fileno())
            # 添加进Eventloop，标志设置为可读
            self._eventloop.add(client, eventloop.POLL_IN)
        
        # 如果是local，要向远程发，要过墙，所以要加密
        if self._is_local:
            data = encrypt.encrypt_all(self._password, self._method, 1, data)
            if not data:
                return
        # 如果是远程，要向dest发请求，所以把除数据的部分除去，即除去header。
        else:
            # data已经在上面进行数据解密了。不需要像local一样加密发送。
            # data已经被切除头的3个字节了
            data = data[header_length:]

        if not data:
            return
        
        try:
            # 发送，完美无瑕。。。。
            # 这个sendto同时有udp的和tcp的两种，sendto函数主要用于UDP，但这里两种都用了
            # 调用sendto时候会自动加上那个首3个字节，貌似是x00 x00 x00
            client.sendto(data, (server_addr, server_port))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                logging.error(e)

    # 作为local的处理函数，包括【服务端收到dest（例如youtube）发送的udp】和【本地端收到服务端发来的加密udp】
    # 对于local，得到的是远程的相应，要往客户端发
    # 对于远程，得到的是dest的响应，要往local发
    def _handle_client(self, sock):
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return
        # 如果是服务端接收到的udp，（例如来自youtube）
        if not self._is_local:
            addrlen = len(r_addr[0])
            # 域名规范：域名不能超过255个字符。其中顶级域名不能超过63字符
            if addrlen > 255:
                # drop
                return
            # pack_addr(r_addr[0])：把r_addr[0]打包成shadowvpn的专用的地址header，追加到r_addr[0]头部。
            # struct.pack('>H', r_addr[1])：打包成Big-Endian格式
            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data
            # 加密
            response = encrypt.encrypt_all(self._password, self._method, 1,
                                           data)
            if not response:
                return
            
        # 本地端收到服务端发来的加密udp
        else:
            # 解密
            data = encrypt.encrypt_all(self._password, self._method, 0,
                                       data)
            if not data:
                return
            header_result = parse_header(data)
            if header_result is None:
                return
            # addrtype, dest_addr, dest_port, header_length = header_result
            # 还原为标准的udp数据报格式，加上首3个字节
            response = b'\x00\x00\x00' + data
            # data: raw data
            # +------+----------+----------+----------+
            # | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +------+----------+----------+----------+
            # |  1   | Variable |    2     | Variable |
            # +------+----------+----------+----------+
            # response: true udp packet
            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +----+------+------+----------+----------+----------+
            # | 2  |  1   |  1   | Variable |    2     | Variable |
            # +----+------+------+----------+----------+----------+

        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        if client_addr:
            # 同样的，完美无瑕。。
            self._server_socket.sendto(response, client_addr)
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    # 下面的添加到Eventloop跟tcprelay.py中的是大致相同的，少了某些可靠性的函数，符合udp传输的特性。
    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        loop.add_handler(self._handle_events)

        server_socket = self._server_socket
        self._eventloop.add(server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR)

    def _handle_events(self, events):
        for sock, fd, event in events:
            if sock == self._server_socket:
                if event & eventloop.POLL_ERR:
                    logging.error('UDP server_socket err')
                # 处理来自server的udp消息
                self._handle_server()
            # shadowsocks可以给很多人用，所以可以有很多client socket
            elif sock and (fd in self._sockets):
                if event & eventloop.POLL_ERR:
                    logging.error('UDP client_socket err')
                # 处理来自client的udp请求
                self._handle_client(sock)

        now = time.time()
        # 超时 清理socket。
        if now - self._last_time > 3:
            self._cache.sweep()
            self._client_fd_to_server_addr.sweep()
            self._last_time = now
        if self._closed:
            self._server_socket.close()
            for sock in self._sockets:
                sock.close()
            self._eventloop.remove_handler(self._handle_events)

    def close(self, next_tick = False):
        self._closed = True
        if not next_tick:
            self._server_socket.close()
