#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
一些公用的函数，涉及底层的header打包，地址判断，比较全面
'''

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import struct
import logging

# 输入一个char，返回ascii值
def compat_ord(s):
    if type(s) == int:
        return s
    return _ord(s)

# 输入一个数字，返回对应的char符号
def compat_chr(d):
    if bytes == str:
        return _chr(d)
    return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord    # 输入char返回ascii
chr = compat_chr    # 输入ascii返回char

# 字符串在Python内部的表示是unicode编码，因此，在做编码转换时，通常需要以unicode作为中间编码
# 即先将其他编码的字符串解码（decode）成unicode，再从unicode编码（encode）成另一种编码。

# encode的作用是将unicode编码转换成其他编码的字符串
def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s

# decode的作用是将其他编码的字符串转换成unicode编码
def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s

# 将网络地址转成二进制(v4 + v6)，而且返回的是utf-8格式的
def inet_ntop(family, ipstr):
    # ipv4
    if family == socket.AF_INET:
        # inet_aton()将一个字符串IP地址转换为一个32位的网络序列IP地址
        return to_bytes(socket.inet_ntoa(ipstr))
    # ipv6
    elif family == socket.AF_INET6:
        import re
        # zip函数返回一个tuple
        # %02X 宽度2的十六进制格式化
        # lstrip()函数是移除前导字符，例如'0'
        # ipstr[::2]表示从第一个字母开始，读取每2个字符，返回字符串分隔
        v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j))).lstrip('0')
                          for i, j in zip(ipstr[::2], ipstr[1::2]))
        # re.sub()是替换函数，只替换一次：count=1
        v6addr = re.sub('::+', '::', v6addr, count = 1)
        return to_bytes(v6addr)

# 将二进制转成网络地址(v4 + v6)
def inet_pton(family, addr):
    addr = to_str(addr)
    if family == socket.AF_INET:
        # 将ipv4二进制返回成网络地址。
        return socket.inet_aton(addr)
    elif family == socket.AF_INET6:
        if '.' in addr:    # a v4 addr
            # rindex()是查找字符串中的位置。
            v4addr = addr[addr.rindex(':') + 1:]
            v4addr = socket.inet_aton(v4addr)
            # map() return a list
            v4addr = map(lambda x: ('%02X' % ord(x)), v4addr)
            v4addr.insert(2, ':')
            newaddr = addr[:addr.rindex(':') + 1] + ''.join(v4addr)
            return inet_pton(family, newaddr)
        # 等价于[0,0,0,0,0,0,0,0]
        dbyts = [0] * 8    # 8 groups
        grps = addr.split(':')
        # 以下函数是功能忽略v6地址中的00:00之类的零
        # enumerate是返回一个迭代器，返回一个index和value of index
        for i, v in enumerate(grps):
            if v:
                dbyts[i] = int(v, 16)
            else:
                # grps[::-1]是字符串的反序
                for j, w in enumerate(grps[::-1]):
                    if w:
                        dbyts[7 - j] = int(w, 16)
                    else:
                        break
                break
        # 取出dbtys的每个元素的低8位，int是32位的
        return b''.join((chr(i // 256) + chr(i % 256)) for i in dbyts)
    else:
        raise RuntimeError("What family?")

# 这个patch是干嘛的/
def patch_socket():
    if not hasattr(socket, 'inet_pton'):
        socket.inet_pton = inet_pton

    if not hasattr(socket, 'inet_ntop'):
        socket.inet_ntop = inet_ntop


patch_socket()


ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3


def pack_addr(address):
    address_str = to_str(address)
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            # inet_pton：将“点分十进制” －> “二进制整数”
            r = socket.inet_pton(family, address_str)
            if family == socket.AF_INET6:
                # 把 ADDRTYPE_IPV6 = 4 封包到数据首部
                return b'\x04' + r
            else:
                # 把 ADDRTYPE_IPV4 = 1 封包到数据首部
                return b'\x01' + r
        except (TypeError, ValueError, OSError, IOError):
            pass
    if len(address) > 255:
        address = address[:255]    # TODO：地址超长的
    # 把 ADDRTYPE_HOST = 3 封包到数据首部
    return b'\x03' + chr(len(address)) + address

# 传递header，判断三种模式：ipv4 ipv6 地址模式
# 返回四个值：地址类型，地址，端口，header长度
def parse_header(data):
    # 返回ascii值
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == ADDRTYPE_IPV4:
        if len(data) >= 7:
            # ntoa: convert 32-bit packed binary format to string format
            dest_addr = socket.inet_ntoa(data[1:5])
            # 把端口数据打包为大端的c结构体
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 2 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 + 
                                          addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_IPV6:
        if len(data) >= 19:
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            dest_port = struct.unpack('>H', data[17:19])[0]
            header_length = 19
        else:
            logging.warn('header is too short')
    else:
        # 密码错误？
        logging.warn('unsupported addrtype %d, maybe wrong password' % 
                     addrtype)
    if dest_addr is None:
        return None
    return addrtype, to_bytes(dest_addr), dest_port, header_length


def test_inet_conv():
    ipv4 = b'8.8.4.4'
    b = inet_pton(socket.AF_INET, ipv4)
    assert inet_ntop(socket.AF_INET, b) == ipv4
    ipv6 = b'2404:6800:4005:805::1011'
    b = inet_pton(socket.AF_INET6, ipv6)
    assert inet_ntop(socket.AF_INET6, b) == ipv6


def test_parse_header():
    assert parse_header(b'\x03\x0ewww.google.com\x00\x50') == \
        (3, b'www.google.com', 80, 18)
    assert parse_header(b'\x01\x08\x08\x08\x08\x00\x35') == \
        (1, b'8.8.8.8', 53, 7)
    assert parse_header((b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00'
                         b'\x00\x10\x11\x00\x50')) == \
        (4, b'2404:6800:4005:805::1011', 80, 19)


def test_pack_header():
    assert pack_addr(b'8.8.8.8') == b'\x01\x08\x08\x08\x08'
    assert pack_addr(b'2404:6800:4005:805::1011') == \
        b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00\x00\x10\x11'
    assert pack_addr(b'www.google.com') == b'\x03\x0ewww.google.com'

# 用于测试目的
if __name__ == '__main__':
    test_inet_conv()
    test_parse_header()
    test_pack_header()
