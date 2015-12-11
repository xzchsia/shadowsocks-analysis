#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
事件循环，在对应不同的操作系统使用select、poll、epoll、kequeue实现IO复用，
将三种底层实现包装成一个类Eventloop
'''

# from ssloop
# https://github.com/clowwindy/ssloop

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import select
import errno
import logging
from collections import defaultdict

# 供外部文件导入本package的全部名字
__all__ = ['EventLoop', 'POLL_NULL', 'POLL_IN', 'POLL_OUT', 'POLL_ERR',
           'POLL_HUP', 'POLL_NVAL', 'EVENT_NAMES']

POLL_NULL = 0x00    # NULL无效
POLL_IN = 0x01    # 有数据可读
POLL_OUT = 0x04    # 写数据不会导致阻塞
POLL_ERR = 0x08    # 指定的文件描述符发生错误
POLL_HUP = 0x10    # 指定的文件描述符挂起事件
POLL_NVAL = 0x20    # 指定的文件描述符非法


EVENT_NAMES = {
    POLL_NULL: 'POLL_NULL',
    POLL_IN: 'POLL_IN',
    POLL_OUT: 'POLL_OUT',
    POLL_ERR: 'POLL_ERR',
    POLL_HUP: 'POLL_HUP',
    POLL_NVAL: 'POLL_NVAL',
}

# 作者每一个类都有定义如下方法：然后封装成一个大类Eventloop
# 初始化函数
# 返回FD
# 添加，删除，修改FD


# fd是：socket描述符
class EpollLoop(object):
    # 创建一个epoll实例
    def __init__(self):
        self._epoll = select.epoll()
    # 等待poll，超时
    def poll(self, timeout):
        return self._epoll.poll(timeout)
    # 注册一个描述符
    def add_fd(self, fd, mode):
        self._epoll.register(fd, mode)
    # 注销一个描述符
    def remove_fd(self, fd):
        self._epoll.unregister(fd)
    # 更改描述符的特性（读、写等）
    def modify_fd(self, fd, mode):
        self._epoll.modify(fd, mode)

# kqueue是FreeBSD系统下的用法，linux下没有
class KqueueLoop(object):

    MAX_EVENTS = 1024
    # 创建一个kqueue实例
    def __init__(self):
        self._kqueue = select.kqueue()
        self._fds = {}
    
    def _control(self, fd, mode, flags):
        events = []
        # 和这种比较用&
        if mode & POLL_IN:
            events.append(select.kevent(fd, select.KQ_FILTER_READ, flags))
        if mode & POLL_OUT:
            events.append(select.kevent(fd, select.KQ_FILTER_WRITE, flags))
        # 加到kqueue里面去
        for e in events:
            self._kqueue.control([e], 0)

    def poll(self, timeout):
        if timeout < 0:
            timeout = None    # kqueue behaviour
        events = self._kqueue.control(None, KqueueLoop.MAX_EVENTS, timeout)
        # 只可以加类型，所以用一个lambda打包成一个类型
        results = defaultdict(lambda: POLL_NULL)
        for e in events:
            # e是kevent
            fd = e.ident
            if e.filter == select.KQ_FILTER_READ:
                results[fd] |= POLL_IN
            elif e.filter == select.KQ_FILTER_WRITE:
                results[fd] |= POLL_OUT
        # 最终返回某个fd是不是有POLL_IN/POLL_OUT，默认是POLL_NULL
        return results.items()

    def add_fd(self, fd, mode):
        self._fds[fd] = mode
        self._control(fd, mode, select.KQ_EV_ADD)

    def remove_fd(self, fd):
        self._control(fd, self._fds[fd], select.KQ_EV_DELETE)
        del self._fds[fd]

    def modify_fd(self, fd, mode):
        self.remove_fd(fd)
        self.add_fd(fd, mode)

# 自己定义的set的封装，多路复用的类
class SelectLoop(object):

    def __init__(self):
        self._r_list = set()
        self._w_list = set()
        self._x_list = set()

    # 返回poll，对应
    def poll(self, timeout):
        r, w, x = select.select(self._r_list, self._w_list, self._x_list,
                                timeout)
        # 创建一个标准字典 defaultdict() ，默认键值是:POLL_NULL空。
        # 参考http://www.cnblogs.com/huangcong/archive/2012/12/13/2815606.html
        results = defaultdict(lambda: POLL_NULL)
        for p in [(r, POLL_IN), (w, POLL_OUT), (x, POLL_ERR)]:
            for fd in p[0]:
                results[fd] |= p[1]
        return results.items()

    def add_fd(self, fd, mode):
        if mode & POLL_IN:
            self._r_list.add(fd)
        if mode & POLL_OUT:
            self._w_list.add(fd)
        if mode & POLL_ERR:
            self._x_list.add(fd)

    def remove_fd(self, fd):
        if fd in self._r_list:
            self._r_list.remove(fd)
        if fd in self._w_list:
            self._w_list.remove(fd)
        if fd in self._x_list:
            self._x_list.remove(fd)

    def modify_fd(self, fd, mode):
        self.remove_fd(fd)
        self.add_fd(fd, mode)

# 一个EventLoop包装了所有系统下的IO复用方法
# 需要判断当前select包的属性hasattr()，也就是判断当前系统是win\linux\bsd
class EventLoop(object):
    def __init__(self):
        # 这里的迭代器是什么意思？
        self._iterating = False
        if hasattr(select, 'epoll'):
            self._impl = EpollLoop()
            model = 'epoll'
        elif hasattr(select, 'kqueue'):
            self._impl = KqueueLoop()
            model = 'kqueue'
        elif hasattr(select, 'select'):
            self._impl = SelectLoop()
            model = 'select'
        else:
            raise Exception('can not find any available functions in select '
                            'package')
        # 类的成员
        self._fd_to_f = {}    # 用于操作的描述符
        self._handlers = []    # 服务函数，_handlers列表里面存放handler函数。
        self._ref_handlers = []    # ref句柄？
        self._handlers_to_remove = []    # 待删除的句柄
        logging.debug('using event model: %s', model)

    # poll() waits for one of a set of file descriptors to become ready to perform I/O.
    # Reference:' man poll ' on linux
    def poll(self, timeout = None):
        events = self._impl.poll(timeout)
        return [(self._fd_to_f[fd], fd, event) for fd, event in events]

    # 将select/kqueue/epoll的接口统一起来
    # 添加FD
    def add(self, f, mode):
        fd = f.fileno()
        self._fd_to_f[fd] = f
        self._impl.add_fd(fd, mode)

    # 移除FD
    def remove(self, f):
        fd = f.fileno()
        del self._fd_to_f[fd]
        # self._impl loop的是fd，发信息靠socket
        self._impl.remove_fd(fd)

    # 修改FD的状态
    def modify(self, f, mode):
        fd = f.fileno()
        self._impl.modify_fd(fd, mode)

    # 添加服务函数
    def add_handler(self, handler, ref = True):
        self._handlers.append(handler)
        if ref:
            # when all ref handlers are removed, loop stops
            self._ref_handlers.append(handler)

    # 移除服务函数
    def remove_handler(self, handler):
        if handler in self._ref_handlers:
            self._ref_handlers.remove(handler)
        if self._iterating:    # 这里的迭代器是什么意思
            self._handlers_to_remove.append(handler)
        else:
            self._handlers.remove(handler)

    def run(self):
        # events从poll()获得所有事件
        events = []
        while self._ref_handlers:
            try:
                # 统一之后的启动，timeout为1
                events = self.poll(1)
            
            except (OSError, IOError) as e:
            # EPIPE: Happens when the client closes the connection客户端断开连接
            # EINTR: Happens when received a signal收到（中断）信号
            # handles them as soon as possible尽快处理
                if errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    logging.debug('poll:%s', e)
                else:
                    logging.error('poll:%s', e)
                    # 代码review常遇到的是没有异常日志分析，乱七八糟的，因此引入堆栈追踪
                    # 用于处理异常栈：traceback模块，实际上不用写，系统自动加入异常追踪，但是不会继续执行下去
                    import traceback
                    traceback.print_exc()
                    continue
            # 谁来告诉我这个迭代是什么意思。
            self._iterating = True
            for handler in self._handlers:
                # TODO when there are a lot of handlers
                try:
                    # 调用所有handler去处理所有events
                    handler(events)
                except (OSError, IOError) as e:
                    logging.error(e)
                    import traceback
                    traceback.print_exc()
            for handler in self._handlers_to_remove:
                # 可以直接从列表里面remove
                self._handlers.remove(handler)
                # 为啥不把移除命令放在for循环外面？答：作者在2.6.3中修改了，放在循环体外
                self._handlers_to_remove = []
            self._iterating = False


# from tornado
# 从tornado库引用的。
def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None

# from tornado
def get_sock_error(sock):
    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return socket.error(error_number, os.strerror(error_number))
