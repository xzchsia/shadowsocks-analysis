#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
一个基于LRU的Key-Value缓存
'''

from __future__ import absolute_import, division, print_function, \
    with_statement

import collections
import logging
import time


# this LRUCache is optimized for concurrency, not QPS
# n: concurrency, keys stored in the cache
# m: visits not timed out, proportional to QPS * timeout
# get & set is O(1), not O(n). thus we can support very large n
# TODO: if timeout or QPS is too large, then this cache is not very efficient,
#       as sweep() causes long pause

# 维基百科的介绍：lru缓存算法
# Least Recently Used (LRU)
# Discards the least recently used items first. This algorithm requires keeping track of what was used when, 
# which is expensive if one wants to make sure the algorithm always discards the least recently used item.
# General implementations of this technique require keeping "age bits" for cache-lines and 
# track the "Least Recently Used" cache-line based on age-bits. In such an implementation, 
# every time a cache-line is used, the age of all other cache-lines changes. 

# 用到了容器基类：易变映射，能实现key-value任意查找
class LRUCache(collections.MutableMapping):
    """This class is not thread safe"""

    def __init__(self, timeout = 60, close_callback = None, *args, **kwargs):
        # sweep清扫 超时值
        self.timeout = timeout
        self.close_callback = close_callback
        # 存储字典store，核心字典。
        self._store = {}
        
        # 创建一个默认字典，其内每一个元素是一个列表。
        self._time_to_keys = collections.defaultdict(list)    # 该默认字典每一个元素是列表：访问时刻->key
        self._keys_to_last_time = {}    # key->上次访问时刻
        
        self._last_visits = collections.deque()    # 记录访问的时刻。deque:双端队列，能在首尾插入数据的列表
        self.update(dict(*args, **kwargs))    # use the free update to set keys

    # 返回store字典中最近使用的key对应的键值
    def __getitem__(self, key):
        # O(1)
        # 查找表的复杂度为O(1)
        t = time.time()
        self._keys_to_last_time[key] = t    # 更新key对应的此刻查询的时间
        self._time_to_keys[t].append(key)    # 记录这一时刻的key存入默认字典：元素名字为时间t,时间t为一个列表，存储时刻t访问的key
        # 根据时间去清理
        # 双端队列插入最近访问的时间
        # deque.append()是插入到右侧，appendleft()是插入到左侧
        # 相对的操作:pop()右侧，popleft()左侧
        self._last_visits.append(t)
        return self._store[key]

    # 修改store字典中的key->value
    def __setitem__(self, key, value):
        # O(1)
        t = time.time()
        self._keys_to_last_time[key] = t
        self._store[key] = value
        self._time_to_keys[t].append(key)
        self._last_visits.append(t)

    # 删除store字典中的key->value
    def __delitem__(self, key):
        # O(1)
        del self._store[key]
        del self._keys_to_last_time[key]

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)


# 先找访问时间_last_visits中超出timeout的所有键
# 然后去找_time_to_keys，找出所有可能过期的键
# 因为最早访问时间访问过的键之后可能又访问了，所以要看_keys_to_last_time
# 找出那些没被访问过的，然后删除

    def sweep(self):
        # O(m)
        now = time.time()
        # c为count，用于调试输出被清扫的key数量
        c = 0
        # 当存在访问记录才进行sweep
        while len(self._last_visits) > 0:
            # least：最早访问的时刻，在双向队列的最左侧。
            least = self._last_visits[0]
            # 最早访问的仍未超时，退出while
            if now - least <= self.timeout:
                break
            # close_callback是关闭回调函数吧？
            if self.close_callback is not None:
                # 把最早时刻least的对应的key拿出来
                for key in self._time_to_keys[least]:
                    # 如果key已经被存储
                    if key in self._store:
                        # 如果超时了
                        if now - self._keys_to_last_time[key] > self.timeout:
                            # 从store中取出key对应的value
                            value = self._store[key]
                            # 执行value对应的callback函数
                            self.close_callback(value)
            
            # 把最早时刻least的对应的key拿出来
            for key in self._time_to_keys[least]:
                # 从访问时刻队列中弹出，双向队列，左弹出的元素皆为最早访问的时间
                self._last_visits.popleft()
                # 如果key已经被存储
                if key in self._store:
                    # 如果超时了
                    if now - self._keys_to_last_time[key] > self.timeout:
                        # 删掉store中的key
                        del self._store[key]
                        # 删掉key对应最近的访问时间
                        del self._keys_to_last_time[key]
                        c += 1
            # 删掉least时刻对应的所有keys。
            # defaultdict的元素是列表。
            del self._time_to_keys[least]
        if c:
            logging.debug('%d keys swept' % c)

# 测试样例，使用断言
# 若断言不为真，抛出异常。
def test():
    c = LRUCache(timeout = 0.3)

    c['a'] = 1
    assert c['a'] == 1

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c

    c['a'] = 2
    c['b'] = 3
    time.sleep(0.2)
    c.sweep()
    assert c['a'] == 2
    assert c['b'] == 3

    time.sleep(0.2)
    c.sweep()
    c['b']
    time.sleep(0.2)
    c.sweep()
    assert 'a' not in c
    assert c['b'] == 3

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c
    assert 'b' not in c

if __name__ == '__main__':
    test()
