#!/usr/bin/env python

'''
处理Shadowsocks协议的加密解密
'''

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging

from shadowsocks.crypto import m2, rc4_md5, salsa20_ctr, \
    ctypes_openssl, ctypes_libsodium, table

# 支持加密方式，以字典方式存储
method_supported = {}
method_supported.update(rc4_md5.ciphers)
method_supported.update(salsa20_ctr.ciphers)
method_supported.update(ctypes_openssl.ciphers)
method_supported.update(ctypes_libsodium.ciphers)
# let M2Crypto override ctypes_openssl
method_supported.update(m2.ciphers)
method_supported.update(table.ciphers)

# 返回一个长度为length随机字符串，用于生成随机iv
def random_string(length):
    try:
        import M2Crypto.Rand
        return M2Crypto.Rand.rand_bytes(length)
    except ImportError:
        return os.urandom(length)

# 缓存的pass-key-iv字典
cached_keys = {}

# 这个函数下文没有用到
def try_cipher(key, method = None):
    Encryptor(key, method)

# 返回一个(key,iv)，先从cache中查找是否有key，没有的话生成一个并放入cache
def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    # OpenSSL中的EVP_BytesToKey()方法是等价的。所以使得key和iv的长度和nodejs版本一致
    if hasattr(password, 'encode'):
        password = password.encode('utf-8')
    # 生成一个名字，用作存储字典的关键词。便于索引
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    # 缓存中存在key，直接return
    if r:
        return r
    
    m = []
    i = 0
    # 多次join md5使得m变长
    while len(b''.join(m)) < (key_len + iv_len):
        # md5使用例程：http://blog.csdn.net/tys1986blueboy/article/details/7229199
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    # Deep copy m
    ms = b''.join(m)
    # 截取
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    # 缓存key，cached_key在上面已经生成。
    # 字典的key为cached_key，对应的value是tuple：(key,iv)
    cached_keys[cached_key] = (key, iv)
    return key, iv


class Encryptor(object):
    def __init__(self, key, method):
        self.key = key
        self.method = method
        self.iv = None
        self.iv_sent = False
        self.cipher_iv = b''
        self.decipher = None
        method = method.lower()    # 变小写
        
        self._method_info = self.get_method_info(method)    # 加密方式
        if self._method_info:
            self.cipher = self.get_cipher(key, method, 1,
                                          random_string(self._method_info[1]))
        else:
            logging.error('method %s not supported' % method)
            sys.exit(1)

    def get_method_info(self, method):
        method = method.lower()
        # 字典
        m = method_supported.get(method)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    # 参数op有什么用途：判断加密解密
    # 返回值：对应加密方式的初始化函数
    def get_cipher(self, password, method, op, iv):
        if hasattr(password, 'encode'):
            password = password.encode('utf-8')
        # m指向一种加密方式，是tuple。
        # 举例：m=rc4-md5时候， m = (16, 16, create_cipher)
        m = self._method_info
        # 若key_length > 0：
        if m[0] > 0:
            # 实际上iv_这个变量是炮灰，没用到。毕竟iv是自己生成的
            key, iv_ = EVP_BytesToKey(password, m[0], m[1])    # m[0]是key-len m[1]是iv-len
        else:
            # key_length == 0 indicates we should use the key directly
            key, iv = password, b''
        # 截取iv长度
        iv = iv[:m[1]]
        # TODO: 这是什么意思
        if op == 1:
            # 这是获取加密专用的iv，不能用于解密
            # this iv is for cipher not decipher
            self.cipher_iv = iv[:m[1]]
        # m[2]指向一个函数create_cipher()，其函数定义在各自独立的加密方式的py源码中
        return m[2](method, key, iv, op)

    # 返回加密后二进制流，包含明文iv+密文data
    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.iv_sent:
            return self.cipher.update(buf)
        else:
            self.iv_sent = True
            return self.cipher_iv + self.cipher.update(buf)
    
    # 返回解密后的数据，不含iv
    def decrypt(self, buf):
        if len(buf) == 0:
            return buf
        # 若解密器尚未创建，新建一个解密器
        if self.decipher is None:
            decipher_iv_len = self._method_info[1]
            # 从buf首部截取iv明文
            decipher_iv = buf[:decipher_iv_len]
            self.decipher = self.get_cipher(self.key, self.method, 0,
                                            iv = decipher_iv)
            buf = buf[decipher_iv_len:]
            if len(buf) == 0:
                return buf
        return self.decipher.update(buf)

# 加密解密同在一个函数
# 使用随机IV进行加密，使用接收到的iv进行解密
# 返回明文或者密文，首部不含iv
def encrypt_all(password, method, op, data):    # 0解码，1加密
    result = []
    method = method.lower()
    # m是create_cipher函数
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    if op:
        # 生产随机iv，供下一步加密
        iv = random_string(iv_len)
        result.append(iv)
    else:
        # 从数据包取出iv，供下一步解密
        iv = data[:iv_len]
        data = data[iv_len:]
        
    # 创建一个加密（解密）器
    cipher = m(method, key, iv, op)
    # 获得加密（解密）结果
    result.append(cipher.update(data))
    return b''.join(result)


CIPHERS_TO_TEST = [
    b'aes-128-cfb',
    b'aes-256-cfb',
    b'rc4-md5',
    b'salsa20',
    b'chacha20',
    b'table',
]


def test_encryptor():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        encryptor = Encryptor(b'key', method)
        decryptor = Encryptor(b'key', method)
        cipher = encryptor.encrypt(plain)
        plain2 = decryptor.decrypt(cipher)
        assert plain == plain2


def test_encrypt_all():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        cipher = encrypt_all(b'key', method, 1, plain)
        plain2 = encrypt_all(b'key', method, 0, cipher)
        assert plain == plain2


if __name__ == '__main__':
    test_encrypt_all()
    test_encryptor()
