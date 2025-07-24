#!/usr/bin/env python
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import time
import hashlib
import random
import struct
import hmac
import base64
import string

__all__ = ['ciphers']

def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s

# HTTP头列表，用于随机选择
HTTP_HEADERS = [
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset: UTF-8,*;q=0.5',
    'Accept-Encoding: gzip,deflate,sdch',
    'Accept-Language: en-US,en;q=0.8,zh;q=0.6',
    'Connection: keep-alive',
    'Cookie: _ga=GA1.2.123456789.1234567890; _gid=GA1.2.123456789.1234567890',
    'Referer: https://www.bing.com/',
    'Cache-Control: max-age=0',
]

# 常见User-Agent列表，随机使用
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
]

# 常见的网站域名，用于伪装请求
COMMON_DOMAINS = [
    'apps.microsoft.com',
    'www.bing.com',
    'www.freesound.org',
    'www.amazon.com',
    'www.anthropic.com',
    'www.kenney.nl',
    'brackeysgames.itch.io',
    'www.linkedin.com',
    'www.reddit.com',
    'www.upf.edu',
]

# 常见的HTTP路径，用于伪装请求
COMMON_PATHS = [
    '/',
    '/index.html',
    '/news',
    '/article/latest',
    '/search?q=technology',
    '/login',
    '/about',
    '/contact',
    '/images/banner.jpg',
    '/css/style.css',
    '/js/main.js',
]

# 扩展的table加密表缓存
cached_tables = {}

# Python 2/3 兼容的 maketrans 和 translate 函数
if bytes == str:  # Python 2
    def maketrans(a, b):
        return bytes(bytearray(range(256)))
else:  # Python 3
    def maketrans(a, b):
        return bytes.maketrans(a, b)

def translate(s, t):
    return s.translate(t)
        
# 删除这两行代码
# 将兼容函数分配给变量
# maketrans = str_maketrans
# translate = str_translate

def get_extended_table(key):
    """生成扩展的table(增加0.5倍长度)"""
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    a, b = struct.unpack('<QQ', s)
    
    # 基础table大小为256
    base_size = 256
    # 扩展0.5倍，总大小为384
    extended_size = base_size + base_size // 2
    
    # 创建基础table
    table = maketrans(b'', b'')
    table = [table[i: i + 1] for i in range(len(table))]
    
    # 对基础table排序
    for i in range(1, 1024):
        table.sort(key=lambda x: int(a % (ord(x) + i)))
    
    # 扩展table：基于基础table生成额外的128个元素
    # 使用不同的哈希算法来增加随机性
    extra_table = []
    h = hashlib.sha256()
    h.update(key)
    h.update(s)  # 加入之前MD5的结果增加差异性
    extra_seed = h.digest()
    c, d = struct.unpack('<QQ', extra_seed[:16])
    
    # 生成额外的128个元素
    for i in range(base_size // 2):
        # 从base_table中选择两个字节，组合生成新的变换
        idx1 = (c + i) % base_size
        idx2 = (d + i) % base_size
        # 组合两个字节创建新的变换规则
        value = (ord(table[idx1]) + ord(table[idx2])) % 256
        extra_table.append(bytes([value]))
    
    # 合并基础table和扩展部分
    extended_table = table + extra_table
    
    return extended_table

def init_extended_table(key):
    """初始化加密解密表"""
    if key not in cached_tables:
        encrypt_table = b''.join(get_extended_table(key))
        
        # 为扩展表创建解密表
        base_table = encrypt_table[:256]  # 基础部分(0-255)
        extra_table = encrypt_table[256:] # 扩展部分(256-383)
        
        # 创建基础解密表
        base_decrypt = maketrans(base_table, maketrans(b'', b''))
        
        # 为扩展部分创建解密映射
        extended_decrypt = [0] * len(extra_table)
        for i, b in enumerate(extra_table):
            extended_decrypt[i] = base_decrypt[b]
        
        # 合并解密表
        decrypt_table = base_decrypt + bytes(extended_decrypt)
        
        cached_tables[key] = [encrypt_table, decrypt_table]
    
    return cached_tables[key]

def generate_http_request_header(data_len):
    """生成伪造的HTTP请求头"""
    domain = random.choice(COMMON_DOMAINS)
    path = random.choice(COMMON_PATHS)
    user_agent = random.choice(USER_AGENTS)
    
    # 生成随机的X-Request-ID
    request_id = ''.join(random.choice('0123456789abcdef') for _ in range(32))
    
    # 构建HTTP头
    headers = [
        f'GET {path} HTTP/1.1',
        f'Host: {domain}',
        f'User-Agent: {user_agent}',
        f'X-Request-ID: {request_id}'
    ]
    
    # 随机添加2-5个额外的HTTP头
    extra_headers_count = random.randint(2, 5)
    selected_headers = random.sample(HTTP_HEADERS, extra_headers_count)
    headers.extend(selected_headers)
    
    # 添加Content-Length
    headers.append(f'Content-Length: {data_len}')
    headers.append('')  # 空行，表示头部结束
    headers.append('')  # 为了生成双回车换行
    
    return '\r\n'.join(headers).encode('utf-8')

def generate_http_response_header(data_len):
    """生成伪造的HTTP响应头"""
    # 随机选择HTTP状态码，大多数是200
    status_codes = [200, 200, 200, 200, 200, 301, 302, 304, 307, 404]
    status = random.choice(status_codes)
    status_text = {
        200: 'OK',
        301: 'Moved Permanently',
        302: 'Found',
        304: 'Not Modified',
        307: 'Temporary Redirect',
        404: 'Not Found'
    }.get(status, 'OK')
    
    # 构建HTTP响应头
    headers = [
        f'HTTP/1.1 {status} {status_text}',
        f'Date: {time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}',
        'Server: nginx/1.18.0',
        'Content-Type: text/html; charset=utf-8',
        f'Content-Length: {data_len}',
        'Connection: keep-alive',
    ]
    
    # 随机添加缓存控制头
    if random.choice([True, False]):
        headers.append('Cache-Control: no-store, no-cache, must-revalidate')
    
    # 随机添加其他头
    if random.choice([True, False]):
        headers.append('X-Frame-Options: SAMEORIGIN')
    if random.choice([True, False]):
        headers.append('X-Content-Type-Options: nosniff')
    if random.choice([True, False]):
        headers.append('X-XSS-Protection: 1; mode=block')
    
    headers.append('')  # 空行，表示头部结束
    headers.append('')  # 为了生成双回车换行
    
    return '\r\n'.join(headers).encode('utf-8')

class ExtendedTableCipher(object):
    """扩展的Table加密算法"""
    def __init__(self, key, op):
        self._encrypt_table, self._decrypt_table = init_extended_table(key)
        self._op = op
        # 用于跟踪使用了哪些索引，以便解密时能够正确还原
        self._index_buffer = bytearray()
    
    def encrypt(self, data):
        return self.update(data)
    
    def decrypt(self, data):
        return self.update(data)
    
    def encrypt_once(self, data):
        return self.encrypt(data)
    
    def decrypt_once(self, data):
        return self.decrypt(data)
    
    def update(self, data):
        if not data:
            return b''
            
        data = to_bytes(data)
        
        if self._op:  # 加密
            # 为每个字节存储使用的是基础表还是扩展表
            result = bytearray()
            index_buffer = bytearray()
            
            for byte in data:
                # 固定使用基础表（0-255）而不是随机选择
                # 这样解密时才能正确还原
                if byte < 256:
                    result.append(ord(self._encrypt_table[byte:byte+1]))
                    index_buffer.append(0)  # 0表示使用基础表
                else:
                    # 超出范围的字节保持不变
                    result.append(byte)
                    index_buffer.append(255)  # 255表示未加密
            
            # 保存索引信息用于解密
            self._index_buffer = index_buffer
            return bytes(result)
        else:  # 解密
            result = bytearray()
            for byte in data:
                # 使用解密表进行解密
                if byte < 256:
                    result.append(ord(self._decrypt_table[byte:byte+1]))
                else:
                    # 超出范围的字节保持不变
                    result.append(byte)
            return bytes(result)

class HttpMixCrypto(object):
    """HTTP混淆加密"""
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        self._op = op  # 操作类型：加密/解密
        self._buffer = b''  # 用于存储未处理完的数据
        self._have_header = False  # 是否已添加HTTP头
        
        # 创建底层加密器，使用扩展的Table加密算法
        self._cipher = ExtendedTableCipher(key, op)
    
    def update(self, data):
        """处理数据"""
        if self._op == 1:  # 加密
            # 先用底层加密器加密数据
            encrypted_data = self._cipher.update(data)
            
            if not self._have_header:
                # 添加HTTP头
                is_request = random.choice([True, False])
                if is_request:
                    header = generate_http_request_header(len(encrypted_data))
                else:
                    header = generate_http_response_header(len(encrypted_data))
                
                self._have_header = True
                return header + encrypted_data
            else:
                return encrypted_data
        else:  # 解密
            # 将新数据添加到缓冲区
            self._buffer += data
            
            # 如果是第一次接收数据，需要移除HTTP头
            if not self._have_header and self._buffer:
                # 查找HTTP头结束的位置（双回车换行）
                pos = self._buffer.find(b'\r\n\r\n')
                if pos >= 0:
                    # 移除HTTP头
                    self._buffer = self._buffer[pos + 4:]
                    self._have_header = True
            
            # 解密缓冲区中的数据
            result = b''
            if self._buffer:
                result = self._cipher.update(self._buffer)
                self._buffer = b''
            
            return result
    
    def encrypt(self, data):
        """加密数据"""
        return self.update(data)
    
    def decrypt(self, data):
        """解密数据"""
        return self.update(data)
    
    def encrypt_once(self, data):
        """一次性加密，添加完整HTTP头和尾"""
        # 先用底层加密器加密数据
        encrypted_data = self._cipher.encrypt(data)
        
        # 随机决定是HTTP请求还是HTTP响应
        is_request = random.choice([True, False])
        if is_request:
            header = generate_http_request_header(len(encrypted_data))
        else:
            header = generate_http_response_header(len(encrypted_data))
        
        return header + encrypted_data
    
    def decrypt_once(self, data):
        """一次性解密，移除HTTP头和尾"""
        # 查找HTTP头结束位置
        pos = data.find(b'\r\n\r\n')
        if pos >= 0:
            # 移除HTTP头
            data = data[pos + 4:]
        
        # 使用底层解密器解密
        return self._cipher.decrypt(data)

def create_cipher(alg, key, iv, op, crypto_path=None,
                  key_as_bytes=0, d=None, salt=None,
                  i=1, padding=1):
    if alg == 'http_mix':
        return HttpMixCrypto(alg, key, iv, op, crypto_path)
    else:
        raise Exception('Unknown algorithm')

ciphers = {
    'http_mix': (16, 16, create_cipher),  # 密钥长度, IV长度, 创建函数
}

def test():
    key = b'k' * 16
    iv = b'i' * 16
    
    cipher = create_cipher('http_mix', key, iv, 1)
    decipher = create_cipher('http_mix', key, iv, 0)
    
    # 简单测试
    plain = b'Hello, World!'
    encrypted = cipher.encrypt_once(plain)
    decrypted = decipher.decrypt_once(encrypted)
    assert plain == decrypted, f"Test failed! {plain} != {decrypted}"
    print("Test passed!")

def print_test_vector():
    key = b'k' * 16
    iv = b'i' * 16
    cipher = create_cipher('http_mix', key, iv, 1)
    plain = b'Hello, World!'
    encrypted = cipher.encrypt_once(plain)
    print('Input:', plain)
    print('Key:', key)
    print('Expected encrypted (hex):', encrypted.hex())

if __name__ == '__main__':
    test()
    print_test_vector()