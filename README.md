## shadowsocks 2.6 源码分析

研究目的：阅读旧版本(2014.12)源码，体验基本的网络编程思想，学习通信协议

[![Join the chat at https://gitter.im/lao605/shadowsocks_analysis](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/lao605/shadowsocks_analysis?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)  <= 点击加入讨论组

仅用作学术交流用途，其他行为带来的后果本人概不负责

* * *

|Shadowsocks作者|源码注释项目作者|原注释项目地址|
|---|---|----|
|[@clowwindy](https://github.com/clowwindy)|[@lao605](https://github.com/lao605)|[shadowsocks-analysis](https://github.com/lao605/shadowsocks_analysis)|

由[@lixingcong](https://github.com/lixingcong)进行代码注释完善。Finished in December, 2015

* * *

### 项目结构

以下内容，绝大部分摘自[@lao605](https://github.com/lao605)项目README页面。

#### 感想
代码质量相当的高，感觉都能达到重用的级别。
作者设计的思想是，一个配置文件，一段程序，在本地和远程通用。

可读性非常强。我是python初学者，今年10月份才到图书馆借书学py，没想到在12月中旬就能读懂这个shadowsocks的代码了，作者的代码风格，命名规范，异常的捕捉思路都是非常厉害的。这些都给我学习python提供了很大帮助，再次感谢clowwindy为我们提供这么好的一个工具。

#### 按文件名

|文件名|功能|备注|
|-----|---|----|
|asyncdns.py|异步处理dns请求|提供远端dns查询|
|common.py|工具函数|进行header和addr数据包处理|
|utils.py|工具函数|实现config配置检查|
|daemon.py|linux守护进程||
|encrypt.py|加密解密|简单易懂，不涉及到底层算法，封装很好|
|eventloop.py|事件循环|实现IO复用，封装成类Eventloop，多平台|
|local.py|客户端|在本地运行的程序|
|server.py|服务端|在远程运行的程序,支持多用户|
|lru_cache.py|缓存|基于LRU的Key-Value字典|
|tcprelay.py|tcp的转达|用在远程端中使远程和dest连接|
|udprelay.py|udp的转达|用于local端处理local和客户端的socks5协议通信，用于local端和远程端shadowsocks协议的通信；用于远程端与local端shadowsocks协议的通信，用于远程端和dest端的通信,local <=> client <=> server <=> dest|

* * *


### eventloop.py

事件循环类

    使用select、epoll、kqueue等IO复用实现异步处理。
    优先级为epoll\>kqueue\>select
    Eventloop将三种复用机制的add，remove，poll，add_handler，remve_handler接口统一
    程序员只需要使用这些函数即可，不需要处理底层细节。
    当eventloop监测到socket的数据，程序就将所有监测到的socket和事件交给所有handler去处理
    每个handler通过socket和事件判断自己是否要处理该事件，并进行相对的处理：

### udprelay.py / tcprelay.py / asyndns.py

数据包的转发处理

    三个文件分别实现用来处理udp的请求，tcp的请求，dns的查询请求
    将三种请求的处理包装成handler。
    对于tcp，udp的handler，它们bind到特定的端口，并且将socket交给eventloop，并且将自己的处理函数加到eventloop的handlers
    对于dns的handler，它接受来自udp handler和tcp handler的dns查询请求，并且向远程dns服务器发出udp请求
	协议解析和构建用的struct.pack()和struct.unpack()

#### lru_cache.py

实现缓存，英文:Least Recently Used Cache

    先找访问时间_last_visits中超出timeout的所有键
    然后去找_time_to_keys，找出所有可能过期的键
    因为最早访问时间访问过的键之后可能又访问了，所以要_keys_to_last_time
    找出那些没被访问过的，然后删除


##### 当local收到udprelay handler绑定的端口的事件，说明客户端发来请求，local对SOCKS5协议的内容进行处理之后经过加密转发给远程；

<pre>
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+
</pre>

trim-\>
<pre>
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+
</pre>

-\>encrypt
<pre>
+-------+--------------+
|   IV  |    PAYLOAD   |
+-------+--------------+
| Fixed |   Variable   |
+-------+--------------+
</pre>


##### 当local新建的socket收到连接请求时，说明远程向local发送结果，此时对信息进行解密，并且对shadowsocks协议进行适当加工，发回给客户端

<pre>
+-------+--------------+
|   IV  |    PAYLOAD   |
+-------+--------------+
| Fixed |   Variable   |
+-------+--------------+
</pre>

-\>decrypt

<pre>
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+
</pre>

-\>add

<pre>
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+
</pre>

##### 当远程端收到udp handler绑定的端口的事件，说明local端发来请求，远程端对信息进行解密并根据dest服务器/端口的协议类型对其发出tcp连接或者udp连接；

<pre>
+-------+--------------+
|   IV  |    PAYLOAD   |
+-------+--------------+
| Fixed |   Variable   |
+-------+--------------+
</pre>

-\>decrypt

<pre>
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+
</pre>

-\>trim

<pre>
+----------+
|   DATA   |
+----------+
| Variable |
+----------+
</pre>

-\>getaddrinfo-\>tcp/udp
-\>send to dest server via tcp/udp 


##### 当远程新建的socket收到连接请求时，说明dest服务器向远程端发出响应，远程端对其进行加密，并且转发给local端

<pre>
+----------+
|   DATA   |
+----------+
| Variable |
+----------+
</pre>

-\>add

<pre>
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+
</pre>

-\>encrypt

<pre>
+-------+--------------+
|   IV  |    PAYLOAD   |
+-------+--------------+
| Fixed |   Variable   |
+-------+--------------+
</pre>

-\>send to local

在handler函数里面的基本逻辑就是：
<pre>
if sock == self._server_socket:
self._handle_server()
elif sock and (fd in self._sockets):
self._handle_client(sock)
</pre>

协议解析和构建用的struct.pack()和struct.unpack()

===============================================================
##### asyndns.py实现的是一个DNS服务器，封装得相当的好
1.1、读取/etc/hosts和/etc/resolv.conf文件，如果没有设置，就设置dns服务器为8.8.8.8和8.8.4.4
1.2、收到tcp handler和udp handler的dns请求之后，建立socket并且向远程服务器发送请求，并把（hostname：callback）加入_hostname_to_cb
1.3、收到响应之后触发callback _hostname_to_cb[hostname](#)

###### 作者全程用二进制构建dns报文，非常值得学习

<pre>
# 请求
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
</pre>

响应：
<pre>
                                 1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
</pre>

===============================================================
##### lru_cache.py实现的是一个缓存

<pre>
self._store = 
self._time_to_keys = collections.defaultdict(list)
self._keys_to_last_time = 
self._last_visits = collections.deque()
</pre>


###### 1、先找访问时间_last_visits中超出timeout的所有键
###### 2、然后去找_time_to_keys，找出所有可能过期的键
###### 3、因为最早访问时间访问过的键之后可能又访问了，所以要_keys_to_last_time
###### 4、找出那些没被访问过的，然后删除

===============================================================
##### 学到的其他东西：
###### 1、__future__
###### 2、json.loads(f.read().decode('utf8'),object_hook=_decode_dict)
###### 3、python内置的logging也可作大规模使用
###### 4、把我理解层面阔伸到协议层面，学到怎么构建一个协议（协议的设计还要学习）
###### 5、网络编程和信息安全息息相关
###### 6、这个网络编程的学习路线挺不错的：爬虫-\>翻墙软件。不知道下一步怎么加深

一些问题：
###### 1、如何做到线程安全？
###### 2、大量对变量是否存在的检查是为了什么？
###### 3、FSM的思想怎么应用到网络编程？
###### 4、防火墙到底是怎么工作的？（其实这个问题我自己觉得问的挺逗的。。）
###### 5、linux的内核异步IO怎么调用（操作系统）  
  

===============================================================
#### 其他

这个项目有一些比较有趣的代码，目的是兼容python3标准
- 每一个py文件前面都有导入3.x的package:  __future__  ，如果使用print "hello"，会提示出错，因此使用print("hello")
- 给字符串赋值时，总是带有一个前缀'b'，比如：v4addr=b'8.8.4.4'，是为了兼容py3标准，[参考这里](http://stackoverflow.com/questions/6269765/what-does-the-b-character-do-in-front-of-a-string-literal)
- 待续...

* * *

由于水平不足，鄙人尚未理解的代码片段：[Questions](/Questions.md)

* * *

### License

[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-nc-sa/4.0/").

