## shadowsocks 2.6 源码分析

研究目的：阅读旧版本(2014.12)源码，体验基本的网络编程思想，学习通信协议

[![Join the chat at https://gitter.im/lao605/shadowsocks_analysis](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/lao605/shadowsocks_analysis?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)  <= 点击加入讨论组

仅用作学术交流用途，其他行为带来的后果本人概不负责

* * *

|Shadowsocks作者|源码注释项目作者|原注释项目地址
|---|---|
|[@clowwindy](https://github.com/clowwindy)|[@lao605](https://github.com/lao605)|[shadowsocks-analysis](https://github.com/lao605/shadowsocks_analysis)

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
|local.py|客户端||
|server.py|服务端|支持多用户|
|lru_cache.py|缓存|基于LRU的Key-Value字典|
|tcprelay.py|tcp的转达||
|udprelay.py|udp的转达|local <=> client <=> server <=> dest|

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

* * *

由于水平不足，鄙人尚未理解的代码片段：[Questions](/Questions.md)

* * *

### License

[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-nc-sa/4.0/").

