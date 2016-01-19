shadowsocks2.6源码阅读_201512,使用了带有注释的版本

asyncdns.py

	1. ~~对于re.complie函数还是一窍不通啊。初始化前几行用到了compile~~
	2. ~~def build_address(address)函数中的results.append(common.chr(l)) #这个l对应的ascii是什么意思~~
	3. ~~parse_name(data, offset)这个函数原理，，中的if (l & (128 + 64)) == (128 + 64):是什么意思~~
	4. class DNSResolver(object)中的hostname to callback 和 callback to hostname有什么区别，对回调这几段，完全看不懂作者的用意。


common.py

	1. ~~def inet_pton(family, addr):这个函数把ipv6地址转成二进制时候首先判断ipv6是否是一个含有v4地址，这部分看不懂~~
	2. ~~def patch_socket():这个补丁是干啥的~~


daemon.py

	1. 有空对应c语言linux编程演示一下daemon的执行过程。


encrypt.py

	1. md5是摘要算法不是加密算法，通常用于密码的验证，例如是锐捷密码验证，可以查看一下锐捷密码查看器的源码
	2. get_cipher()的参数op有什么用途。op=1


eventloop.py

	1. 涉及到各种容器的打包根本不会用
	2. http://www.haiyun.me/archives/1056.html
	3. logging.debug('using event model: %s', model)这个debug输出函数到底是怎么弄出来的，一般的不会显示debug吧
	4. add_handler的含义是什么，handler的准确译法是什么。还有handlers和ref_handlers区别是什么
	5. self._iterating = False，还有if self._iterating: #这里的迭代器是什么意思
	6. 为啥不把移除命令放在for循环外面？ self._handlers_to_remove = []


local.py

	1. if hasattr(sys, "frozen") 这段py2exe初始检查代码的用意？


lru_cache.py

	1. collections.deque还有mutablemapping容器不了解。
	2. LRUCache类的初始化函数形参中的close_callback函数用法，是关闭回调函数吧


server.py

	1. workers是什么东西，"It only works on unix/linux"


tcprelay.py

	1. 在类TCPRelayHandler里面，loop的定义在哪里，怎么就有一个add方法？
	2. 在类TCPRelayHandler里面，_update_stream函数，检查状态是否被改变，只在dirty时候更新，什么意思
	3. @property这个@符号用于什么情况的python里面？
	4. if now - handler.last_activity < TIMEOUT_PRECISION:这个last_activity定义啥了
	6. log级别是怎么显示出来的，平常都是INFO级别的消息？logging.log(utils.VERBOSE_LEVEL,)
	

udprelay.py

	1. 多次见到getaddrinfo函数，返回的proto是什么意思。


utils.py

	1. optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)这个函数是实现原理是？

