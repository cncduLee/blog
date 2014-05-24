## 让Kohana直接支持python——Server篇

最近写php用的是[Kohana](http://kohanaframework.org/) MVC框架。这个框架用的人不是很多，不过确实是一个相当不错的轻量级PHP MVC框架。

php用于web开发还是很方便的，这门语言专注于web开发，作为前端工程师，非常喜欢这种简单的脚本语言。

不过有些后端的服务，如一些对异步要求较高的服务，用php写就稍稍有点费劲，而用python则是不错的选择。

因此，我自然开始考虑是否能将kohana和python结合起来。

<!--more-->

我的设想是：在kohana中能直接new python写的class，就像php的原生方法那样简单

例如：

在koahan中，如果要直接加载一个php的类clas Foo_Bar，那么要求这个类定义放在 classes/foo/bar.php 文件中

现在如果我定义在classes/foo文件夹下的是一个python文件 bar.py，里面定义了一个python的类Foo_Bar

我希望也能用kohana调用这个类

即——

```php
$myObj = new Foo_Bar(); //不论这个类是php还是python写的
```

首先的问题是python和php之间的通信问题，思考之后，我决定用tcp socketserver来解决它，数据协议就用json

python自带了一个socketserver，那是可以支持多线程的异步socket，试着拿它写了一个server——

```python
# coding=utf-8
 
import sys
import json
import traceback
import socket
from SocketServer import BaseRequestHandler, ThreadingTCPServer
from daemon import Daemon
 
from handler import Handler
 
from logger import logger
logger = logger().instance()
 
class RequestHandler(BaseRequestHandler, Handler):
    def setup(self):
        logger.debug('setup')
        self.request.settimeout(60)
        self.rpc_instances = {}
    def handle(self):
        while True:
            try:
                data = self.request.recv(2*1024*1024)
                if not data:
                    break  #end
                data = json.loads(data)
 
                res = self.execute(data)
               
                logger.debug('instance count:' + str(len(self.rpc_instances.keys())))
 
                res = json.dumps(res) 
                res = str(len(res)).rjust(8, '0') + res 
                self.request.send(res)
            except socket.timeout as err:
                res = ('error in RequestHandler :%s, res:%s' % (traceback.format_exc(), data))
                logger.debug(res)
                res = json.dumps({'err':'sys.socket.error', 'msg':format(err)})
                res = str(len(res)).rjust(8, '0') + res 
                self.request.send(res)
                self.request.close()
                break
            except Exception as err:
                res = ('error in RequestHandler :%s, res:%s' % (traceback.format_exc(), data))
                logger.debug(res)
                res = json.dumps({'err':'sys.socket.error', 'msg': format(err)})
                res = str(len(res)).rjust(8, '0') + res 
                self.request.send(res)
 
    def finish(self):
        logger.debug('finish')
        self.request.close()
 
    def response(self, data):
        res = json.dumps(data)
        res = str(len(res)).rjust(8, '0') + res 
        self.transport.write(res)
 
class Server(Daemon):       
    def conf(self, host, port):
        self.host = host
        self.port = port
        ThreadingTCPServer.allow_reuse_address = True
    def run(self):
        server = ThreadingTCPServer((self.host, self.port), RequestHandler)
        try:
            server.serve_forever()
        except Exception as err:
            logger.debug(traceback.format_exc())
   
if __name__ == '__main__':
    server = Server('/tmp/daemon-tortoise.pid')
    port = 1990
    if len(sys.argv) >= 3:
        port = sys.argv[2]
    server.conf('0.0.0.0', port) #change ip address if you want to call remotely
    if len(sys.argv) >= 2:
        if 'start' == sys.argv[1]:
            server.start()
        elif 'stop' == sys.argv[1]:
            server.stop()
        elif 'restart' == sys.argv[1]:
            server.restart()
        else:
            print("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        print("usage: %s start|stop|restart" % sys.argv[0])
        sys.exit(2)
```

继承自Daemon的Server是让操作系统管理进程的，关键的是——

```python
server = ThreadingTCPServer((self.host, self.port), RequestHandler)
        try:
            server.serve_forever()
```

这一步启动了一个tcp server，接下来在RequestHandler中处理逻辑

```python
res = self.execute(data)
```

这一句将json数据解析成python类和方法来执行，具体的代码我们在后续的RPC篇中详细介绍

如果处理过程中有错误，记录日志，并把错误信息发送回php，以方便捕获异常进行调试

在这个模型下，python的整个过程是一个多线程的请求，每个php请求单独建立一个线程连接，处理完成之后或者请求超时之后，连接将被关闭，所有的资源得到释放。

上面用原生的SocketServer实现了简单的php和python通信的机制，它确实能稳定地跑起来，而且效率不差

不过由于存在GIL机制的限制，python多线程模型不能完全占有CPU资源，因此考虑到进一步提高并发请求的效率，改用异步非阻塞单线程机制是一个合理的想法。

对于异步非阻塞连接，php的twisted框架提供了一个相当不错的实现，因此安装twisted之后，利用这个框架写了一个新的server——

```python
server-twisted.py

# coding=utf-8
 
import sys
import traceback
from daemon import Daemon
 
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.protocols.policies import TimeoutMixin
 
from handler import Handler
 
from logger import logger
logger = logger().instance()
 
import json
 
class PHPRequest(Protocol, TimeoutMixin, Handler):   
    def connectionMade(self):
        logger.debug('connection opened')
        self.setTimeout(self.factory.conn_timeout)
        self.clients = str(self.transport.getPeer().host)
        self.factory.connections = self.factory.connections + 1
        logger.debug('connections:' + str(self.factory.connections))
   
    def connectionLost(self,reason):
        self.setTimeout(None)
        self.factory.connections = self.factory.connections - 1
        logger.debug('connection closed:' + reason)
   
    def timeoutConnection(self):
        res = {'err' : 'sys.socket.error', 'msg':"timed out: %s" % self.clients}
        logger.debug("timed out: %s" % self.clients)
        self.response(res)
        self.transport.unregisterProducer()
        self.transport.loseConnection()
 
    def dataReceived(self,data):
        try:
            data = json.loads(data)
            res = self.execute(data)
            logger.debug('instance count:' + str(len(self.rpc_instances.keys())))
        except Exception as err:
            res = ('error in RequestHandler :%s, res:%s' % (traceback.format_exc(), data))
            logger.debug(res)
            res = {'err':'sys.socket.error', 'msg':format(err)}
        finally:
            self.response(res)
   
    def response(self, data):
        res = json.dumps(data)
        res = str(len(res)).rjust(8, '0') + res 
        self.transport.write(res)
 
class PHPRequestFactory(Factory):
    protocol = PHPRequest
    connections = 0
    def __init__(self, conn_timeout):
        self.conn_timeout = conn_timeout
 
class Server(Daemon):       
    def conf(self, host, port):
        self.host = host
        self.port = port 
    def run(self):
        try:
            logger.debug('run')
            factory = PHPRequestFactory(60)
            reactor.listenTCP(self.port, factory)
            reactor.run()
        except:
            logger.debug(traceback.format_exc())
   
if __name__ == '__main__':
    server = Server('/tmp/daemon-tortoise.pid')
    port = 1990
    if len(sys.argv) >= 3:
        port = sys.argv[2]
    server.conf('0.0.0.0', port) #change ip address if you want to call remotely
    if len(sys.argv) >= 2:
        if 'start' == sys.argv[1]:
            server.start()
        elif 'stop' == sys.argv[1]:
            server.stop()
        elif 'restart' == sys.argv[1]:
            server.restart()
        else:
            print("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        print("usage: %s start|stop|restart" % sys.argv[0])
        sys.exit(2)
```

twisted是异步事件回调的模型，逻辑比之前的socketserver更简单，分别处理好connectionMade、connectionLost、dataRecevied和timeoutConnection几个事件就好了。

到此为止，简单的server写好了，它可以和php的client之间相互通信。现在我们要做的事情是将php发送给python的json格式的数据解析成python的命令执行，并且组织好返回给php的数据格式。

关于php的client，将在下一篇文章中详细说明。