## 让Kohana直接支持python——RPC篇

上一篇中，我们实现了基础的TCP Server，数据通过json协议进行传输

接下来，我们需要处理RPC请求的核心部分。
我们来看，在PHP代码中写：

```php
$myObj = new Foo_Bar();
$myObj->test();
```

我们要python端做哪些事情

<!--more-->

首先，我们要让python找到对应的模块加载（按kohana规则，这个模块叫 classes/foo/bar.py）

其次，我们用php new了一个python对象，对象名为Foo_Bar，接着，调用了test方法

在RPC请求中，我们先要通知python去new这个对象，并且将这个实例保存下来

再次，当我们调用test()方法时，python要知道调用这个方法的对象实例是我们刚才保存下来的那个Foo_Bar实例。所以这里，我们必须要维持一个唯一的id，作为这个实例的标识。

id有两个作用，一是避免对象的重复构造，二是让python知道该用哪个对象去调用方法。

对于让python找到对应的模块加载，这个可以放在php的autoload中进行，只要在autoload的过程中，将对应的路径classes加入到python的sys.path中，并且写好classes/foo/__init__.py，那么在python中通过import或__import__就能将正确的模块加载进来了。

至于new正确的python对象，只需要将Foo_Bar解析成foo.bar.Foo_Bar，应该不难。这只是简单的正则替换而已。

有了class，我们根据guid构造出实例，并且将这个实例保存在对应的guid的字典字段中。

完整的代码并不复杂：

```python
# coding=utf-8
 
import sys
import uuid
from types import *
 
class Handler():
    def __init__(self):
        self.rpc_instances = {}
    def execute(self, data):
        rpc_instances = self.rpc_instances;
 
        if('paths' in data): #set auto loading paths
            data['paths'].reverse()
            for i in range(len(data['paths'])):
                path = data['paths'][i] + 'classes'
                if(path not in sys.path):
                    sys.path.insert(1, path)
       
        #call the object instance func - {id, func, args[class, init]}
        if('id' in data):
            if(data['id'] in rpc_instances):    #the object has been created
                o = rpc_instances[data['id']]
            else:                               #create new object instance
                c = self.find_class(data['class'])
                o = apply(c, data['init'])
                rpc_instances[data['id']] = o 
            res =  apply(getattr(o, data['func']), data['args']) or '' 
 
        #call class func - {class, [func, args]}
        else:
            c = self.find_class(data['class'])
            #if not 'func', only to test wether the class exists or not
            if(not ('func' in data)): #TODO: get the detail info of the class?
                res = True
            else:
                res = apply(getattr(c, data['func']), data['args']) or ''
       
        if(type(res) is InstanceType):
            uid = str(uuid.uuid4())
            rpc_instances[uid] = res
            res = {'@id':uid, '@class':res.__class__.__name__, '@init':[]}  
       
        return {'err':'ok', 'data':res}
 
    def find_class(self, class_name):
        #resolve the path from class name like 'Model_Logic_Test'
        path = map(lambda s: s.lower(), class_name.split('_'))
        p = __import__(".".join(path))
 
        for i in range(len(path)):
            if(i > 0):
                p = getattr(p, path[i])
   
        return getattr(p, class_name)
```