## 让Kohana直接支持python——client篇

最后，是让php和python”对接“起来

我们在php的auto_load的时候也让python加载对应的模块

<!--more-->

```php
<?php defined('SYSPATH') or die('No direct script access.');
 
Socket_Instance::$client = new Socket_Client('127.0.0.1', 1990);
 
class Python_Env_Init extends Kohana{
    /**
     * add auto_load to create php local classes associate to remote python classes
     */
    public static function auto_load($class){
        try{
                $data = Socket_Instance::find_class($class, self::$_paths);
                $code =
                    'class '.$class.' extends Socket_Instance
                        {
                            protected static $_class="'.$class.'";
                            function __construct(){
                                $args = func_get_args();
                                parent::__construct(self::$_class,$args);
                            }
                            static function __callStatic($func, $args){
                                return self::_rpc_call(self::$client,
                                    array(
                                            "class" => self::$_class,
                                            "func" => $func,
                                            "args" => $args, )
                                );                                                   
                            }
                    }';
                eval($code);
                return true;
        }catch(Exception $ex){
                return false;
        }
    }
}
 
spl_autoload_register(array('Python_Env_Init', 'auto_load'));
```

注意到，auto_load的时候动态定义一个class，这个class是一个叫做Socket_Instance的类的实例，这个类是这样的——

```php
<?php defined('SYSPATH') or die('No direct script access.');
 
/**
* the socket instanc handle an unique object instance from the socket server
*
* @package    Python
* @category   Socket
* @author     akira.cn@gmail.com
* @copyright (c) 2011 WED Team
* @license    http://kohanaframework.org/license
*/
class Socket_Instance{
    /**
     * unique identifier to hold the instance
     */
    protected $_id;
 
    /**
     * constructor
     */
    protected $_constructor;
    /**
     * constructor arguments
     */
    protected $_args;
   
    /**
     * socket client
     */
    public static $client = null;
   
    /**
     * create a new socket instance to operate an object instance from the socket server
     *
     * @param    String            $class    class name
     * @param    Array            $args    construct arguments
     * @param    Socket_Client    $client
     */
    public function __construct($class, $args = array(), $id = null){
        if(!isset($id)){
            $id = uniqid('i',true);
        }
        $this->_constructor = $class;
        $this->_args = $args;
        $this->_id = $id;
 
        self::$client->instances[$this->_id] = $this;
    }
   
    /**
     * call a function from remote server
     *
     * @param    String    $func    method name
     * @param    Array    $args    method arguments
     * @return    mixed
     */
    public function __call($func, $args){
        return self::_rpc_call(self::$client,
            array(   
                    "class"        => $this->_constructor,
                    "init"        => $this->_args,
                    "func"        => $func,
                    "args"        => $args,
                    "id"        => $this->_id)
        );                                                   
    }
   
    /**
     * make a rpc_call, send data to server
     *
     * @param    Socket_Client    $client
     * @param    Array            $data
     * @return    mixed   
     */
    protected static function _rpc_call($client, $data){
        $data = json_encode($data);
        $socket = $client->socket();
 
        $res = socket_write($socket, $data, strlen($data));
 
        if($res===false){
            return $client->_error('error socket_write'.socket_strerror(socket_last_error()));
        }
        $res = socket_read($socket, 1024, PHP_BINARY_READ);
        $size = intval(substr($res, 0, 8));
        while($size + 8 > strlen($res)){
            $res .= socket_read($socket, 1024, PHP_BINARY_READ);
        }
        while($size + 8 < strlen($res)){
            $res = substr($res, $size + 8);
            $size = intval(substr($res, 0, 8));
        }
        $res = substr($res, 8, $size);
 
        $ret = json_decode($res, true);
       
        if($ret['err'] == 'sys.socket.error'){
            throw new Socket_Exception($res);
        }
       
        $data = $ret['data'];
       
        //if python func returns a python object, create this object via php
        if(is_array($data) && isset($data['@class']) && isset($data['@init']) && isset($data['@id'])){
            $data = new Socket_Instance($data['@class'], $data['@init'], $data['@id']);
        }
 
        return $data;
    }
 
    /**
     * find a class from remote server
     *
     * @param    String    $class    class name
     * @param    Array    $paths    root paths
     * @return    boolean
     */
    public static function find_class($class, $paths = array()){
        return self::_rpc_call(self::$client,array('class' => $class, 'paths' => $paths));   
    }
}
```

Socket_Instance及其派生类当实例化的时候生成一个唯一的id，用来标识这个实例，并利用魔术方法来处理静态方法和对象方法
注意到实例化Sockiet_Instance的时候并不会连接python，因此python端的对应实例是延迟初始化的，只有当第一个对象方法被调用的时候，id被第一次传入python处理程序（见上一篇），python端的对象实例才被创建（调用static方法因为不传id，所以并不会导致python端的对象构造）。这样的话如果用户new了一个class但一次都没使用过，那么python那头就不会连接和构造，从而优化了效率。

最后为socket_instance封装一个socet client对象

```php
<?php defined('SYSPATH') or die('No direct script access.');
 
/**
* Creating socket handles connected to the socket server
*
* @package    Python
* @category   Socket
* @author     akira.cn@gmail.com
* @copyright (c) 2011 WED Team
* @license    http://kohanaframework.org/license
*/
class Socket_Client{
    /**
     * socket server ip address
     */
    private $_host;
    /**
     * socket server port
     */
    private $_port;
    /**
     * socket connection
     */
    private $_socket;
    /**
     * error reports
     */
    private $_error;
   
    /**
     * the object instances handled
     */
    public $instances = array();
   
    /**
     * create a new socket client object
     *
     * @param    String    $host
     * @param    Int        $port
     */
    function __construct($host = '127.0.0.1', $port = 1990) {
        $this->_host = $host;
        $this->_port = $port;
        $this->_connect();
    }
   
    /**
     * create the connection
     *
     * @return    Socket
     */
    private function _connect() {
        $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if($sock === false){
            return $this->_error('error socket_create'.socket_strerror(socket_last_error()));
        }
 
        $ret = socket_connect($sock, $this->_host, $this->_port);
        if($ret === false){
            return $this->_error('error socket_connect'.socket_strerror(socket_last_error()));
        }
 
        $this->_socket = $sock;
    }
 
    /**
     * get the socket handle
     *
     * @return Socket
     */ 
    public function socket(){
        return $this->_socket;
    }
   
    /**
     * remove the instances handled from the socket server
     */
    public function __destruct() {
        $socket = $this->_socket;
        socket_write($socket, '', 0);
        socket_close($socket);
    }
   
    /**
     * provide errors
     *
     * @throws Socket_Exception
     */
    private function _error($errMsg = '') {
        $this->_error = array(
            'err' => 'sys.socket.error',
            'msg' => $errMsg,
        );
        throw new Socket_Exception($errMsg);
    }
}
```

至此，kohana下python和php直连的机制基本上完成了，用户只需要像写php普通类的方法用python写那些类，在kohana中就可以像是用php写的那些类一样的调用，是不是非常简单呢？

最后，放上这个项目的开源地址——

[https://github.com/akira-cn/Kohana-python]