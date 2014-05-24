## Church计数和Lambda演算——不用“数”的自然数运算

参考：http://shellex.info/church-nurmal-and-lambda-calculus/

```js
var zero = function(f){
    return function(x){return x};
}
 
var one = function(f){
    return function(x){return f(x)};
}
 
var two = function(f){
    return function(x){return f(f(x))};
}
 
var add = function(n, m){
    return function(f){
        return function(x){
            return n(f)(m(f)(x));
        }
    }
}
```

如果要翻译回普通“自然数”，可以用下面的

```js
var inc = function(x){
    return x?++x:1;
}
alert(add(two,add(two,one))(inc)());
```

这个加法是没有用迭代和效率问题的（当然“翻译”的时候需要），另外把inc的++改成 –，就翻译成“减法”了

