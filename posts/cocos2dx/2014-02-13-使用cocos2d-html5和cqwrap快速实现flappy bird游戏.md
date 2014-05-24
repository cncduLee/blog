## 使用 cocos2d-html5 和 cqwrap 快速实现 Flappy Bird 游戏

毫无疑问，最近手机游戏届最大的赢家无疑是 Flappy Bird 的作者。谁也没想到这样一款简单的脑残游戏竟然能够火爆到这种程度。

惊讶归惊讶吧，作为程序猿，我们更多时候还是淡定滴研究技术，因此本文也还是以如何开发这样一款“脑残游戏”为讨论主题。

### 游戏的准备工作

因为我们要做一个一模一样的游戏，所以我们准备与官方扑腾小鸟长得非常相似的素材。由于这款游戏实在太火爆了，因此网络上各种版本的山寨，所以素材并不难找。将这些素材使用 Texture Packer 工具拼接好，那么我们的游戏准备工作就完成了。

### 使用类库

在这里我们使用 cocos2d-html5-2.2.2，在 [cocos2d-html5官方](https://github.com/cocos2d/cocos2d-html5/releases)，可以下载到这个版本。

另外我们使用一个叫做 cqwrap 的库，这是一个我为 cocos2dx-jsb 和 cocos2dx-html5 定制的扩展，我在前一个开源的游戏 HappyGo 中也使用了它，你可以在[这里](http://go.akira-cn.gitpress.org/)看到我为它写的一个简易的使用文档，可以从 github 的这个项目中获得它的代码。

<!--more-->

### 开始编码

素材有了，框架也有了，这样就可以开工了。

首先，这样一个简单的游戏，我们只需要一个场景，我们把它命名为 PlayScene

在 src/view/ 目录下创建一个 play_scene.js 的文件，

```js
var layers = require('cqwrap/layers'),
    BaseScene = require('cqwrap/scenes').BaseScene;
var GameLayer = layers.GameLayer, BgLayer = layers.BgLayer;

var MyScene = BaseScene.extend({
    init:function () {
        this._super();

        //添加静态的背景
        var bg = new BgLayer("res/bg.png");
        this.addChild(bg);
    }
});

module.exports = MyScene;
```

我们首先创建了一个场景，在这个场景里面，我们添加了一个静态的背景层。在cqwrap中，封装了一个BgLayer的类，用来创建静态的背景层。

这样，我们就建立了一个只有一个远背景层的场景。

### 创建前景

我们在背景的基础上创建一个前景层，小鸟、水管和其他元素都在这个层上

```js

var layers = require('cqwrap/layers'),
    BaseScene = require('cqwrap/scenes').BaseScene;
var GameLayer = layers.GameLayer, BgLayer = layers.BgLayer;

var MyScene = BaseScene.extend({
    init:function () {
        this._super();

        //添加静态的背景
        var bg = new BgLayer("res/bg.png");
        this.addChild(bg);

        //添加前景层
        var layer = new MyLayer();
        this.addChild(layer);
    }
});

module.exports = MyScene;
```

我们创建了一个MyLayer实例，作为前景层，我们在下面的代码里展示 MyLayer 的基本结构：

```js

var MyLayer = GameLayer.extend({
    init: function(){
        this._super();
        return true;
    }
});
```

我们仅仅创建了一个游戏层，这个层继承自 GameLayer，GameLayer是cqwrap提供的一个类，用来创建包括精灵和动作事件的层。

### 在游戏场景中加载资源

首先我们得把素材资源加载进来，在 cocos2d-html5 中，我们可以通过 SpriteFrameCache 将之前打包的资源加载进来

```js

var MyLayer = GameLayer.extend({
    init: function(){
        this._super();
        
        //加载游戏素材资源
        var cache = cc.SpriteFrameCache.getInstance();
            cache.addSpriteFrames("res/flappy_packer.plist", "res/flappy_packer.png");

        return true;
    }
});
```

### 实现一个“往前移动”的效果

在 Flappy Bird 中，小鸟看起来在往前飞翔，是因为用地面的图片做了一个动画效果

```js
var MyLayer = GameLayer.extend({
    init: function(){
        this._super();
        
        //加载游戏素材资源
        var cache = cc.SpriteFrameCache.getInstance();
            cache.addSpriteFrames("res/flappy_packer.plist", "res/flappy_packer.png");

        //显示地面
        var ground = cc.createSprite('res/ground.png', {
            anchor: [0, 0],
            xy: [0, 0],
            zOrder: 3
        });

        //让地面运动起来
        ground.moveBy(0.5, cc.p(-120, 0)).moveBy(0, cc.p(120, 0)).repeatAll().act();

        this.addChild(ground);
        
        return true;
    }
});
```

### 飞翔的小鸟

有了一个会“前进”的地面之后，我们只要在空中放置一只小鸟，那么就可以制造出飞翔的效果了：

```js
//我是一只小小小小鸟
var bird = cc.createSprite('bird1.png', {
    anchor: [0.5, 0],
    xy: [220, 650],
    zOrder: 2
});

this.addChild(bird);        
```

cc.createSprite 是一个非常方便的方法，它是由cqwrap库提供的额外方法，可以用来更方便地创建各种 Sprite.

现在我们创建了一只在空中的小鸟，它看起来会不断向前进，但是看起来比较奇怪，因为它的翅膀是不动的。

我们可以执行动画，让小鸟动起来——

```js

//给小鸟增加飞行动画
bird.animate(0.6, 'bird1.png', 'bird2.png', 'bird3.png').repeat().act();
bird.moveBy(0.3, cc.p(0, -20)).reverse().repeatAll().act();
```

现在，我们拥有了一只在空中不断飞翔的小鸟

### 响应 touch/鼠标 事件

在 cqwrap 中，一个 GameLayer 是一个代理，它可以代理精灵们的事件，甚至可以代理自身的事件——

```js
this.delegate(this);    //将Layer的touch事件代理给Layer自身
this.on('touchstart', function(){
    //事件处理函数 
});
```

### 让小鸟往高处飞

我们添加让小鸟往高处飞的事件——

```js
this.on('touchstart', function(){
    bird.stopAllActions();
    bird.animate(0.2, 'bird1.png', 'bird2.png', 'bird3.png').repeat().act();

    var jumpHeight = Math.min(1280 - birdY, 125);
    bird.moveBy(0.2, cc.p(0, jumpHeight)).act();

    bird.rotateTo(0.2, -30).act(); 
});
```

### 让小鸟会掉落下来

```js
this.on('touchstart', function(){
    var birdX = bird.getPositionX();
    var birdY = bird.getPositionY();
    var fallTime = birdY / 1000;

    bird.stopAllActions();
    bird.animate(0.2, 'bird1.png', 'bird2.png', 'bird3.png').repeat().act();

    var jumpHeight = Math.min(1280 - birdY, 125);
    bird.moveBy(0.2, cc.p(0, jumpHeight)).act();

    bird.rotateTo(0.2, -30).act();
    bird.delay(0.2).moveTo(fallTime, cc.p(birdX, 316), cc.EaseIn, 2)
        .then(function(){
            //小鸟掉落下来了

        }).act();
    bird.delay(0.2).rotateTo(fallTime, 90, 0, cc.EaseIn, 2).act();    
});
```

现在我们有了一只会飞的小鸟，点击鼠标让它飞起来，如果不点击，它就会掉到地上。

精灵的 animate 方法可以播放帧动画，只需要传给它每一帧的图片就行了，repeat表示重复播放，可以传一个参数表示次数，不传的话表示无限次重复。

### 创建水管和让水管移动起来

```js
function createHose(dis){
    var hoseHeight = 830;
    var acrossHeight = 250;
    var downHeight = 200 + (400 * Math.random() | 0);
    var upHeight = 1000 - downHeight - acrossHeight;
    
    var n = (self.hoses.length / 2) | 0;
    var hoseX = dis + 400 * n;

    var hoseDown = cc.createSprite('holdback1.png', {
        anchor: [0.5, 0],
        xy: [hoseX, 270 + downHeight - 830],
    });

    var hoseUp = cc.createSprite('holdback2.png', {
        anchor: [0.5, 0],
        xy: [hoseX, 270 + downHeight + acrossHeight],
    });

    self.addChild(hoseDown);
    self.addChild(hoseUp);

    var moveByDis = hoseX+500;
    hoseUp.moveBy(moveByDis/200, cc.p(-moveByDis, 0)).then(function(){
        hoseUp.removeFromParent(true);
    }).act();
    hoseDown.moveBy(moveByDis/200, cc.p(-moveByDis, 0)).then(function(){
        createHose(-500);
        var idx = self.hoses.indexOf(hoseDown);
        self.hoses.splice(idx, 2);
        self.scoreBuf ++;
        hoseDown.removeFromParent(true);
    }).act();

    self.hoses.push(hoseDown, hoseUp);
    
};
```

我们将上下两半部分水管的卡通分别计算位置，让缺口保持固定的大小，出现位置随机，然后将水管从屏幕外面往中间移动。

由于考虑性能，我们回收使用过的水管精灵，所以我们把当前可用的精灵放在一个队列中，根据队列的数量来计算新生成的水管精灵的位置。

### 计算小鸟和水管的碰撞

```js
//碰撞检测
self.checker = self.setInterval(function(){
    //cc.log(111);
    var score = 0;

    //这里可以用 boundingBox 的 上下左右的中间点来判断碰撞，会更准确一些
    var box = bird.getBoundingBox();
    var bottom = cc.p(box.x + box.width / 2, box.y);
    var right = cc.p(box.x + box.width, box.y + box.height / 2);
    var left = cc.p(box.x, box.y + box.height / 2);
    var top = cc.p(box.x + box.width / 2, box.y + box.height);

    self.hoses.some(function(hose){
        var box = hose.getBoundingBox();

        if(hose.getPositionX() <= 220) score ++;

        //cc.log(score);

        if(hose.getPositionX() > 0 && hose.getPositionX() < 720
            //&& cc.rectIntersectsRect(hose.getBoundingBox(), bird.getBoundingBox())
            && (cc.rectContainsPoint(box, left)
                || cc.rectContainsPoint(box, right)
                || cc.rectContainsPoint(box, top)
                || cc.rectContainsPoint(box, bottom))){
            //cc.log([hose.getBoundingBox(), bird.getBoundingBox()]);
            layerMask.fadeIn(0.1).fadeOut(0.1).act();
            Audio.playEffect('audio/sfx_hit.ogg');
            self.status = 'falling';
            return true;
        }
    });

    //碰撞后小鸟掉下来，地面、水管都停止运动
    if(self.status == 'falling'){
        self.clearInterval(self.checker);
        ground.stopAllActions();
        
        self.hoses.forEach(function(o){
            o.stopAllActions();
            //o.removeFromParent(true);
        });
    }

}, 50)
```

基本的原理就这些了，剩下的就是一些细节，最终完整版的扑腾小鸟演示[点这里体验](http://go.weizoo.com/flappy)
