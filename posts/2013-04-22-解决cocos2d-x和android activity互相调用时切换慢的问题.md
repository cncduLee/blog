## 解决 cocos2d-x 和 android activity 互相调用时切换慢的问题

现象：

[cocos2d-x](http://www.cocos2d-x.org/) 编译 android 应用，生成的 activity 继承自 Cocos2dxActivity, 如果在应用中启用一个新的 java 的 activity，并且在两个 activity 之间切换，那么从 java 的 acitivity 切回来的时候会比较慢

原因：

从 log 中可以看到，切回 cocos2dx 的acitvity 的时候 openglES 会重新加载所有的 Texture，这个操作比较耗时，导致了回切的时候慢。

修改方法：

1）在Cocos2dxGLSurfaceView的onPause中， 注释掉super.onPause() 添加this.setVisibility(View.GONE);

2) 在Cocos2dxGLSurfaceView的onResume中， 注释掉super.onResume() 添加this.setVisibility(View.VISIBLE);

3) 在CCPlatform.h 中 ：

```cpp
#if (CC_TARGET_PLATFORM == CC_PLATFORM_ANDROID)
#define CC_ENABLE_CACHE_TEXTURE_DATA 0 //原来是1
#else
#define CC_ENABLE_CACHE_TEXTURE_DATA 0
#endif
```

