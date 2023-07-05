## gb28181Server

国标 gb28181 模拟客户端

- 支持 Linux
- 支持 交叉编译
- 支持 下级设备注册，支持级联上级，并转发下级视频到上级

## 说明
此代码是基于  北小菜 （ https://gitee.com/Vanishi/BXC_SipServer.git ） 和 lyyyuna (https://github.com/lyyyuna/gb28181_client) 两位大神的代码进行了一个拼接整合
  依靠ZLMediaServer进行视频转发。
  此代码仅仅是一个 demo。功能不完善（比如，视频流只能启动转发，不能停止。比如：不能灵活接收下级IPC的注册，只能写死通道号级联报给上级，在比如：调用startSendRtp接口时候，ssrc等参数都是写死的，正常应该灵活获取才对）
  所以大家凑合用吧。根据自己需求在改
## 编译
注意：exosip和osip都采用了5.0.0版本。如果想替换其它版本，请做好两个库的对应。（一般情况下要保证版本号完全一致，比如全部为5.2.0 如果不一致，比如一个采用5.2.0，一个采用5.1.0，则可能会出现能正常运行，抓包SIP接收也正确，但库函数解析错误的情况）

1）编译 osip  eXosip  curl（可能会用到openssl库）
```
init.sh脚本仅供参考
```
2）编译代码
如果想交叉编译，将CMakeLists-ARM.txt修改为CMakeLists.txt
```
mkdir build && cd build
cmake ..
make -j8
```

## 运行
```
将GB28181.json 拷贝到build目录
./gb28181Server 
```

## 运行
```
将GB28181.json 拷贝到build目录
./gb28181Server 
```
