# gb28181Server

国标 gb28181 模拟客户端

- 支持 Linux
- 支持 交叉编译
- 支持 下级设备注册，支持级联上级，并转发下级视频到上级
- 
##说明
此代码是基于  北小菜 （https://gitee.com/Vanishi/BXC_SipServer.git）和

## 编译
注意：exosip和osip都采用了5.2.0版本。如果想替换其它版本，请做好两个库的对应。（一般情况下要保证版本号完全一致，比如全部为5.2.0 如果不一致，比如一个采用5.2.0，一个采用5.1.0，则可能会出现能正常运行，抓包SIP接收也正确，但库函数解析错误的情况）

./init.sh

mkdir build && cd build
cmake ..
make -j8
```

## 运行
```
将GB28181.json 拷贝到build目录
./gb28181Server 
```
