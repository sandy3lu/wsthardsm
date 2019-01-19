## 项目介绍   
提供对卫士通加密卡的 C 语言二次封装。

## 开发环境依赖
```
1. 操作系统：centos：7.5  
2. docker  
3. docker-compose  
4. 卫士通 PCI-XE4 类型的加密卡，B 型号
```

### 开发环境准备
开发过程中，需要编译 C 语言程序，链接加密卡链接库，链接 protobuf 等，因此采用 docker 构建开发环境镜像，
docker-compose up -d 命令即可启动开发使用的容器，进入容器进行日常开发即可。

### 依赖
开发依赖于卫士通加密卡的动态链接库，所有相关的依赖都在 ../resources 目录中:
1. load: 加载加密卡驱动，否者无法检测到和使用加密卡
2. unload: 卸载加密卡驱动，当发现加密卡状态错误时，可以先卸载再加载加密卡驱动以进行复原
3. libsmwsta.so: 卫士通加密卡 A 卡
4. libsmwstb.so: 卫士通加密卡 B 卡
5. libsmwst.so: 对 libsmwstb.so 的软连接，因为目前只用得到 B 卡

### 输出
1. libyjsmwst.so: 本项目输出的 C 语言二次封装库，依赖 libsmwst.so
2. smtest 和 smtool 是编译出的用于测试 libyjsmwst.so 的可执行文件 demo

### 编译
```
make
```  

## 运行
```
cd ../resources
./smtest
./smtool
若输出没有错误信息，即测试无误
```

## 目录结构
1. api: protobuf c apis，详细的 api 描述，参见 hardsm.h
2. build: 编译生成的输出目录，可以 make clean 删除
3. include: 内部头文件
4. proto: proto 定义和生成的代码
5. sm: 主体业务逻辑实现
6. test: 单元测试
7. util: 通用功能

## 遗留问题
1. 加密卡 ukey 制作和备份尚未实现
2. logout 加密卡后，加密卡的存储资源并没有被释放，应该是加密卡的 BUG，但是影响不是很大，大不了每次应用启动前重置驱动即可。

## 联系方式  
```
* 公司开发者邮箱: yjdev@yunjingit.com
* 朱林峰: zhulinfeng@yunjingit.com
```  
------------------------------------------------------------------------------------------------------------
Copyright (c) 2018.11.01 Beijing YunJing Technology.Ltd. All rights reserved.
