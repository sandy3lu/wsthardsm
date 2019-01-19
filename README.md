## 项目介绍   
提供对卫士通加密卡的 C 语言二次封装与 java SDK 封装。

## 功能特性
1. 单元测试
2. 命令行工具
3. API

## 开发环境依赖
```
1. 操作系统：centos：7.5  
2. docker  
3. docker-compose  
4. java8
5. maven3.6
6. 卫士通 PCI-XE4 类型的加密卡，B 型号
```

### 开发环境准备
1. docker 容器
开发过程中，需要编译 C 语言程序，链接加密卡链接库，链接 protobuf 等，也需要 java 和 maven 环境，因此采用 docker 构建开发环境镜像，
docker-compose up -d 命令即可启动开发使用的容器，进入容器进行日常开发即可。

### 生产环境
```
# 部署动态链接库，将 resources 目录中的 libsmwst* 文件拷贝至 /usr/lib 目录下并生效
cp resources/*.so /usr/lib
ldconfig

# 执行单元测试
mvn test

# 生成打包文件并执行单元测试
mvn package

# 生成打包文件，并跳过单元测试
mvn package -Dmaven.test.skip=true 

# 运行
java -jar target/hardsm-0.0.1-SNAPSHOT.jar
```  


## 使用方式


## API 说明


## 目录结构


## 联系方式  

```
* 公司开发者邮箱: yjdev@yunjingit.com
* 朱林峰: zhulinfeng@yunjingit.com
```  
------------------------------------------------------------------------------------------------------------
Copyright (c) 2018.11.01 Beijing YunJing Technology.Ltd. All rights reserved.
