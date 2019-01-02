FROM centos
MAINTAINER zhulinfeng zhulinfeng@yunjingit.com


WORKDIR /root
RUN ls

RUN yum -y install epel-release && \
    yum update -y && \
    yum install gcc -y && \
    yum install gcc-c++ -y && \
    yum install make -y && \
    yum install https://centos7.iuscommunity.org/ius-release.rpm -y && \
    yum install tree -y && \
    yum install less -y && \
    yum install wget -y


COPY deps/protobuf-3.1.0.tar.gz ./
COPY deps/protobuf-c-1.2.1.tar.gz ./
RUN yum install dh-autoreconf -y && \
    tar zxvf protobuf-3.1.0.tar.gz && cd protobuf && \
    ./autogen.sh && ./configure && \
    make && make check && make install && ldconfig && cd ..
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig && \
    tar zxvf protobuf-c-1.2.1.tar.gz && cd protobuf-c-1.2.1 && \
    ./configure && make && make install && cd .. && \
    cp /usr/local/bin/protoc-c /usr/bin/protoc-c && \
    rm -f protobuf-3.1.0.tar.gz protobuf-c-1.2.1.tar.gz && rm -rf protobuf protobuf-c-1.2.1


RUN wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3a%2F%2Fwww.oracle.com%2Ftechnetwork%2Fjava%2Fjavase%2Fdownloads%2Fjdk8-downloads-2133151.html; oraclelicense=accept-securebackup-cookie;" "https://download.oracle.com/otn-pub/java/jdk/8u191-b12/2787e4a523244c269598db4e85c51e0c/jdk-8u191-linux-x64.rpm" \
    && yum install jdk-8u191-linux-x64.rpm -y && rm -f jdk-8u191-linux-x64.rpm


RUN ln -s /usr/java/jdk1.8.0_191-amd64 /usr/java/java8 && \
    echo "export JAVA_HOME=/usr/java/java8" >> /etc/profile && \
    echo "export JRE_HOME=/usr/java/java8/jre" >> /etc/profile && \
    echo "export CLASSPATH=.:/usr/java/java8/lib:/usr/java/java8/jre/lib" >> /etc/profile && \
    echo "export PATH=/usr/java/java8/bin:/usr/java/java8/jre/bin:$PATH"  >> /etc/profile && \
    echo "export JDK_HOME=/usr/java/java8" >> /etc/profile && \
    source /etc/profile && echo $JAVA_HOME && cat /etc/profile


RUN wget http://www-us.apache.org/dist/maven/maven-3/3.6.0/binaries/apache-maven-3.6.0-bin.tar.gz && \
    tar zxvf apache-maven-3.6.0-bin.tar.gz -C /usr/local && \
    ln -s /usr/local/apache-maven-3.6.0 /usr/local/maven && \
    source /etc/profile && \
    echo "export M2_HOME=/usr/local/maven" >> /etc/profile && \
    echo "export PATH=$PATH:/usr/local/maven/bin" >> /etc/profile && \
    source /etc/profile && echo $M2_HOME && cat /etc/profile && rm -f apache-maven-3.6.0-bin.tar.gz
