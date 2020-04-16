# Watchbird
***Version 1.0***

***A Simple PHP WAF for AWD***

## 功能:

- 精致小巧,容易配置(20kb)
- 可以随时修改内置防护等级,也可以随时开启/关闭某项防御
- 基本防御:
    - 数据库注入(sql injection)
    - 文件上传(upload)
    - 文件包含(lfi)
    - flag关键字
    - PHP反序列化(unserialize)
    - 命令执行(rce)
    - 分布式拒绝服务攻击(ddos)
    - 请求头,请求参数(GET/POST)关键字
    - 特殊字符
- 深度防御:
    - 响应检测/反向代理(默认将流量发送至本地服务器自检,可配置代理服务器IP及端口实现反代功能)
    - 响应flag检测并返回虚假flag
- 基于LD_PRELOAD的指令执行保护

## 使用

1. git clone https://github.com/leohearts/awd-watchbird.git
2. 编译waf.c生成.so文件,参考命令:gcc waf.c -shared -fPIC -o waf.so
3. 将waf.so文件存放在/var/www/html或其他目录中
4. 修改watchbird.php的配置(包含详细的注释)
5. 寻找入口文件,将以下代码放入第一行`<?php include "watchbird.php" ?>`

## 贡献者

- *Longlone*
- *Leohearts*
- *guoqing*

## 未来视

- 控制waf的网页前端
- 流量重放