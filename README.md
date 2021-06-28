> 本项目禁止用于比赛. 如果您需要一个比赛场景下的WAF, 可以考虑[DasSecurity-Labs/AoiAWD](https://github.com/DasSecurity-Labs/AoiAWD). (但请注意规则是否允许第三方通防)

<p align="center">
<image style="height:200px;display:inline" src="resources/logo.svg" height="200px" />
<h1 align="center">Watchbird</h1>
<small><p align="center">Version 1.6</p></small>
<b><i><p align="center">A powerful PHP WAF for AWD</p></i></b>
</p>

## 功能:

- 易于配置(单文件, 无需加载外部js/css)
- 可以随时开启/关闭某项防御
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
    - 基于open_basedir的PHP文件操作保护
- 网页控制台:
    - 功能开关及配置
    - 实时日志查看
    - 日志流量重放, 可广播流量至指定网段, 支持提取flag自动提交
    - RCE/文件上传/深度检测 防御通知(由于chrome无法允许不安全的网站(无SSL证书)显示通知,请使用Firefox并修改about:config中dom.webnotifications.allowinsecure为true)

## 使用

1. 下载最新 [release](https://github.com/leohearts/awd-watchbird/releases)
2. 编译waf.c生成.so文件,参考命令:gcc waf.c -shared -o waf.so
3. 将waf.so,watchbird.php文件存放在/var/www/html或其他目录中
5. 将watchbird.php放在www-data可读的目录, 确保当前用户对目标目录可写, 然后执行```php watchbird.php --install [Web目录]```, 安装器将输出安装了watchbird的文件路径
4. 访问任意启用了waf的文件, 参数```?watchbird=ui```打开watchbird控制台, 创建一个初始密码
6. 如需卸载, 请在相同的位置输入```php watchbird.php --uninstall [Web目录]```, 如果您多次运行了安装, 请多次运行卸载直到卸载器无输出

## 构建

- `git clone https://github.com/leohearts/awd-watchbird.git`
- 使用 `pyhton3 pack.py` 将源码打包为单文件

## 截图

![Screenshot_2021-03-08 Watchbird控制台.png](https://i.loli.net/2021/03/08/DELBdIMxyCgtluf.png)

![Screenshot_2021-03-08 Watchbird控制台_1_.png](https://i.loli.net/2021/03/08/6jyrWYUxIXMsqpl.png)

![Screenshot_2021-03-08 Watchbird控制台_2_.png](https://i.loli.net/2021/03/08/RnY7VAZtJmIeKoX.png)

## 贡献者

- *Leohearts*
- *Longlone*
- *你* (欢迎Issue及Pull Request)

<b>本项目的开发仅出于研究目的, 请不要在比赛中使用.</b>
