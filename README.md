Watchdog-Go
===========
基于Golang/http的态势感知系统，主要功能包括：
- 网络流量分析/规则匹配拦截/
- 对php文件扫描危险函数
- 自动备份网站源码
- 基于banIP的ddos拦截

**Usage：**
- 1.修改config.go中的配置，包括sqlite文件名称、管理面板host、jwt的secretkey
- 2.编译：go build src
- 3.将管理域名指向本机，访问管理面板，添加需要监控的域名（也需要指向本机）
- 4.访问管理面板看着用吧

**Contributors：**
- Tritium0041 : 管理面板、反向代理、流量记录拦截
- Zfly : 源码扫描、备份网站
