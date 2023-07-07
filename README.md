Watchdog-Go
===========
基于Golang/gopacket的态势感知系统，主要功能包括：
- 网络流量分析/规则匹配拦截/重放
- 对php文件扫描危险函数
- 自动备份网站源码
- 基于banIP的ddos拦截
- 检测flag字段并自动替换


issue#1
- 是使用proxy还是pcap？pcap貌似无法拦截包
reply#1
- 手写反向代理，这玩意又不是awd用的，当成waf来写
