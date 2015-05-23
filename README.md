# arp-connect

1. 一个通过arp欺骗冒充网关来攻击特定ip的例子
  make start
  ./start [fake ip] [target ip]

2. 测试发送接受arp
编译：
  gcc arp-send.c -o send
  gcc arp-recv.c -o recv
运行：
  ./recv [your ip]
  ./send [your ip]
