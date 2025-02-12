# linux内核dnsmasq服务

dnsmasq是systemd管理的一个service

```bash
# systemctl status dnsmasq.service
● dnsmasq.service - DNS caching server.
   Loaded: loaded (/usr/lib/systemd/system/dnsmasq.service; enabled; vendor preset: disabled)
   Active: active (running) since 三 2025-02-12 16:10:28 CST; 1h 4min ago
 Main PID: 40405 (dnsmasq)
    Tasks: 1
   Memory: 4.0M
   CGroup: /system.slice/dnsmasq.service
           └─40405 /usr/sbin/dnsmasq -k

2月 12 16:10:28 cdnhebcm06-rs-445.idccdn.heb.kwaidc.com systemd[1]: Started DNS caching server..
2月 12 16:10:28 cdnhebcm06-rs-445.idccdn.heb.kwaidc.com systemd[1]: Starting DNS caching server....
2月 12 16:10:28 cdnhebcm06-rs-445.idccdn.heb.kwaidc.com dnsmasq[40405]: listening on lo(#1): 127.0.0.1
2月 12 16:10:28 cdnhebcm06-rs-445.idccdn.heb.kwaidc.com dnsmasq[40405]: listening on lo(#1): ::1
```

日志路径/var/log/dnsmasq.log /var/log下是一些系统日志

dns服务框架





<img src=".gitbook/assets/file.excalidraw.svg" alt="" class="gitbook-drawing">

在查找一个域名的时候会把请求发送到不同级的服务器上进行查询。

但是对于一个ISP来说，拥有一个本地服务器是一个非常常见且高效的做法。



单机上的dns服务

Linux上通常使用dnsmasq服务，它的作用是当用户向一个域名发起请求时，能够根据配置的dns服务器来解析到正确的IP地址。

配置文件/etc/dnsmasq.conf，配置参数：[https://github.com/imp/dnsmasq/blob/master/dnsmasq.conf.example](https://github.com/imp/dnsmasq/blob/master/dnsmasq.conf.example)

dnsmasq的默认流程：

dnsmasq.conf文件中可以配置server地址，通过指定使用哪个DNS服务器进行解析，对于不同的网站可以使用不同的域名对应解析。 例如：`server=/google.com/8.8.8.8` #表示对于google的服务，使用谷歌的DNS解析。这是第一步的查询

不匹配的则走dnsmasq定义的上游DNS，从/etc/dnsmasq.conf文件中读取resolv-file=/path/file，从file中获取upstream的DNS服务器的地址

