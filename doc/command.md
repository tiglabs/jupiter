|Command|Parameter|Description|
|-|-|-|
|config|None|Show configuration information.|
|netdev/reset|None|Reset NIC packet statistics.|
|netdev/stats|[--json]|Show NIC packet statistics.|
|netdev/ipaddr|None|Show KNI\|LOCAL ipv4 address|
|netdev/hwinfo|None|Show NIC link-status|
|lcore-event/stats|None|Show lcore event resource usage|
|arp|None|Show arp table information|
|vs/add|VIP:VPORT tcp\|udp [ipport\|iponly\|rr\|lc]|Add virtual service|
|vs/del|VIP:VPORT tcp\|udp|Delete virtual service|
|vs/list|[--json]|List all virtual services|
|vs/stats|VIP:VPORT tcp\|udp [--json]|Show packet statistics of virtual service|
|vs/max-conns|VIP:VPORT tcp\|udp [VALUE]|Show or set max number of connection to virtual service|
|vs/conn-expire-time|VIP:VPORT tcp\|udp [VALUE]|Show or set connection expiration time|
|vs/source-ipv4-passthrough|VIP:VPORT tcp\|udp [enabel\|disable]|Show or set whether to pass client addres to real service|
|vs/schedule|VIP:VPORT tcp\|udp [ipport\|iponly\|rr\|lc]|Show or set scheduling algorithm|
|vs/cql|VIP:VPORT tcp\|udp [on\|off] [SIZE]|Show or set whether to use CQL(client query limit)|
|vs/cql/list|VIP:VPORT tcp\|udp|List all CQL rules|
|vs/cql/add|VIP:VPORT tcp\|udp IP QPS|Add CQL rules|
|vs/cql/del|VIP:VPORT tcp\|udp IP|Delete CQL rules|
|vs/conn-report|VIP:VPORT tcp\|udp COND_SEC|Report number of client queries in the past time|
|rs/add|VIP:VPORT tcp\|udp RIP:RPORT|Add real service|
|rs/del|VIP:VPORT tcp\|udp RIP:RPORT|Delete real service|
|rs/list|VIP:VPORT tcp\|udp [--json]|List all real services|
|rs/status|VIP:VPORT tcp\|udp RIP:RPORT [up\|down]|Show or set real service status down or up|
|rs/stats|VIP:VPORT tcp\|udp RIP:RPORT|Show packet statistics of real service|
|tcp/stats|[--json]|Show TCP error statistics and TCP resource usage|
|tcp/max-expire-num|[VALUE]|Show or set max number of expired TCP connection each times|
|tcp/reset-timestamp|[enable\|disable]|Show or set whether to clean TCP timestamp option|
|udp/stats|[--json]|Show UDP error statistics and UDP resource usage|
|udp/max-expire-num|[VALUE]|Show or set max number of expired UDP connection each times|
|udp/conn-delay-recycle|[VALUE]|Show or set active time of each UDP connection This can improve performance|
|icmp/stats|None|Show ICMP packet statistics|
|list-command|None|List all the commands|
|memory|[--json]|Show memory usage|
|version|None|Show version|
|exit|None|Kill jupiter-service|
|quit|None|Kill jupiter-service|
|stop|None|Kill jupiter-service|