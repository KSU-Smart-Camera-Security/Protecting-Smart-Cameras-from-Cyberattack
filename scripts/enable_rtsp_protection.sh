#!/bin/bash

while iptables -C INPUT -p tcp --dport 554 -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 554 -j ACCEPT
done

while iptables -C INPUT -p tcp --dport 554 -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 554 -j DROP
done

while iptables -C INPUT -p tcp --dport 554 -j LOG --log-prefix "RTSP_ATTACK: " 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 554 -j LOG --log-prefix "RTSP_ATTACK: "
done

iptables -I INPUT 1 -p tcp --dport 554 -j DROP
iptables -I INPUT 1 -p tcp --dport 554 -j LOG --log-prefix "RTSP_ATTACK: "

echo "RTSP Protection Enabled"
