#!/bin/bash


while iptables -C INPUT -p tcp --dport 554 -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 554 -j DROP
done

while iptables -C INPUT -p tcp --dport 554 -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 554 -j ACCEPT
done


iptables -I INPUT 1 -p tcp --dport 554 -j ACCEPT

echo "RTSP Protection Disabled"
