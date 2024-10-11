#!/bin/bash

# 目标 URL
URL="http://192.168.1.116:8080"

# 请求次数
REQUESTS=10000

# 循环发送 HTTP 请求
for i in $(seq 1 $REQUESTS); do
  curl -s $URL > /dev/null &
done

# 等待所有后台进程完成
wait
