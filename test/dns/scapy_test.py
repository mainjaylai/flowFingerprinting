import time
import psutil
from scapy.all import *

grab_time=90

# 用于存储捕获到的HTTP包
packets_counts = 0
raw_count = 0

# 定义数据包回调函数
def packet_callback(packet):
    global packets_counts, raw_count  # 使用global关键字来声明全局变量
    raw_count += 1
    if packet.haslayer(DNS):
        packets_counts += 1

# 获取当前进程的psutil.Process对象
process = psutil.Process()

# 捕获前的CPU和内存使用情况
cpu_usage_start = process.cpu_percent(interval=1)
memory_usage_start = process.memory_info().rss / (1024 * 1024)

# 捕获开始时间
start_time = time.time()

# 开始捕获HTTP流量
sniff(filter="port 53", iface="enp0s8", prn=packet_callback, timeout=grab_time, store=0)

# 捕获后的CPU和内存使用情况
cpu_usage_end = process.cpu_percent(interval=1)
memory_usage_end = process.memory_info().rss / (1024 * 1024)

# 捕获结束时间
end_time = time.time()

# 计算总的CPU使用率和内存占用
cpu_usage_total = cpu_usage_end - cpu_usage_start
memory_usage_total = memory_usage_end - memory_usage_start

print(f"Scapy captured {packets_counts} DNS packets")
print(f"Scapy captured {raw_count} packets")
# print(f"Total CPU usage during capture: {cpu_usage_total}%")
# print(f"Total memory usage during capture: {memory_usage_total} MB")
# print(f"Total time taken for capture: {end_time - start_time} seconds")
