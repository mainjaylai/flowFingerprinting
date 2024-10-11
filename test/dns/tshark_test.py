import time
import psutil
import subprocess

# sudo tshark -i enp0s8 -f "port 53" -w tshark_output.pcap

# 监控 tshark 进程持续时间
capture_duration = 60

# 启动 tshark 进程捕获 HTTP 流量
tshark_command = ["tshark", "-i", "enp0s8", "-f", "udp port 53", "-a", f"duration:{capture_duration}", "-w", "tshark_output.pcap"]
tshark_process = subprocess.Popen(tshark_command)

# 等待 tshark 进程启动
time.sleep(2)

# 获取 tshark 进程的 psutil.Process 对象
tshark_pid = tshark_process.pid
tshark_psutil_process = psutil.Process(tshark_pid)

# 捕获前的CPU和内存使用情况
cpu_usage_start = tshark_psutil_process.cpu_percent(interval=1)
memory_usage_start = tshark_psutil_process.memory_info().rss / (1024 * 1024)

# 记录捕获开始时间
start_time = time.time()


cpu_usage_total = 0
memory_usage_total = 0
for _ in range(capture_duration):
    cpu_usage_current = tshark_psutil_process.cpu_percent(interval=1)
    memory_usage_current = tshark_psutil_process.memory_info().rss / (1024 * 1024)
    cpu_usage_total += cpu_usage_current
    memory_usage_total += memory_usage_current
    # print(f"Current CPU usage: {cpu_usage_current}%")
    # print(f"Current memory usage: {memory_usage_current} MB")
    # time.sleep(1)

# 捕获后的CPU和内存使用情况
cpu_usage_end = tshark_psutil_process.cpu_percent(interval=1)
memory_usage_end = tshark_psutil_process.memory_info().rss / (1024 * 1024)

# 记录捕获结束时间
end_time = time.time()

# 计算平均的CPU使用率和内存占用
cpu_usage_average = cpu_usage_total / capture_duration
memory_usage_average = memory_usage_total / capture_duration

# 打印结果
print(f"Tshark captured packets for {capture_duration} seconds")
print(f"Average CPU usage during capture: {cpu_usage_average}%")
print(f"Average memory usage during capture: {memory_usage_average} MB")
print(f"Total time taken for capture: {end_time - start_time} seconds")
