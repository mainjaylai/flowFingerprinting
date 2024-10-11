import time
import psutil
import subprocess

capture_duration = 60
# 启动 tcpdump 进程捕获 HTTP 流量
# tcpdump -i enp0s8 udp -w tcpdump_output.pcap
tcpdump_command = ["tcpdump", "-i", "enp0s8", "udp port 53", "-w", "tcpdump_output.pcap"]
tcpdump_process = subprocess.Popen(tcpdump_command)

# 等待 tcpdump 进程启动
time.sleep(1)

# 获取 tcpdump 进程的 psutil.Process 对象
tcpdump_pid = tcpdump_process.pid
tcpdump_psutil_process = psutil.Process(tcpdump_pid)

# 捕获期间的CPU和内存使用情况
cpu_usage_start = psutil.cpu_percent(interval=1)
memory_usage_start = tcpdump_psutil_process.memory_info().rss / (1024 * 1024)

# 记录捕获开始时间
start_time = time.time()

# 监控 tcpdump 进程持续时间

while time.time() - start_time < capture_duration:
    cpu_usage_current = psutil.cpu_percent(interval=1)
    memory_usage_current = tcpdump_psutil_process.memory_info().rss / (1024 * 1024)
    # print(f"Current CPU usage: {cpu_usage_current}%")
    # print(f"Current memory usage: {memory_usage_current} MB")
    # time.sleep(1)

# 捕获结束后的CPU和内存使用情况
cpu_usage_end = psutil.cpu_percent(interval=1)
memory_usage_end = tcpdump_psutil_process.memory_info().rss / (1024 * 1024)

# 记录捕获结束时间
end_time = time.time()

# 终止 tcpdump 进程
tcpdump_process.terminate()

# 计算总的CPU使用率和内存占用
cpu_usage_total = (cpu_usage_end - cpu_usage_start) / capture_duration
memory_usage_total = memory_usage_end - memory_usage_start

# 打印结果
print(f"tcpdump captured packets for {capture_duration} seconds")
print(f"Total CPU usage during capture: {cpu_usage_total}%")
print(f"Total memory usage during capture: {memory_usage_total} MB")
print(f"Total time taken for capture: {end_time - start_time} seconds")
