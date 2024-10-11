import requests
import threading
import time

# 从文件读取网站列表
def load_websites(file_path):
    with open(file_path, 'r') as file:
        websites = [line.strip() for line in file if line.strip()]
    return websites

# 请求函数，执行对网站的20次请求
def make_requests(url, times=20, delay=3):
    for i in range(times):
        try:
            response = requests.get(url)
            print(f"Request {i+1} for {url}: Status Code: {response.status_code}")
        except Exception as e:
            print(f"Request {i+1} for {url} failed: {e}")
        time.sleep(delay)

# 线程管理函数
def start_threads(websites):
    threads = []
    
    # 为每个网站启动一个线程
    for website in websites:
        thread = threading.Thread(target=make_requests, args=(website,))
        threads.append(thread)
        thread.start()

    # 等待所有线程执行完成
    for thread in threads:
        thread.join()

# 执行程序
if __name__ == "__main__":
    websites = ['http://202.90.110.33', 'http://103.37.152.41', 'http://124.251.6.133', 'http://47.94.77.63', 'http://59.82.31.200', 'http://207.7.95.126', 'http://203.119.169.39', 'http://61.135.169.125', 'http://220.181.38.148', 'http://120.27.234.115']  # 从文件加载网站
    start_threads(websites)
