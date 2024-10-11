import socket
import requests

# 从文件读取网站列表
def load_websites(file_path):
    with open(file_path, 'r') as file:
        websites = [line.strip() for line in file if line.strip()]
    return websites

# 获取域名对应的IP地址
def get_ip_address(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

# 从URL中提取域名部分
def extract_domain(url):
    # 去掉https:// 或 http:// 前缀
    if url.startswith("https://"):
        url = url[len("https://"):]
    elif url.startswith("http://"):
        url = url[len("http://"):]
    
    # 去掉路径部分
    if "/" in url:
        url = url.split('/')[0]
    
    return url

# 检查URL是否可以访问成功
def check_url_access(url):
    try:
        response = requests.get(url, timeout=10)  # 5秒超时限制
        return response.status_code == 200
    except requests.RequestException:
        return False

# 主函数：先检查HTTPS网站可访问性，再解析IP并拼接成http://IP
def convert_to_http_ip_and_check_access(websites):
    accessible_ips = []
    inaccessible_websites = []
    
    for website in websites:
        # 检查HTTPS网站的可访问性
        print(f"Checking {website}...")
        if check_url_access(website):
            domain = extract_domain(website)
            ip_address = get_ip_address(domain)
            
            if ip_address:
                http_ip = f"http://{ip_address}"
                print(f"Accessing {http_ip}...")
                accessible_ips.append(http_ip)
            else:
                inaccessible_websites.append(website)
                print(f"Failed to resolve {website}.")
        else:
            inaccessible_websites.append(website)
            print(f"{website} is NOT accessible.")
    
    return accessible_ips, inaccessible_websites

# 保存结果到文件
def save_to_file(data, output_file):
    with open(output_file, 'w') as file:
        for item in data:
            file.write(item + '\n')

# 执行程序
if __name__ == "__main__":
    websites = load_websites('https_website.txt')  # 从文件加载HTTPS网站
    accessible_ips, inaccessible_websites = convert_to_http_ip_and_check_access(websites)  # 解析并检查访问
    save_to_file(accessible_ips, 'accessible_http_ips.txt')  # 将可访问的结果保存到文件中
    save_to_file(inaccessible_websites, 'inaccessible_websites.txt')  # 将不可访问的网站保存到文件中
