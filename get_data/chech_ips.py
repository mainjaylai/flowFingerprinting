import requests
import time

# 从文件读取网站列表
def load_websites(file_path):
    with open(file_path, 'r') as file:
        websites = [line.strip() for line in file if line.strip()]
    return websites

# 检查URL是否可以访问成功
def check_url_access(url):
    try:
        response = requests.get(url, timeout=10)  # 5秒超时限制
        return response.status_code == 200
    except requests.RequestException:
        return False


# 保存结果到文件
def save_to_file(data, output_file):
    with open(output_file, 'w') as file:
        for item in data:
            file.write(item + '\n')


def get_access_url(websites:list):
    access_url = []
    for website in websites:
        print(f"Checking {website}...")
        if check_url_access(website):
            access_url.append(website)
        time.sleep(1)
    return access_url

if __name__ == '__main__':
    websites = load_websites('http_website.txt')
    result = get_access_url(websites)
    save_to_file(result,'access_http_website.txt')
