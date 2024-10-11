# -*- coding: utf-8 -*-

# sudo systemd-resolve --flush-caches
#  systemd-resolve --statistics

import random
import string
import argparse

def generate_random_domains(n):
    domains = []
    tlds = ['com', 'net', 'org', 'io', 'tech']  # 顶级域名列表

    for _ in range(n):
        # 随机生成域名长度在 5 到 10 个字符之间
        domain_length = random.randint(5, 10)
        # 随机生成域名
        domain_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=domain_length))
        # 随机选择顶级域名
        tld = random.choice(tlds)
        # 生成完整的域名
        full_domain = f"{domain_name}.{tld}"
        domains.append(full_domain)

    return domains

def main():
    parser = argparse.ArgumentParser(description="Generate random domain names.")
    parser.add_argument('-n', type=int, default=100, help="Number of domains to generate (default: 100)")
    
    args = parser.parse_args()
    n = args.n

    random_domains = generate_random_domains(n)
    
    # 将域名写入文件
    with open('queries.txt', 'w') as f:
        for domain in random_domains:
            f.write(f"www.{domain} A\n")

    print(f"{n} domains have been written to queriers.txt")

if __name__ == "__main__":
    main()
