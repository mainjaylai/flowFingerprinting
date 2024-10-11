# -*- coding: utf-8 -*-

# sudo systemd-resolve --flush-caches
#  systemd-resolve --statistics

import random
import string
import argparse

def generate_random_domains(n):
    domains = []

    for _ in range(n):
        domain = '.'.join(str(random.randint(0, 255)) for _ in range(4))
        domains.append(domain)

    return domains

def main():
    parser = argparse.ArgumentParser(description="Generate random domain names.")
    parser.add_argument('-n', type=int, default=100, help="Number of domains to generate (default: 100)")
    
    args = parser.parse_args()
    n = args.n

    random_domains = generate_random_domains(n)
    
    # 将域名写入文件
    with open('hosts.txt', 'w') as f:
        for domain in random_domains:
            f.write(f"{domain}\n")

    print(f"{n} domains have been written to hosts.txt")

if __name__ == "__main__":
    main()
