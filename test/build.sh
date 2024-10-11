sudo apt-get update

# 安装 Python 3.8
sudo apt-get install -y python3.8 python3.8-venv python3.8-dev

# 安装 pip
sudo apt-get install -y python3-pip

# 创建 python3.8 的软链接
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1

# 安装python包
sudo apt-get install build-essential libffi-dev python-dev
sudo /usr/bin/python3.8 -m pip install scapy psutil cffi dnsgen cicflowmeter flowprint scapy

# flowprint 相关依赖
sudo /usr/bin/python3.8 -m pip install argformat scikit-learn


# 安装 fping
sudo apt install fping

# download tshark
sudo apt install tshark libpcap-dev pkg-config libssl-dev libck-dev libnghttp2-dev -y

# 安装dnsperf
wget https://www.dns-oarc.net/files/dnsperf/dnsperf-2.14.0.tar.gz
tar -xzvf dnsperf-2.14.0.tar.gz
cd dnsperf-2.14.0/
./configure
make
sudo make install

# 安装tomcat
sudo apt install openjdk-11-jdk -y
cd /tmp
wget https://downloads.apache.org/tomcat/tomcat-9/v9.0.95/bin/apache-tomcat-9.0.95.tar.gz
sudo mkdir /opt/tomcat
sudo tar -xvzf apache-tomcat-9.0.95.tar.gz -C /opt/tomcat --strip-components=1
# 创建 Tomcat 用户和组
sudo groupadd tomcat
sudo useradd -s /bin/false -g tomcat -d /opt/tomcat tomcat
# 设置权限
sudo chown -R tomcat:tomcat /opt/tomcat
sudo chmod -R 755 /opt/tomcat
sudo bash -c 'cat <<EOL > /etc/systemd/system/tomcat.service
[Unit]
Description=Apache Tomcat Web Application Container
After=network.target

[Service]
Type=forking

# Environment=JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
Environment=CATALINA_PID=/opt/tomcat/temp/tomcat.pid
Environment=CATALINA_HOME=/opt/tomcat
Environment=CATALINA_BASE=/opt/tomcat
Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"
Environment="JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"

ExecStart=/opt/tomcat/bin/startup.sh
ExecStop=/opt/tomcat/bin/shutdown.sh

User=tomcat
Group=tomcat
UMask=0007
RestartSec=10
Restart=always

[Install]
WantedBy=multi-user.target
EOL'
# 重新加载 systemd 守护进程并启动 Tomcat 服务
sudo systemctl daemon-reload
sudo systemctl enable tomcat
sudo systemctl start tomcat
# 检查 Tomcat 服务状态
sudo systemctl status tomcat

# 清理dns缓存
sudo systemctl restart systemd-resolved
sudo systemd-resolve --flush-caches


