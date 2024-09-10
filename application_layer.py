from transport_layer import TcpFlow

class HttpFlow(TcpFlow):
    def __init__(self):
        super().__init__()
        self.method = None  # HTTP 请求方法（GET, POST 等）
        self.uri = None  # 请求的 URI
        self.version = None  # HTTP 版本
        self.status_code = None  # HTTP 响应状态码
        self.headers = {}  # HTTP 头部信息

    def add_http_info(self, packet):
        """
        从数据包中提取 HTTP 信息
        
        Args:
            packet: 包含 HTTP 信息的数据包
        """
        super().add_tcp_info(packet)
        if hasattr(packet, "http"):
            http = packet.http
            for field in http.field_names:
                value = getattr(http, field)
                if value:
                    self.headers[field] = value
            
            self.method = self.headers.get("request_method")
            self.uri = self.headers.get("request_uri")
            self.version = self.headers.get("request_version")
            self.status_code = self.headers.get("response_code")

class SmtpFlow(TcpFlow):
    def __init__(self):
        super().__init__()
        self.command = None  # SMTP 命令
        self.response_code = None  # SMTP 响应代码
        self.mail_from = None  # 发件人地址
        self.rcpt_to = []  # 收件人地址列表
        self.headers = {}  # SMTP 头部信息

    def add_smtp_info(self, packet):
        """
        从数据包中提取 SMTP 信息
        
        Args:
            packet: 包含 SMTP 信息的数据包
        """
        super().add_tcp_info(packet)
        if hasattr(packet, "smtp"):
            smtp = packet.smtp
            self.command = getattr(smtp, "command", None)
            self.response_code = getattr(smtp, "response_code", None)
            
            if hasattr(smtp, "mail_from"):
                self.mail_from = smtp.mail_from
            if hasattr(smtp, "rcpt_to"):
                self.rcpt_to.append(smtp.rcpt_to)
            
            for field in smtp.field_names:
                value = getattr(smtp, field)
                if value:
                    self.headers[field] = value

class FtpFlow(TcpFlow):
    def __init__(self):
        super().__init__()
        self.command = None  # FTP 命令
        self.response_code = None  # FTP 响应代码
        self.file_name = None  # 传输的文件名
        self.file_size = None  # 传输的文件大小
        self.headers = {}  # FTP 头部信息

    def add_ftp_info(self, packet):
        """
        从数据包中提取 FTP 信息
        
        Args:
            packet: 包含 FTP 信息的数据包
        """
        super().add_tcp_info(packet)
        if hasattr(packet, "ftp"):
            ftp = packet.ftp
            self.command = getattr(ftp, "command", None)
            self.response_code = getattr(ftp, "response_code", None)
            
            if hasattr(ftp, "file_name"):
                self.file_name = ftp.file_name
            if hasattr(ftp, "file_size"):
                self.file_size = ftp.file_size
            
            for field in ftp.field_names:
                value = getattr(ftp, field)
                if value:
                    self.headers[field] = value