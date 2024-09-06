from transport_layer import TcpFlow

class HttpFlow(TcpFlow):
    def __init__(self):
        super().__init__()
        self.method = None
        self.uri = None
        self.version = None
        self.status_code = None
        self.headers = {}

    def add_http_info(self, packet):
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
        self.command = None
        self.response_code = None
        self.mail_from = None
        self.rcpt_to = []
        self.headers = {}

    def add_smtp_info(self, packet):
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
        self.command = None
        self.response_code = None
        self.file_name = None
        self.file_size = None
        self.headers = {}

    def add_ftp_info(self, packet):
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