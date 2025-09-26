"""
Basic Proxy settings for Burp Suite
"""

BURP_PROXY_IP = "127.0.0.1"
BURP_PROXY_PORT = "8080"
BURP_PROXIES = {
    "http": f"http://{BURP_PROXY_IP}:{BURP_PROXY_PORT}",
    "https": f"http://{BURP_PROXY_IP}:{BURP_PROXY_PORT}",
}
