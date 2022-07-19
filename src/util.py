import re

"""
Helper Functions
"""


def strip_subnet(ipv4: str) -> str:
    ipv4 = ipv4.strip()
    try:
        tokens = ipv4.split("/")
        address = tokens[0]
    except:
        address = ipv4
    return address


def ensure_subnet(ipv4: str, default_subnet: str = "24") -> str:
    ipv4 = ipv4.strip()
    try:
        address, subnet = ipv4.split("/")
    except:
        address = ipv4
        subnet = default_subnet
    return f"{address}/{subnet}"


# Regex Match
def regex_match(regex, text):
    pattern = re.compile(regex)
    return pattern.search(text) is not None


# Check IP format
def check_IP(ip):
    ip_patterns = (
        r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}",
        r"[0-9a-fA-F]{0,4}(:([0-9a-fA-F]{0,4})){1,7}$",
    )
    for match_pattern in ip_patterns:
        match_result = regex_match(match_pattern, ip)
        if match_result:
            result = match_result
            break
    else:
        result = None

    return result


# Clean IP
def clean_IP(ip):
    return ip.replace(" ", "")


# Clean IP with range
def clean_IP_with_range(ip):
    return clean_IP(ip).split(",")


# Check IP with range
def check_IP_with_range(ip):
    ip_patterns = (
        r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|\/)){4}([0-9]{1,2})(,|$)",
        r"[0-9a-fA-F]{0,4}(:([0-9a-fA-F]{0,4})){1,7}\/([0-9]{1,3})(,|$)",
    )

    for match_pattern in ip_patterns:
        match_result = regex_match(match_pattern, ip)
        if match_result:
            result = match_result
            break
    else:
        result = None

    return result


# Check allowed ips list
def check_Allowed_IPs(ip):
    ip = clean_IP_with_range(ip)
    for i in ip:
        if not check_IP_with_range(i):
            return False
    return True


# Check DNS
def check_DNS(dns):
    dns = dns.replace(" ", "").split(",")
    status = True
    for i in dns:
        if not (
            check_IP(i)
            or regex_match(
                "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z]{0,61}[a-z]", i
            )
        ):
            return False
    return True


# Check remote endpoint
def check_remote_endpoint(address):
    return check_IP(address) or regex_match(
        "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z]{0,61}[a-z]", address
    )
