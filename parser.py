import pyshark
from urllib.parse import urlparse, parse_qs

def parse_pcap(pcap_path):
    records = []
    try:
        cap = pyshark.FileCapture(pcap_path, display_filter='http.request')
        for pkt in cap:
            try:
                http = pkt.http
                method = getattr(http, 'request_method', '')
                host = getattr(http, 'host', '')
                uri = getattr(http, 'request_uri', '')
                full = ''
                if host and uri:
                    full = f'http://{host}{uri}'
                elif hasattr(http, 'request_full_uri'):
                    full = getattr(http, 'request_full_uri')
                user_agent = getattr(http, 'user_agent', '')
                params = {}
                if '?' in uri:
                    path, q = uri.split('?',1)
                    params = parse_qs(q, keep_blank_values=True)
                body = getattr(http, 'file_data', '') or ''
                rec = {'src_ip': pkt.ip.src if hasattr(pkt, 'ip') else '',
                       'dst_ip': pkt.ip.dst if hasattr(pkt, 'ip') else '',
                       'method': method,
                       'url': full,
                       'params': params,
                       'user_agent': user_agent,
                       'body': body,
                       'raw': full + ' ' + str(params) + ' ' + (body or '')}
                records.append(rec)
            except Exception:
                continue
        cap.close()
    except Exception as e:
        print('pyshark parse error:', e)
    return records

import re
def parse_access_log(log_path):
    pattern = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" (?P<status>\d+) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')
    records = []
    with open(log_path, 'r', errors='ignore') as f:
        for line in f:
            m = pattern.match(line)
            if not m:
                continue
            ip = m.group('ip')
            method = m.group('method')
            path = m.group('path')
            ua = m.group('ua')
            params = {}
            if '?' in path:
                p, q = path.split('?',1)
                from urllib.parse import parse_qs
                params = parse_qs(q, keep_blank_values=True)
            rec = {'src_ip': ip, 'dst_ip': '', 'method': method, 'url': path, 'params': params, 'user_agent': ua, 'body':'', 'raw': path}
            records.append(rec)
    return records
