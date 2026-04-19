import socket
import threading
import os

SRV_ADDR = '127.0.0.2'
SRV_PORT = 8080
BAN_LIST_PATH = 'blacklist.txt'
RECV_BUFFER = 4096
MAX_QUEUED = 15
NET_ENCODING = 'iso-8859-1'

output_lock = threading.Lock()


def log_msg(content):
    with output_lock:
        print(content)


def get_banned_sites(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        return [ln.strip().lower() for ln in f if ln.strip()]


def split_http_request(raw_text):
    first_ln = raw_text.split('\r\n')[0]
    tokens = first_ln.split()
    if len(tokens) != 3:
        return None, None, None
    return tokens[0], tokens[1], tokens[2]  # verb, url, proto_ver


def get_remote_info(url_string):
    if not url_string.startswith('http://'):
        return None

    clean_url = url_string[len('http://'):]
    split_pos = clean_url.find('/')

    if split_pos == -1:
        addr_port = clean_url
        uri_path = '/'
    else:
        addr_port = clean_url[:split_pos]
        uri_path = clean_url[split_pos:]

    if ':' in addr_port:
        domain, port_val = addr_port.split(':', 1)
        return domain, int(port_val), uri_path

    return addr_port, 80, uri_path


def modify_headers(raw_text, verb, uri_path, proto_ver):
    lines = raw_text.split('\r\n')
    out_lines = [f'{verb} {uri_path} {proto_ver}']
    conn_fixed = False

    for ln in lines[1:]:
        if ln == '': continue
        low_ln = ln.lower()

        if low_ln.startswith('proxy-connection:'):
            continue

        if low_ln.startswith('connection:'):
            out_lines.append('Connection: close')
            conn_fixed = True
            continue

        out_lines.append(ln)

    if not conn_fixed:
        out_lines.append('Connection: close')

    return '\r\n'.join(out_lines) + '\r\n\r\n'


def relay_data(outgoing_req, remote_ip, remote_port, client_conn, full_url):
    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote_sock.connect((remote_ip, remote_port))
        remote_sock.sendall(outgoing_req.encode(NET_ENCODING))

        head_chunk = remote_sock.recv(RECV_BUFFER)
        if not head_chunk:
            if not full_url.endswith('/favicon.ico'):
                log_msg(f'{full_url} – empty response')
            return

        try:
            resp_txt = head_chunk.decode(NET_ENCODING, errors='replace')
            status_ln = resp_txt.split('\r\n')[0]
            status_info = ' '.join(status_ln.split()[1:])
            if not full_url.endswith('/favicon.ico'):
                log_msg(f'{full_url} – {status_info}')
        except:
            pass

        client_conn.sendall(head_chunk)

        while True:
            chunk = remote_sock.recv(RECV_BUFFER)
            if not chunk: break
            client_conn.sendall(chunk)
    finally:
        remote_sock.close()


class HttpProxyController:
    def __init__(self, ip, port, banned_list):
        self.ip = ip
        self.port = port
        self.banned = banned_list
        self.main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.main_sock.bind((self.ip, self.port))

    def activate(self):
        self.main_sock.listen(MAX_QUEUED)
        log_msg(f'Прокси сервер запущен на: {self.ip}:{self.port}')

        while True:
            c_sock, c_addr = self.main_sock.accept()
            worker = threading.Thread(
                target=self.process_request,
                args=(c_sock, c_addr),
                daemon=True
            )
            worker.start()

    def process_request(self, c_sock, c_addr):
        try:
            raw_content = b''
            while b'\r\n\r\n' not in raw_content:
                buf = c_sock.recv(RECV_BUFFER)
                if not buf: break
                raw_content += buf
                if len(raw_content) > 100000: break

            if not raw_content: return

            decoded_text = raw_content.decode(NET_ENCODING, errors='replace')
            vrb, target, ver = split_http_request(decoded_text)

            if target is None: return

            dest_info = get_remote_info(target)
            if dest_info is None: return

            host_val, port_val, path_val = dest_info

            is_banned = False
            for pattern in self.banned:
                if pattern in target.lower():
                    is_banned = True
                    break

            if is_banned:
                if not target.endswith('/favicon.ico'):
                    log_msg(f'{target} – [ACCESS DENIED]')

                err_body = f"<html><body><h1>403 Forbidden</h1><p>URL {target} is blocked.</p></body></html>"
                err_res = (f"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                           f"Content-Length: {len(err_body)}\r\nConnection: close\r\n\r\n{err_body}")
                c_sock.sendall(err_res.encode())
                return

            final_req = modify_headers(decoded_text, vrb, path_val, ver)
            relay_data(final_req, host_val, port_val, c_sock, target)

        except Exception:
            pass
        finally:
            c_sock.close()


if __name__ == '__main__':
    banned_sites = get_banned_sites(BAN_LIST_PATH)
    app = HttpProxyController(SRV_ADDR, SRV_PORT, banned_sites)
    app.activate()