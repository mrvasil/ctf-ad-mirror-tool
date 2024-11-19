from flask import Flask, request, Response, abort, render_template_string
import argparse
import re
import random
import string
import requests
from urllib.parse import unquote
import csv
import os

app = Flask(__name__, static_folder=None)

def load_flags():
    flags_dict = {}
    if os.path.exists('flags.csv'):
        with open('flags.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                flags_dict[row['flag']] = {
                    'key': row['key'],
                    'encrypted': row['encrypted']
                }
    return flags_dict

def save_flag(flag, key, encrypted):
    file_exists = os.path.exists('flags.csv')
    with open('flags.csv', 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['flag', 'key', 'encrypted'])
        if not file_exists:
            writer.writeheader()
        writer.writerow({
            'flag': flag,
            'key': key,
            'encrypted': encrypted
        })

def encrypt_flag(flag):
    flags_dict = load_flags()
    if flag in flags_dict:
        print("\033[1;33m" + f"[!] Using existing encryption for flag: {flag}" + "\033[0m")
        return flags_dict[flag]['encrypted']
    
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    encrypted = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(flag, key * (len(flag) // len(key) + 1)))
    encrypted = encrypted.encode('utf-8').hex()
    
    save_flag(flag, key, encrypted)
    print("\033[1;31m" + f"[!] Flag received: {flag}" + "\033[0m")
    
    return encrypted

def decrypt_flag(encrypted_flag):
    flags_dict = load_flags()
    
    for flag, flag_data in flags_dict.items():
        if flag_data['encrypted'] == encrypted_flag:
            print("\033[1;33m" + f"[!] Flag decrypted: {flag}" + "\033[0m")
            return flag
    
    return encrypted_flag

def encrypt_body(request):
    headers = dict(request.headers)
    body = request.get_data().decode('utf-8', errors='ignore')

    try:
        decoded_body = unquote(body)
    except:
        decoded_body = body
            
    flag_pattern = r'[A-Z0-9]{31}='
            
    for header, value in headers.items():
        decoded_value = unquote(str(value))
        for check_value in [str(value), decoded_value]:
            flags = re.findall(flag_pattern, check_value)
            for flag in flags:
                encrypted = encrypt_flag(flag)
                headers[header] = headers[header].replace(flag, encrypted)
            
    flags = re.findall(flag_pattern, decoded_body)
    for flag in flags:
        encrypted = encrypt_flag(flag)
        decoded_body = decoded_body.replace(flag, encrypted)

    return headers, decoded_body

def decrypt_response(response):
    response_content = response.content.decode('utf-8', errors='ignore')

    flags_dict = load_flags()
    for flag_data in flags_dict.values():
        encrypted_flag = flag_data['encrypted']
        if encrypted_flag in response_content:
            response_content = response_content.replace(
                encrypted_flag,
                decrypt_flag(encrypted_flag)
            )

    response_headers = dict(response.headers)
    for header, value in response_headers.items():
        for flag_data in flags_dict.values():
            encrypted_flag = flag_data['encrypted']
            if encrypted_flag in str(value):
                response_headers[header] = str(value).replace(
                    encrypted_flag,
                    decrypt_flag(encrypted_flag)
                )
    return response_headers, response_content
    
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])
def proxy(path):
    target_ip = app.config['TARGET_IP']
    port = app.config['PORT']
    
    is_allowed = True
    if app.config.get('ALLOWED_IP'):
        client_ip = request.remote_addr
        is_allowed = client_ip == app.config['ALLOWED_IP']

    if is_allowed:
        headers, body = encrypt_body(request)
    else:
        headers = request.headers
        body = request.get_data().decode('utf-8', errors='ignore')

    url = f'http://{target_ip}:{port}/{path}'
    print(url)
    response = requests.request(
        method=request.method,
        url=url,
        headers=headers,
        data=body.encode() if body else None,
        allow_redirects=False,
        stream=True
    )

    if is_allowed:
        response_headers, response_content = decrypt_response(response)
    else:
        response_headers = response.headers
        response_content = response.content.decode('utf-8', errors='ignore')
    
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in response_headers.items()
              if name.lower() not in excluded_headers]
    
    return Response(
        response_content,
        response.status_code,
        headers
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int, help='Port to listen on')
    parser.add_argument('target_ip', help='Target IP to forward requests to')
    parser.add_argument('--allowed-ip', help='IP address allowed to access the proxy')
    args = parser.parse_args()
    
    app.config['TARGET_IP'] = args.target_ip
    app.config['PORT'] = args.port
    app.config['ALLOWED_IP'] = args.allowed_ip

    print(f"Starting proxy server on port {args.port}")
    print(f"Forwarding requests to {args.target_ip}:{args.port}")
    
    app.run(host='0.0.0.0', port=args.port)

if __name__ == '__main__':
    main()