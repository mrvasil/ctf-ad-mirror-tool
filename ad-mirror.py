import os
import sys
import subprocess
import configparser
from dotenv import load_dotenv
import ast
import signal
import time

def load_config():
    load_dotenv()
    
    try:
        allowed_ips = ast.literal_eval(os.getenv('allowed_ips', '[]'))
        access_enabled = os.getenv('access', 'True').lower() == 'true'
    except:
        print("Error parsing allowed_ips from .env")
        sys.exit(1)

    config = configparser.ConfigParser()
    with open('.env') as f:
        config.read_string('[global]\n' + f.read())

    tasks = []
    for section in config.sections():
        if section != 'global' and config.has_option(section, 'forward_ip') and config.has_option(section, 'port'):
            tasks.append({
                'name': section,
                'forward_ip': config[section]['forward_ip'],
                'port': config[section]['port']
            })

    return {
        'allowed_ips': allowed_ips,
        'access_enabled': access_enabled,
        'tasks': tasks
    }

def start_proxies(config):
    processes = []
    print(f"Allowed IPs: \033[1;33m{config["allowed_ips"]}\033[0m")
    print(f"Public access enabled: \033[1;{'32' if config['access_enabled'] else '31'}m{config['access_enabled']}\033[0m")

    for task in config['tasks']:
        cmd = [
            'python3',
            'main.py',
            str(task['port']),
            task['forward_ip'],
            '--allowed-ips', str(config['allowed_ips']),
            '--access', str(config['access_enabled']).lower()
        ]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append({
            'name': task['name'],
            'process': process,
            'config': task
        })
        print(f"Started \033[1;32m{task['name']}\033[0m proxy on port \033[1;33m{task['port']}\033[0m -> \033[1;33m{task['forward_ip']}\033[0m")

    return processes

def monitor_processes(processes, config):
    try:
        while True:
            for p in processes:
                if p['process'].poll() is not None:
                    print(f"Process {p['name']} died, restarting...")
                    cmd = [
                        'python3',
                        'main.py',
                        str(p['config']['port']),
                        p['config']['forward_ip'],
                        '--allowed-ips', str(config['allowed_ips']),
                        '--access', str(config['access_enabled']).lower()
                    ]
                    p['process'] = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping all proxies...")
        for p in processes:
            p['process'].send_signal(signal.SIGTERM)
            p['process'].wait()

def main():
    config = load_config()
    processes = start_proxies(config)
    monitor_processes(processes, config)

if __name__ == '__main__':
    main()