# core/fifo_worker.py
"""FIFO reader worker for processing firewall commands."""
import os
import threading
import time
from typing import Dict, List
from core.api_client import APIClient
import config

def parse_fifo_message(raw_data: str) -> List[Dict[str, str]]:
    """Parses raw FIFO data into command dictionaries."""
    commands = []
    current_command = {}
    
    for line in raw_data.split('\n'):
        line = line.strip()
        if not line:
            continue
            
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            
            if key == 'command':
                if current_command:
                    commands.append(current_command)
                current_command = {'command': value}
            else:
                current_command[key] = value
    
    if current_command:
        commands.append(current_command)
    
    return commands

def process_command(cmd: Dict[str, str]) -> None:
    """Processes a single command dictionary."""
    try:
        if cmd['command'] == 'report_log':
            payload = {
                'type': str(cmd.get('type', 'unknown')),
                'data': str(cmd.get('data', ''))
            }
            APIClient.send_report_log(payload)
        elif cmd['command'] == 'check_blocklist':
            payload = {
                'status': str(cmd.get('status', 'unknown'))
            }
            APIClient.check_blocklist(payload)
        else:
            print(f"[API_PARSER] Unknown command: {cmd['command']}")
    except Exception as e:
        print(f"[API_PARSER] Error processing command {cmd}: {str(e)}")

def fifo_reader_thread():
    """FIFO reader thread function."""
    if not os.path.exists(config.FIFO_PATH):
        os.mkfifo(config.FIFO_PATH)
    print(f"... listening at {config.FIFO_PATH}")
    while True:
        try:
            with open(config.FIFO_PATH, 'r') as fifo:
                buf = []
                for line in fifo:
                    line = line.rstrip('\n')
                    if line == "":  # delimiter between commands
                        raw = "\n".join(buf).strip()
                        if raw:
                            for cmd in parse_fifo_message(raw):
                                process_command(cmd)
                        buf = []
                    else:
                        buf.append(line)
        except Exception as e:
            print(f"[API_PARSER] FIFO error: {e}; retrying in 1s")
            time.sleep(1)

def start_fifo_listener():
    """Start the FIFO reader thread."""
    thread = threading.Thread(target=fifo_reader_thread, daemon=True)
    thread.start()
    return thread

