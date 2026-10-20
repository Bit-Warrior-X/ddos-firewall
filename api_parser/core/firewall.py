# core/firewall.py
"""L4 firewall service operations."""
import subprocess
from typing import Dict, Optional

def parse_cli_output(output: str) -> Dict[str, str]:
    """Parse CLI output where first line is status."""
    lines = output.strip().splitlines()
    if not lines:
        return {'status': 'error', 'message': 'Empty response from command'}

    first = lines[0].strip().split(':', 1)[0].lower()
    if first == 'ok':
        status = 'success'
    elif first == 'failed':
        status = 'error'
    else:
        return {'status': 'error', 'message': 'Unexpected response format'}

    message = '\n'.join(lines[1:]) if len(lines) > 1 else ''
    return {'status': status, 'message': message}

def execute_cli_command(command_args: list) -> Dict[str, str]:
    """Execute CLI command and return parsed result."""
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            check=False,
            timeout=30
        )
        output = result.stdout.strip()
        if not output:
            if result.returncode == 0:
                return {'status': 'success', 'message': ''}
            error_msg = result.stderr.strip() or 'Command failed with no output'
            return {'status': 'error', 'message': error_msg}
        return parse_cli_output(output)
    except subprocess.TimeoutExpired:
        return {'status': 'error', 'message': 'Command timed out'}
    except Exception as e:
        return {'status': 'error', 'message': f'Unexpected error: {str(e)}'}

def firewall_control(action: str, interface: str, attach_mode: str = 'native') -> Dict[str, str]:
    """Control firewall (start/stop/restart/reload)."""
    actions = {
        'start': 'START_FW',
        'stop': 'STOP_FW',
        'restart': 'RESTART_FW',
        'reload': 'RELOAD_FW'
    }
    
    if action not in actions:
        return {
            'status': 'error',
            'message': f"Invalid action. Valid actions: {', '.join(actions.keys())}"
        }
    
    command_args = ['sparta_cli', actions[action], interface, attach_mode]
    return execute_cli_command(command_args)

def set_protection(
    protection_type: str,
    status: str,
    threshold: int,
    burst_pkt: int,
    burst_counter: int,
    fixed_threshold: int,
    fixed_duration: int,
    protection_duration: int,
    challenge_timeout: Optional[int] = None
) -> Dict[str, str]:
    """Set protection parameters for various attack types."""
    command_args = ['sparta_cli', protection_type, status, 
                   str(threshold), str(burst_pkt), str(burst_counter),
                   str(fixed_threshold), str(fixed_duration)]
    
    if challenge_timeout is not None:
        command_args.extend([str(challenge_timeout)])
    
    command_args.append(str(protection_duration))
    return execute_cli_command(command_args)

def set_socket_protection(
    status: str,
    fin_threshold: int,
    fixed_threshold: int,
    fixed_duration: int
) -> Dict[str, str]:
    """Set SOCKET defense. This is a fixed window, not a flood mode."""
    command_args = ['sparta_cli', 'TCP_SOCKET', status,
                    str(fin_threshold), str(fixed_threshold), str(fixed_duration)]
    return execute_cli_command(command_args)

def health_check() -> Dict[str, str]:
    """Perform firewall health check."""
    command_args = ['sparta_cli', 'HEALTH_CHECK']
    return execute_cli_command(command_args)

