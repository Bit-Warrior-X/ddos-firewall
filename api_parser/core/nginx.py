# core/nginx.py
"""Nginx configuration management service."""
import os
import shutil
from typing import Tuple, List
from core.nginx_ops import nginx_test, nginx_reload
from utils.nginx_utils import backup_path, write_atomic, remove_backup

class NginxConfigManager:
    """Manages nginx configuration updates with atomic writes."""
    
    @staticmethod
    def update_config(
        config_path: str,
        new_content: str,
        test_before_reload: bool = True
    ) -> Tuple[bool, str]:
        """Atomically update nginx config with backup and rollback."""
        backup = None
        try:
            if os.path.exists(config_path):
                backup = backup_path(config_path)
                shutil.copy2(config_path, backup)
            
            write_atomic(config_path, new_content)
            
            if test_before_reload:
                ok_test, test_msg = nginx_test()
                if not ok_test:
                    if backup and os.path.exists(backup):
                        shutil.copy2(backup, config_path)
                    remove_backup(backup)
                    return False, test_msg
            
            ok_reload, reload_msg = nginx_reload()
            if not ok_reload:
                remove_backup(backup)
                return False, reload_msg
            
            remove_backup(backup)
            return True, "Configuration updated successfully"
            
        except Exception as e:
            if backup and os.path.exists(backup):
                try:
                    shutil.copy2(backup, config_path)
                except Exception:
                    pass
            remove_backup(backup)
            return False, f"Failed to update config: {str(e)}"
    
    @staticmethod
    def update_multiple_configs(
        configs: List[Tuple[str, str]]
    ) -> Tuple[bool, str]:
        """Update multiple config files atomically."""
        backups = []
        
        try:
            for path, _ in configs:
                if os.path.exists(path):
                    backup = backup_path(path)
                    shutil.copy2(path, backup)
                    backups.append((path, backup))
            
            for path, content in configs:
                write_atomic(path, content)
            
            ok_test, test_msg = nginx_test()
            if not ok_test:
                for path, backup in backups:
                    if os.path.exists(backup):
                        shutil.copy2(backup, path)
                        remove_backup(backup)
                return False, test_msg
            
            ok_reload, reload_msg = nginx_reload()
            if not ok_reload:
                for _, backup in backups:
                    remove_backup(backup)
                return False, reload_msg
            
            for _, backup in backups:
                remove_backup(backup)
            return True, "All configurations updated successfully"
            
        except Exception as e:
            for path, backup in backups:
                if os.path.exists(backup):
                    try:
                        shutil.copy2(backup, path)
                    except Exception:
                        pass
                remove_backup(backup)
            return False, f"Failed to update configs: {str(e)}"

