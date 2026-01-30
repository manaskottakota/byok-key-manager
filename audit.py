# audit.py
import os
from datetime import datetime
from typing import Optional

AUDIT_LOG_FILE = "data/audit.log"

def log(action: str, key_id: str, app_name: Optional[str], success: bool) -> None:
    """Write timestamp, action, key_id, app_name, result to audit.log"""
    os.makedirs("data", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "DENIED"
    app = app_name if app_name else "None"
    
    log_entry = f"{timestamp} | {action} | {key_id} | {app} | {status}\n"
    
    with open(AUDIT_LOG_FILE, 'a') as f:
        f.write(log_entry)