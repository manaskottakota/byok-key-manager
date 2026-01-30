import json
import os
from typing import Dict, List


PERMISSIONS_FILE = "data/permissions.json"

def _load_permissions() -> Dict[str, List[str]]:
    """load permissions from storage"""

    if not os.path.exists(PERMISSIONS_FILE):
        return {}
    
    with open(PERMISSIONS_FILE, 'r') as f:
        return json.load(f)


def _save_permissions(permissions: Dict[str, List[str]]) -> None:
    """save permissions to storage"""
    os.makedirs("data", exist_ok = True)

    with open(PERMISSIONS_FILE, 'w') as f:
        json.dump(permissions, f, indent=2)


def authorize_app(app_name: str, key_id: str) -> None:
    """grant app permission to use a key"""
    permissions = _load_permissions()
    
    if app_name not in permissions:
        permissions[app_name] = []
    
    if key_id not in permissions[app_name]:
        permissions[app_name].append(key_id)
    
    _save_permissions(permissions)


def check_access(app_name: str, key_id: str) -> bool:
    """verify if app can use key"""
    permissions = _load_permissions()
    
    if app_name not in permissions:
        return False
    
    return key_id in permissions[app_name]