# main.py
import sys
from typing import List
from key_store import create_key, get_key, rotate_key, revoke_key
from access import authorize_app, check_access
from crypto import encrypt_data, decrypt_data
from audit import log

def execute_command(command: str, args: List[str]) -> None:
    """Execute a single command"""
    try:
        if command == "generate":
            # generate <key_id>
            key_id = args[0]
            create_key(key_id)
            log("generate", key_id, None, True)
            print(f"✓ Key '{key_id}' generated")
        
        elif command == "encrypt":
            # encrypt <key_id> <plaintext>
            key_id = args[0]
            plaintext = " ".join(args[1:])  # Join rest as plaintext
            key = get_key(key_id)
            ciphertext = encrypt_data(key, plaintext)
            log("encrypt", key_id, None, True)
            print(f"✓ Encrypted: {ciphertext.decode('utf-8')}")
        
        elif command == "decrypt":
            # decrypt <key_id> <ciphertext> <app_name>
            key_id = args[0]
            ciphertext = args[1]
            app_name = args[2] if len(args) > 2 else None
            
            # Check authorization
            if app_name and not check_access(app_name, key_id):
                log("decrypt", key_id, app_name, False)
                print(f"✗ Access denied: {app_name} cannot use key '{key_id}'")
                return
            
            key = get_key(key_id)
            plaintext = decrypt_data(key, ciphertext.encode('utf-8'))
            log("decrypt", key_id, app_name, True)
            print(f"✓ Decrypted: {plaintext}")
        
        elif command == "rotate":
            # rotate <key_id>
            key_id = args[0]
            rotate_key(key_id)
            log("rotate", key_id, None, True)
            print(f"✓ Key '{key_id}' rotated to new version")
        
        elif command == "revoke":
            # revoke <key_id>
            key_id = args[0]
            revoke_key(key_id)
            log("revoke", key_id, None, True)
            print(f"✓ Key '{key_id}' revoked")
        
        elif command == "authorize":
            # authorize <app_name> <key_id>
            app_name = args[0]
            key_id = args[1]
            authorize_app(app_name, key_id)
            log("authorize", key_id, app_name, True)
            print(f"✓ App '{app_name}' authorized for key '{key_id}'")
        
        else:
            print(f"✗ Unknown command: {command}")
    
    except Exception as e:
        print(f"✗ Error: {e}")
        if len(args) > 0:
            log(command, args[0], None, False)

def run_command_file(filepath: str) -> None:
    """Read and execute commands from .txt file"""
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):  # Skip empty/comments
                continue
            parts = line.split()
            command = parts[0]
            args = parts[1:]
            print(f"\n> {line}")
            execute_command(command, args)

def main() -> None:
    """Parse and execute commands from CLI"""
    if len(sys.argv) < 2:
        print("Usage: python main.py <command> [args]")
        print("   OR: python main.py --file <commands.txt>")
        return
    
    if sys.argv[1] == "--file":
        run_command_file(sys.argv[2])
    else:
        command = sys.argv[1]
        args = sys.argv[2:]
        execute_command(command, args)

if __name__ == "__main__":
    main()