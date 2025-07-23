import os
import json
import getpass
import re
import subprocess
import threading
import time
from datetime import datetime

class MiniOS:
    def __init__(self):
        self.fs = {
            'type': 'directory',
            'name': '/',
            'owner': 'root',
            'group': 'root',
            'permissions': 0o755,
            'children': {
                'home': {
                    'type': 'directory',
                    'name': 'home',
                    'owner': 'root',
                    'group': 'root',
                    'permissions': 0o755,
                    'children': {}
                },
                'etc': {
                    'type': 'directory',
                    'name': 'etc',
                    'owner': 'root',
                    'group': 'root',
                    'permissions': 0o755,
                    'children': {
                        'passwd': {
                            'type': 'file',
                            'name': 'passwd',
                            'owner': 'root',
                            'group': 'root',
                            'permissions': 0o644,
                            'content': "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash"
                        }
                    }
                }
            }
        }
        
        self.users = {
            "root": {
                "password": "root",
                "uid": 0,
                "gid": 0,
                "home": "/root",
                "groups": ["root"]
            },
            "admin": {
                "password": "admin123",
                "uid": 1000,
                "gid": 1000,
                "home": "/home/admin",
                "groups": ["admin", "users"]
            }
        }
        
        self.groups = {
            "root": {"gid": 0, "members": ["root"]},
            "admin": {"gid": 1000, "members": ["admin"]},
            "users": {"gid": 1001, "members": ["admin"]}
        }
        
        self.current_user = None
        self.cwd = '/'
        self.running = True
        self.db_file = "minios_db.json"
        self.processes = {}
        self.next_pid = 1
        self.env = {
            'PATH': '/bin:/usr/bin',
            'HOME': '/',
            'USER': '',
            'SHELL': '/bin/bash'
        }
        self.history = []
        self.history_file = ".minios_history"
        
        self.commands = {
            'help': self.cmd_help,
            'exit': self.cmd_exit,
            'ls': self.cmd_ls,
            'cat': self.cmd_cat,
            'touch': self.cmd_touch,
            'rm': self.cmd_rm,
            'echo': self.cmd_echo,
            'edit': self.cmd_edit,
            'whoami': self.cmd_whoami,
            'save': self.cmd_save,
            'load': self.cmd_load,
            'logout': self.cmd_logout,
            'cd': self.cmd_cd,
            'pwd': self.cmd_pwd,
            'mkdir': self.cmd_mkdir,
            'rmdir': self.cmd_rmdir,
            'chmod': self.cmd_chmod,
            'chown': self.cmd_chown,
            'useradd': self.cmd_useradd,
            'passwd': self.cmd_passwd,
            'ps': self.cmd_ps,
            'kill': self.cmd_kill,
            'bg': self.cmd_bg,
            'fg': self.cmd_fg,
            'jobs': self.cmd_jobs,
            'env': self.cmd_env,
            'export': self.cmd_export,
            'grep': self.cmd_grep,
            'history': self.cmd_history,
            'clear': self.cmd_clear
        }

    def cmd_echo(self, args):
        print(' '.join(args))

    def start(self):
        print("Welcome to Advanced MiniOS!")
        self.cmd_load([])
        self.authenticate()

        while self.running:
            try:
                user_input = input(f"{self.current_user}@MiniOS:{self.cwd}$ ").strip()
                if not user_input:
                    continue
                
                self.history.append(user_input)
                parts = self.parse_input(user_input)
                cmd = parts[0]
                args = parts[1:]
                
                if cmd in self.commands:
                    try:
                        self.commands[cmd](args)
                    except Exception as e:
                        print(f"Error: {e}")
                else:
                    self.run_external(cmd, args)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                self.cmd_exit([])

    def parse_input(self, user_input):
        # Handle quoted arguments and redirection
        parts = []
        current = ''
        in_quote = False
        quote_char = ''
        
        for char in user_input:
            if char in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = char
            elif char == quote_char and in_quote:
                in_quote = False
                if current:
                    parts.append(current)
                    current = ''
            elif char in (' ', '\t') and not in_quote:
                if current:
                    parts.append(current)
                    current = ''
            else:
                current += char
        
        if current:
            parts.append(current)
        
        return parts

    def authenticate(self):
        print("=== Login ===")
        while True:
            username = input("Username: ")
            password = getpass.getpass("Password: ")

            if username in self.users and self.users[username]["password"] == password:
                self.current_user = username
                self.env['USER'] = username
                self.env['HOME'] = self.users[username]["home"]
                self.cwd = self.users[username]["home"]
                print(f"Welcome, {username}!")
                self.load_history()
                break
            else:
                print("Invalid credentials.")

    # File System Helper Functions
    def _get_absolute_path(self, path):
        if path.startswith('/'):
            return path
        return os.path.normpath(os.path.join(self.cwd, path))

    def _find_node(self, path):
        abs_path = self._get_absolute_path(path)
        components = [comp for comp in abs_path.split('/') if comp]
        current = self.fs
        
        for comp in components:
            if current['type'] != 'directory':
                return None, "Not a directory"
            if comp not in current['children']:
                return None, "Path not found"
            current = current['children'][comp]
        
        return current, None

    def _get_parent_node(self, path):
        abs_path = self._get_absolute_path(path)
        components = [comp for comp in abs_path.split('/') if comp]
        if not components:
            return self.fs, None, None  # Root directory
        
        parent_path = '/' + '/'.join(components[:-1])
        return self._find_node(parent_path) + (components[-1],)

    def _check_permission(self, node, access):
        if self.current_user == 'root':
            return True
            
        perms = node['permissions']
        uid = self.users[self.current_user]["uid"]
        gid = self.users[self.current_user]["gid"]
        
        if uid == 0:  # Root user
            return True
            
        if node['owner'] == self.current_user:
            perm_bits = (perms >> 6) & 7
        elif gid == node.get('gid', 0) or self.current_user in self.groups.get(node.get('group', ''), {}).get('members', []):
            perm_bits = (perms >> 3) & 7
        else:
            perm_bits = perms & 7
            
        access_bit = {'r': 4, 'w': 2, 'x': 1}.get(access, 0)
        return (perm_bits & access_bit) == access_bit

    # Command Implementations
    def cmd_help(self, args):
        print("Available commands:")
        for cmd in sorted(self.commands.keys()):
            print(f"  {cmd}")
        print("\nAdvanced features:")
        print("  - Directory structure with permissions")
        print("  - User and group management")
        print("  - Background processes")
        print("  - Environment variables")
        print("  - Command history")
        print("  - File searching with grep")
        print("  - Job control (bg, fg, jobs, kill)")

    def cmd_exit(self, args):
        self.save_history()
        print("Shutting down MiniOS...")
        self.cmd_save([])
        self.running = False

    def cmd_ls(self, args):
        path = args[0] if args else self.cwd
        node, err = self._find_node(path)
        
        if err:
            print(err)
            return
            
        if node['type'] != 'directory':
            print("Not a directory")
            return
            
        if not self._check_permission(node, 'r'):
            print("Permission denied")
            return
            
        print(f"Contents of {path}:")
        for name, child in node['children'].items():
            perm_str = self._format_permissions(child)
            print(f"{perm_str} {child['owner']:>8} {child['group']:>8} {name}")

    def _format_permissions(self, node):
        perms = node['permissions']
        types = {'directory': 'd', 'file': '-', 'link': 'l'}.get(node['type'], '?')
        
        def perm_bits(bits):
            return ''.join([
                'r' if bits & 4 else '-',
                'w' if bits & 2 else '-',
                'x' if bits & 1 else '-'
            ])
            
        owner_bits = (perms >> 6) & 7
        group_bits = (perms >> 3) & 7
        other_bits = perms & 7
        
        return types + perm_bits(owner_bits) + perm_bits(group_bits) + perm_bits(other_bits)

    def cmd_cd(self, args):
        if not args:
            new_path = self.users[self.current_user]["home"]
        else:
            new_path = args[0]
            
        node, err = self._find_node(new_path)
        if err:
            print(err)
            return
            
        if node['type'] != 'directory':
            print("Not a directory")
            return
            
        if not self._check_permission(node, 'x'):
            print("Permission denied")
            return
            
        self.cwd = self._get_absolute_path(new_path)
        print(f"Current directory: {self.cwd}")

    def cmd_pwd(self, args):
        print(self.cwd)

    def cmd_mkdir(self, args):
        if not args:
            print("Usage: mkdir <directory>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            print(f"Error: {err}")
            return
            
        if name in parent['children']:
            print(f"Directory '{name}' already exists")
            return
            
        if not self._check_permission(parent, 'w'):
            print("Permission denied")
            return
            
        parent['children'][name] = {
            'type': 'directory',
            'name': name,
            'owner': self.current_user,
            'group': self.users[self.current_user]["groups"][0],
            'permissions': 0o755,
            'children': {}
        }
        print(f"Directory '{name}' created")

    def cmd_touch(self, args):
        if not args:
            print("Usage: touch <filename>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            print(f"Error: {err}")
            return
            
        if name in parent['children']:
            print(f"File '{name}' already exists")
            return
            
        if not self._check_permission(parent, 'w'):
            print("Permission denied")
            return
            
        parent['children'][name] = {
            'type': 'file',
            'name': name,
            'owner': self.current_user,
            'group': self.users[self.current_user]["groups"][0],
            'permissions': 0o644,
            'content': ""
        }
        print(f"File '{name}' created")

    def cmd_cat(self, args):
        if not args:
            print("Usage: cat <filename>")
            return
            
        path = args[0]
        node, err = self._find_node(path)
        if err:
            print(err)
            return
            
        if node['type'] != 'file':
            print("Not a file")
            return
            
        if not self._check_permission(node, 'r'):
            print("Permission denied")
            return
            
        print(node['content'])

    def cmd_rm(self, args):
        if not args:
            print("Usage: rm <filename>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            print(f"Error: {err}")
            return
            
        if name not in parent['children']:
            print("File not found")
            return
            
        node = parent['children'][name]
        
        if node['type'] not in ['file', 'link']:
            print("Use rmdir for directories")
            return
            
        if not self._check_permission(parent, 'w'):
            print("Permission denied")
            return
            
        del parent['children'][name]
        print(f"Removed {name}")

    def cmd_rmdir(self, args):
        if not args:
            print("Usage: rmdir <directory>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            print(f"Error: {err}")
            return
            
        if name not in parent['children']:
            print("Directory not found")
            return
            
        node = parent['children'][name]
        
        if node['type'] != 'directory':
            print("Not a directory")
            return
            
        if node['children']:
            print("Directory not empty")
            return
            
        if not self._check_permission(parent, 'w'):
            print("Permission denied")
            return
            
        del parent['children'][name]
        print(f"Removed directory {name}")

    def cmd_edit(self, args):
        if not args:
            print("Usage: edit <filename>")
            return
            
        path = args[0]
        node, err = self._find_node(path)
        if err:
            print(err)
            return
            
        if node['type'] != 'file':
            print("Not a file")
            return
            
        if not self._check_permission(node, 'w'):
            print("Permission denied")
            return
            
        print(f"Editing {path}. Enter your content below (end with EOF on a single line):")
        content_lines = []
        while True:
            line = input()
            if line.strip() == "EOF":
                break
            content_lines.append(line)
            
        node['content'] = "\n".join(content_lines)
        print(f"File {path} updated")

    def cmd_chmod(self, args):
        if len(args) < 2:
            print("Usage: chmod <mode> <path>")
            return
            
        mode_str = args[0]
        path = args[1]
        
        try:
            if mode_str.isdigit():
                mode = int(mode_str, 8)
            else:
                # Handle symbolic modes: u+rwx,g-w,o=r
                print("Symbolic modes not implemented. Use octal format.")
                return
        except ValueError:
            print("Invalid mode format. Use octal (e.g., 755)")
            return
            
        node, err = self._find_node(path)
        if err:
            print(err)
            return
            
        if not self._check_permission(node, 'w'):
            print("Permission denied")
            return
            
        node['permissions'] = mode
        print(f"Permissions for {path} updated to {oct(mode)}")

    def cmd_chown(self, args):
        if len(args) < 2:
            print("Usage: chown <owner>[:group] <path>")
            return
            
        owner_group = args[0].split(':')
        new_owner = owner_group[0]
        new_group = owner_group[1] if len(owner_group) > 1 else None
        path = args[1]
        
        node, err = self._find_node(path)
        if err:
            print(err)
            return
            
        if new_owner not in self.users:
            print(f"User '{new_owner}' not found")
            return
            
        if new_group and new_group not in self.groups:
            print(f"Group '{new_group}' not found")
            return
            
        if not self._check_permission(node, 'w'):
            print("Permission denied")
            return
            
        node['owner'] = new_owner
        if new_group:
            node['group'] = new_group
        print(f"Ownership for {path} updated")

    def cmd_useradd(self, args):
        if not args:
            print("Usage: useradd <username>")
            return
            
        if self.current_user != 'root':
            print("Permission denied: Only root can create users")
            return
            
        username = args[0]
        if username in self.users:
            print(f"User '{username}' already exists")
            return
            
        # Create new user
        uid = max(user['uid'] for user in self.users.values()) + 1
        self.users[username] = {
            "password": "changeme",
            "uid": uid,
            "gid": uid,
            "home": f"/home/{username}",
            "groups": [username]
        }
        
        # Create user group
        self.groups[username] = {"gid": uid, "members": [username]}
        
        # Create home directory
        home_parent, err, home_name = self._get_parent_node(f"/home/{username}")
        if not err:
            home_parent['children'][home_name] = {
                'type': 'directory',
                'name': home_name,
                'owner': username,
                'group': username,
                'permissions': 0o700,
                'children': {}
            }
        
        print(f"User '{username}' created with UID {uid}. Default password: 'changeme'")

    def cmd_passwd(self, args):
        username = args[0] if args else self.current_user
        
        if username != self.current_user and self.current_user != 'root':
            print("Permission denied: Can only change your own password")
            return
            
        if username not in self.users:
            print(f"User '{username}' not found")
            return
            
        print(f"Changing password for {username}")
        current = getpass.getpass("Current password: ") if username == self.current_user else ""
        
        if username == self.current_user and current != self.users[username]["password"]:
            print("Current password is incorrect")
            return
            
        new_password = getpass.getpass("New password: ")
        confirm_password = getpass.getpass("Retype new password: ")
        
        if new_password != confirm_password:
            print("Passwords do not match")
            return
            
        self.users[username]["password"] = new_password
        print("Password updated successfully")

    # Process Management
    def run_external(self, cmd, args):
        pid = self.next_pid
        self.next_pid += 1
        
        def run_process():
            try:
                if cmd == "sleep":
                    time.sleep(int(args[0]))
                elif cmd == "yes":
                    while True:
                        print("y")
                        time.sleep(0.1)
                else:
                    print(f"Command not found: {cmd}")
            except Exception as e:
                print(f"Process error: {e}")
            finally:
                if pid in self.processes:
                    del self.processes[pid]
        
        thread = threading.Thread(target=run_process)
        thread.daemon = True
        self.processes[pid] = {
            "pid": pid,
            "cmd": cmd,
            "args": args,
            "thread": thread,
            "status": "running"
        }
        thread.start()
        print(f"[{pid}] {cmd} {' '.join(args)}")
        return pid

    def cmd_ps(self, args):
        print("PID\tCMD\tSTATUS")
        for pid, proc in self.processes.items():
            print(f"{pid}\t{proc['cmd']}\t{proc['status']}")

    def cmd_kill(self, args):
        if not args:
            print("Usage: kill <pid>")
            return
            
        try:
            pid = int(args[0])
            if pid not in self.processes:
                print(f"No such process: {pid}")
                return
                
            # Terminate the process (simulated)
            self.processes[pid]["status"] = "terminated"
            print(f"Process {pid} terminated")
        except ValueError:
            print("Invalid PID")

    def cmd_bg(self, args):
        print("Background processing not fully implemented")
        # In real implementation, would detach process from terminal

    def cmd_fg(self, args):
        print("Foreground processing not fully implemented")
        # In real implementation, would attach process to terminal

    def cmd_jobs(self, args):
        print("Background jobs:")
        for pid, proc in self.processes.items():
            if proc["status"] == "running":
                print(f"[{pid}] {proc['cmd']} {' '.join(proc['args'])}")

    # Environment Management
    def cmd_env(self, args):
        for key, value in self.env.items():
            print(f"{key}={value}")

    def cmd_export(self, args):
        if not args:
            return
            
        for arg in args:
            if '=' in arg:
                key, value = arg.split('=', 1)
                self.env[key] = value
                print(f"Exported {key}={value}")
            else:
                print(f"Invalid export format: {arg}")

    # Advanced Utilities
    def cmd_grep(self, args):
        if len(args) < 2:
            print("Usage: grep <pattern> <file>")
            return
            
        pattern = args[0]
        path = args[1]
        
        node, err = self._find_node(path)
        if err:
            print(err)
            return
            
        if node['type'] != 'file':
            print("Not a file")
            return
            
        if not self._check_permission(node, 'r'):
            print("Permission denied")
            return
            
        try:
            regex = re.compile(pattern)
            for i, line in enumerate(node['content'].split('\n')):
                if regex.search(line):
                    print(f"{path}:{i+1}:{line}")
        except re.error:
            print("Invalid regular expression")

    def cmd_history(self, args):
        count = 10
        if args and args[0].isdigit():
            count = int(args[0])
            
        start_idx = max(0, len(self.history) - count)
        for i, cmd in enumerate(self.history[start_idx:], start=start_idx+1):
            print(f"{i}  {cmd}")

    def cmd_clear(self, args):
        if os.name == 'posix':
            os.system('clear')
        else:
            os.system('cls')

    def cmd_whoami(self, args):
        print(self.current_user)

    def cmd_logout(self, args):
        self.save_history()
        print(f"Goodbye, {self.current_user}!")
        self.current_user = None
        self.authenticate()

    # History Management
    def save_history(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f)
        except Exception:
            pass

    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.history = json.load(f)
        except Exception:
            self.history = []

    # Persistence
    def cmd_save(self, args):
        data = {
            "fs": self.fs,
            "users": self.users,
            "groups": self.groups,
            "cwd": self.cwd,
            "env": self.env
        }
        with open(self.db_file, "w") as f:
            json.dump(data, f, indent=2)
        print("System state saved")

    def cmd_load(self, args):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, "r") as f:
                    data = json.load(f)
                self.fs = data.get("fs", self.fs)
                self.users = data.get("users", self.users)
                self.groups = data.get("groups", self.groups)
                self.cwd = data.get("cwd", '/')
                self.env = data.get("env", self.env)
                print("System state loaded")
            except Exception as e:
                print(f"Error loading state: {e}")

if __name__ == "__main__":
    osys = MiniOS()
    osys.start()