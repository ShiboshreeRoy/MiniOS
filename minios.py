import os
import json
import getpass
import re
import subprocess
import threading
import time
from datetime import datetime

class MiniOS:
    # ANSI color codes
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    HIDDEN = "\033[8m"

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
                },
                'bin': {
                    'type': 'directory',
                    'name': 'bin',
                    'owner': 'root',
                    'group': 'root',
                    'permissions': 0o755,
                    'children': {}
                }
            }
        }
        
        self.users = {
            "root": {
                "password": "root",
                "uid": 0,
                "gid": 0,
                "home": "/root",
                "groups": ["root"],
                "shell": "/bin/bash"
            },
            "admin": {
                "password": "admin123",
                "uid": 1000,
                "gid": 1000,
                "home": "/home/admin",
                "groups": ["admin", "users"],
                "shell": "/bin/bash"
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
            'SHELL': '/bin/bash',
            'TERM': 'xterm-256color',
            'PS1': r'\[\033[1;32m\]\u@\h\[\033[0m\]:\[\033[1;34m\]\w\[\033[0m\]\$ '
        }
        self.history = []
        self.history_file = ".minios_history"
        self.background_jobs = {}
        self.next_job_id = 1
        
        self.commands = {
            'help': self.cmd_help,
            'exit': self.cmd_exit,
            'quit': self.cmd_exit,
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
            'clear': self.cmd_clear,
            'date': self.cmd_date,
            'sleep': self.cmd_sleep,
            'yes': self.cmd_yes
        }

    def colorize(self, text, color, bg_color=None, bold=False, underline=False):
        result = ""
        if bold:
            result += self.BOLD
        if underline:
            result += self.UNDERLINE
            
        result += color
        
        if bg_color:
            result += bg_color
            
        result += text + self.RESET
        return result

    def print_error(self, message):
        print(f"{self.BRIGHT_RED}✗ Error:{self.RESET} {message}")

    def print_success(self, message):
        print(f"{self.BRIGHT_GREEN}✓ Success:{self.RESET} {message}")

    def print_warning(self, message):
        print(f"{self.BRIGHT_YELLOW}⚠ Warning:{self.RESET} {message}")

    def print_info(self, message):
        print(f"{self.BRIGHT_CYAN}ℹ Info:{self.RESET} {message}")

    def cmd_echo(self, args):
        print(' '.join(args))

    def start(self):
        print(f"{self.BRIGHT_GREEN}=== Welcome to {self.BOLD}Advanced MiniOS!{self.RESET}{self.BRIGHT_GREEN} ==={self.RESET}")
        print(f"{self.BRIGHT_CYAN}Type 'help' for available commands{self.RESET}")
        self.cmd_load([])
        self.authenticate()

        while self.running:
            try:
                # Colorful prompt
                username_color = self.BRIGHT_GREEN if self.current_user != 'root' else self.BRIGHT_RED
                host_color = self.BRIGHT_YELLOW
                path_color = self.BRIGHT_BLUE
                
                prompt = f"{username_color}{self.current_user}{self.RESET}@{host_color}MiniOS{self.RESET}:{path_color}{self.cwd}{self.RESET}$ "
                user_input = input(prompt).strip()
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
                        self.print_error(str(e))
                else:
                    self.run_external(cmd, args)
            except KeyboardInterrupt:
                print(f"\n{self.BRIGHT_YELLOW}Use 'exit' to quit{self.RESET}")
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
        print(f"{self.BRIGHT_CYAN}=== Login ==={self.RESET}")
        while True:
            username = input(f"{self.BRIGHT_BLUE}Username:{self.RESET} ")
            password = getpass.getpass(f"{self.BRIGHT_BLUE}Password:{self.RESET} ")

            if username in self.users and self.users[username]["password"] == password:
                self.current_user = username
                self.env['USER'] = username
                self.env['HOME'] = self.users[username]["home"]
                self.cwd = self.users[username]["home"]
                print(f"{self.BRIGHT_GREEN}Welcome, {username}!{self.RESET}")
                self.load_history()
                break
            else:
                self.print_error("Invalid credentials.")

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
        print(f"{self.BRIGHT_CYAN}Available commands:{self.RESET}")
        for cmd in sorted(self.commands.keys()):
            print(f"  {self.BRIGHT_GREEN}{cmd}{self.RESET}")
        
        print(f"\n{self.BRIGHT_CYAN}Advanced features:{self.RESET}")
        print(f"  - {self.BRIGHT_YELLOW}Directory structure with permissions{self.RESET}")
        print(f"  - {self.BRIGHT_YELLOW}User and group management{self.RESET}")
        print(f"  - {self.BRIGHT_YELLOW}Background processes{self.RESET}")
        print(f"  - {self.BRIGHT_YELLOW}Environment variables{self.RESET}")
        print(f"  - {self.BRIGHT_YELLOW}Command history{self.RESET}")
        print(f"  - {self.BRIGHT_YELLOW}File searching with grep{self.RESET}")
        print(f"  - {self.BRIGHT_YELLOW}Job control (bg, fg, jobs, kill){self.RESET}")

    def cmd_exit(self, args):
        self.save_history()
        print(f"{self.BRIGHT_GREEN}Shutting down MiniOS...{self.RESET}")
        self.cmd_save([])
        self.running = False

    def cmd_ls(self, args):
        path = args[0] if args else self.cwd
        node, err = self._find_node(path)
        
        if err:
            self.print_error(err)
            return
            
        if node['type'] != 'directory':
            self.print_error("Not a directory")
            return
            
        if not self._check_permission(node, 'r'):
            self.print_error("Permission denied")
            return
            
        print(f"{self.BRIGHT_BLUE}Contents of {path}:{self.RESET}")
        for name, child in node['children'].items():
            perm_str = self._format_permissions(child)
            owner_color = self.BRIGHT_RED if child['owner'] == 'root' else self.BRIGHT_GREEN
            group_color = self.BRIGHT_MAGENTA
            
            # Color files based on type
            if child['type'] == 'directory':
                name_color = self.BRIGHT_BLUE
            elif child['permissions'] & 0o100:  # Executable
                name_color = self.BRIGHT_GREEN
            else:
                name_color = self.WHITE
                
            print(f"{perm_str} {owner_color}{child['owner']:>8}{self.RESET} {group_color}{child['group']:>8}{self.RESET} {name_color}{name}{self.RESET}")

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
        
        perm_str = types + perm_bits(owner_bits) + perm_bits(group_bits) + perm_bits(other_bits)
        
        # Color permissions
        if owner_bits & 0o7 == 0o7:  # Full permissions
            perm_str = self.BRIGHT_GREEN + perm_str + self.RESET
        elif owner_bits & 0o7 >= 0o5:  # Read and execute
            perm_str = self.BRIGHT_YELLOW + perm_str + self.RESET
        elif owner_bits & 0o4:  # At least read
            perm_str = self.BRIGHT_CYAN + perm_str + self.RESET
        else:
            perm_str = self.RED + perm_str + self.RESET
            
        return perm_str

    def cmd_cd(self, args):
        if not args:
            new_path = self.users[self.current_user]["home"]
        else:
            new_path = args[0]
            
        node, err = self._find_node(new_path)
        if err:
            self.print_error(err)
            return
            
        if node['type'] != 'directory':
            self.print_error("Not a directory")
            return
            
        if not self._check_permission(node, 'x'):
            self.print_error("Permission denied")
            return
            
        self.cwd = self._get_absolute_path(new_path)
        print(f"{self.BRIGHT_CYAN}Current directory:{self.RESET} {self.BRIGHT_BLUE}{self.cwd}{self.RESET}")

    def cmd_pwd(self, args):
        print(f"{self.BRIGHT_BLUE}{self.cwd}{self.RESET}")

    def cmd_mkdir(self, args):
        if not args:
            self.print_error("Usage: mkdir <directory>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            self.print_error(err)
            return
            
        if name in parent['children']:
            self.print_error(f"Directory '{name}' already exists")
            return
            
        if not self._check_permission(parent, 'w'):
            self.print_error("Permission denied")
            return
            
        parent['children'][name] = {
            'type': 'directory',
            'name': name,
            'owner': self.current_user,
            'group': self.users[self.current_user]["groups"][0],
            'permissions': 0o755,
            'children': {}
        }
        self.print_success(f"Directory '{name}' created")

    def cmd_touch(self, args):
        if not args:
            self.print_error("Usage: touch <filename>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            self.print_error(err)
            return
            
        if name in parent['children']:
            print(f"File '{name}' already exists")
            return
            
        if not self._check_permission(parent, 'w'):
            self.print_error("Permission denied")
            return
            
        parent['children'][name] = {
            'type': 'file',
            'name': name,
            'owner': self.current_user,
            'group': self.users[self.current_user]["groups"][0],
            'permissions': 0o644,
            'content': ""
        }
        self.print_success(f"File '{name}' created")

    def cmd_cat(self, args):
        if not args:
            self.print_error("Usage: cat <filename>")
            return
            
        path = args[0]
        node, err = self._find_node(path)
        if err:
            self.print_error(err)
            return
            
        if node['type'] != 'file':
            self.print_error("Not a file")
            return
            
        if not self._check_permission(node, 'r'):
            self.print_error("Permission denied")
            return
            
        print(f"{self.BRIGHT_CYAN}Contents of {path}:{self.RESET}")
        print(node['content'])

    def cmd_rm(self, args):
        if not args:
            self.print_error("Usage: rm <filename>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            self.print_error(err)
            return
            
        if name not in parent['children']:
            self.print_error("File not found")
            return
            
        node = parent['children'][name]
        
        if node['type'] not in ['file', 'link']:
            self.print_error("Use rmdir for directories")
            return
            
        if not self._check_permission(parent, 'w'):
            self.print_error("Permission denied")
            return
            
        del parent['children'][name]
        self.print_success(f"Removed {name}")

    def cmd_rmdir(self, args):
        if not args:
            self.print_error("Usage: rmdir <directory>")
            return
            
        path = args[0]
        parent, err, name = self._get_parent_node(path)
        if err:
            self.print_error(err)
            return
            
        if name not in parent['children']:
            self.print_error("Directory not found")
            return
            
        node = parent['children'][name]
        
        if node['type'] != 'directory':
            self.print_error("Not a directory")
            return
            
        if node['children']:
            self.print_error("Directory not empty")
            return
            
        if not self._check_permission(parent, 'w'):
            self.print_error("Permission denied")
            return
            
        del parent['children'][name]
        self.print_success(f"Removed directory {name}")

    def cmd_edit(self, args):
        if not args:
            self.print_error("Usage: edit <filename>")
            return
            
        path = args[0]
        node, err = self._find_node(path)
        if err:
            self.print_error(err)
            return
            
        if node['type'] != 'file':
            self.print_error("Not a file")
            return
            
        if not self._check_permission(node, 'w'):
            self.print_error("Permission denied")
            return
            
        print(f"{self.BRIGHT_CYAN}Editing {path}. Enter your content below (end with EOF on a single line):{self.RESET}")
        content_lines = []
        while True:
            try:
                line = input()
                if line.strip() == "EOF":
                    break
                content_lines.append(line)
            except EOFError:
                break
            
        node['content'] = "\n".join(content_lines)
        self.print_success(f"File {path} updated")

    def cmd_chmod(self, args):
        if len(args) < 2:
            self.print_error("Usage: chmod <mode> <path>")
            return
            
        mode_str = args[0]
        path = args[1]
        
        try:
            if mode_str.isdigit():
                mode = int(mode_str, 8)
            else:
                self.print_error("Symbolic modes not implemented. Use octal format.")
                return
        except ValueError:
            self.print_error("Invalid mode format. Use octal (e.g., 755)")
            return
            
        node, err = self._find_node(path)
        if err:
            self.print_error(err)
            return
            
        if not self._check_permission(node, 'w'):
            self.print_error("Permission denied")
            return
            
        node['permissions'] = mode
        self.print_success(f"Permissions for {path} updated to {oct(mode)}")

    def cmd_chown(self, args):
        if len(args) < 2:
            self.print_error("Usage: chown <owner>[:group] <path>")
            return
            
        owner_group = args[0].split(':')
        new_owner = owner_group[0]
        new_group = owner_group[1] if len(owner_group) > 1 else None
        path = args[1]
        
        node, err = self._find_node(path)
        if err:
            self.print_error(err)
            return
            
        if new_owner not in self.users:
            self.print_error(f"User '{new_owner}' not found")
            return
            
        if new_group and new_group not in self.groups:
            self.print_error(f"Group '{new_group}' not found")
            return
            
        if not self._check_permission(node, 'w'):
            self.print_error("Permission denied")
            return
            
        node['owner'] = new_owner
        if new_group:
            node['group'] = new_group
        self.print_success(f"Ownership for {path} updated")

    def cmd_useradd(self, args):
        if not args:
            self.print_error("Usage: useradd <username>")
            return
            
        if self.current_user != 'root':
            self.print_error("Permission denied: Only root can create users")
            return
            
        username = args[0]
        if username in self.users:
            self.print_error(f"User '{username}' already exists")
            return
            
        # Create new user
        uid = max(user['uid'] for user in self.users.values()) + 1
        self.users[username] = {
            "password": "changeme",
            "uid": uid,
            "gid": uid,
            "home": f"/home/{username}",
            "groups": [username],
            "shell": "/bin/bash"
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
        
        self.print_success(f"User '{username}' created with UID {uid}. Default password: 'changeme'")

    def cmd_passwd(self, args):
        username = args[0] if args else self.current_user
        
        if username != self.current_user and self.current_user != 'root':
            self.print_error("Permission denied: Can only change your own password")
            return
            
        if username not in self.users:
            self.print_error(f"User '{username}' not found")
            return
            
        print(f"{self.BRIGHT_CYAN}Changing password for {username}{self.RESET}")
        current = getpass.getpass("Current password: ") if username == self.current_user else ""
        
        if username == self.current_user and current != self.users[username]["password"]:
            self.print_error("Current password is incorrect")
            return
            
        new_password = getpass.getpass("New password: ")
        confirm_password = getpass.getpass("Retype new password: ")
        
        if new_password != confirm_password:
            self.print_error("Passwords do not match")
            return
            
        self.users[username]["password"] = new_password
        self.print_success("Password updated successfully")

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
                    self.print_error(f"Command not found: {cmd}")
            except Exception as e:
                self.print_error(f"Process error: {e}")
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
        print(f"{self.BRIGHT_YELLOW}[{pid}] {cmd} {' '.join(args)}{self.RESET}")
        return pid

    def cmd_ps(self, args):
        print(f"{self.BRIGHT_CYAN}{'PID':<6}{'CMD':<15}{'STATUS':<10}{self.RESET}")
        for pid, proc in self.processes.items():
            status_color = self.BRIGHT_GREEN if proc['status'] == 'running' else self.BRIGHT_RED
            print(f"{pid:<6}{proc['cmd']:<15}{status_color}{proc['status']:<10}{self.RESET}")

    def cmd_kill(self, args):
        if not args:
            self.print_error("Usage: kill <pid>")
            return
            
        try:
            pid = int(args[0])
            if pid not in self.processes:
                self.print_error(f"No such process: {pid}")
                return
                
            # Terminate the process (simulated)
            self.processes[pid]["status"] = "terminated"
            self.print_success(f"Process {pid} terminated")
        except ValueError:
            self.print_error("Invalid PID")

    def cmd_bg(self, args):
        if not self.background_jobs:
            self.print_error("No background jobs")
            return
            
        job_id = list(self.background_jobs.keys())[0] if not args else int(args[0])
        if job_id not in self.background_jobs:
            self.print_error(f"No such job: {job_id}")
            return
            
        job = self.background_jobs[job_id]
        job["status"] = "running"
        print(f"{self.BRIGHT_YELLOW}[{job_id}] {job['cmd']} {' '.join(job['args'])}{self.RESET}")

    def cmd_fg(self, args):
        if not self.background_jobs:
            self.print_error("No background jobs")
            return
            
        job_id = list(self.background_jobs.keys())[0] if not args else int(args[0])
        if job_id not in self.background_jobs:
            self.print_error(f"No such job: {job_id}")
            return
            
        job = self.background_jobs[job_id]
        job["status"] = "foreground"
        print(f"{self.BRIGHT_YELLOW}Bringing job {job_id} to foreground: {job['cmd']} {' '.join(job['args'])}{self.RESET}")

    def cmd_jobs(self, args):
        if not self.background_jobs:
            print("No background jobs")
            return
            
        print(f"{self.BRIGHT_CYAN}{'JobID':<6}{'PID':<6}{'CMD':<20}{'STATUS':<10}{self.RESET}")
        for job_id, job in self.background_jobs.items():
            status_color = self.BRIGHT_GREEN if job['status'] == 'running' else self.BRIGHT_YELLOW
            print(f"{job_id:<6}{job['pid']:<6}{job['cmd']:<20}{status_color}{job['status']:<10}{self.RESET}")

    # Environment Management
    def cmd_env(self, args):
        for key, value in self.env.items():
            print(f"{self.BRIGHT_CYAN}{key}{self.RESET}={self.BRIGHT_GREEN}{value}{self.RESET}")

    def cmd_export(self, args):
        if not args:
            return
            
        for arg in args:
            if '=' in arg:
                key, value = arg.split('=', 1)
                self.env[key] = value
                print(f"{self.BRIGHT_GREEN}Exported {key}={value}{self.RESET}")
            else:
                self.print_error(f"Invalid export format: {arg}")

    # Advanced Utilities
    def cmd_grep(self, args):
        if len(args) < 2:
            self.print_error("Usage: grep <pattern> <file>")
            return
            
        pattern = args[0]
        path = args[1]
        
        node, err = self._find_node(path)
        if err:
            self.print_error(err)
            return
            
        if node['type'] != 'file':
            self.print_error("Not a file")
            return
            
        if not self._check_permission(node, 'r'):
            self.print_error("Permission denied")
            return
            
        try:
            regex = re.compile(pattern)
            for i, line in enumerate(node['content'].split('\n')):
                if regex.search(line):
                    matched = regex.search(line)
                    start, end = matched.span()
                    highlighted = (
                        line[:start] + 
                        self.BRIGHT_RED + line[start:end] + self.RESET + 
                        line[end:]
                    )
                    print(f"{self.BRIGHT_BLUE}{path}:{i+1}:{self.RESET}{highlighted}")
        except re.error:
            self.print_error("Invalid regular expression")

    def cmd_history(self, args):
        count = 10
        if args and args[0].isdigit():
            count = int(args[0])
            
        start_idx = max(0, len(self.history) - count)
        for i, cmd in enumerate(self.history[start_idx:], start=start_idx+1):
            print(f"{self.BRIGHT_CYAN}{i:4}{self.RESET}  {cmd}")

    def cmd_clear(self, args):
        if os.name == 'posix':
            os.system('clear')
        else:
            os.system('cls')

    def cmd_whoami(self, args):
        username_color = self.BRIGHT_RED if self.current_user == 'root' else self.BRIGHT_GREEN
        print(username_color + self.current_user + self.RESET)

    def cmd_logout(self, args):
        self.save_history()
        print(f"{self.BRIGHT_GREEN}Goodbye, {self.current_user}!{self.RESET}")
        self.current_user = None
        self.authenticate()

    def cmd_date(self, args):
        now = datetime.now()
        print(f"{self.BRIGHT_CYAN}{now.strftime('%a %b %d %H:%M:%S %Y')}{self.RESET}")

    def cmd_sleep(self, args):
        if not args:
            self.print_error("Usage: sleep <seconds>")
            return
            
        try:
            seconds = float(args[0])
            time.sleep(seconds)
        except ValueError:
            self.print_error("Invalid time value")

    def cmd_yes(self, args):
        text = ' '.join(args) if args else 'y'
        try:
            while True:
                print(text)
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass

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
            "env": self.env,
            "history": self.history
        }
        with open(self.db_file, "w") as f:
            json.dump(data, f, indent=2)
        self.print_success("System state saved")

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
                self.history = data.get("history", self.history)
                self.print_success("System state loaded")
            except Exception as e:
                self.print_error(f"Error loading state: {e}")
        else:
            self.print_warning("No saved state found")

if __name__ == "__main__":
    osys = MiniOS()
    osys.start()