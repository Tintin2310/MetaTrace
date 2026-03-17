import os
import sys

# Ensure parent directory is in path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class ConsoleColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    banner = f"""
{ConsoleColors.OKCYAN}{ConsoleColors.BOLD}
    __  ___     __      ______                      
   /  |/  /__  / /_____/_  __/__________ _________ 
  / /|_/ / _ \/ __/ __ `// / / ___/ __ `/ ___/ _ \\
 / /  / /  __/ /_/ /_/ // / / /  / /_/ / /__/  __/
/_/  /_/\___/\__/\__,_//_/ /_/   \__,_/\___/\___/ 
                                                   
{ConsoleColors.ENDC}{ConsoleColors.OKBLUE}      >>> CYBER DEFENSE & FORENSICS SUITE <<<
{ConsoleColors.ENDC}
    """
    print(banner)

def print_header(text):
    print(f"\n{ConsoleColors.HEADER}{ConsoleColors.BOLD}[*] {text}{ConsoleColors.ENDC}")
    print(f"{ConsoleColors.HEADER}{'=' * (len(text) + 4)}{ConsoleColors.ENDC}")

def print_success(text):
    print(f"{ConsoleColors.OKGREEN}[+] {text}{ConsoleColors.ENDC}")

def print_error(text):
    print(f"{ConsoleColors.FAIL}[!] {text}{ConsoleColors.ENDC}")

def print_info(text):
    print(f"{ConsoleColors.OKBLUE}[i] {text}{ConsoleColors.ENDC}")

def print_warning(text):
    print(f"{ConsoleColors.WARNING}[!] {text}{ConsoleColors.ENDC}")

def print_table(headers, rows):
    """Simple ASCII table plotter."""
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))
            
    # Format string
    fmt = " | ".join([f"{{:<{w}}}" for w in widths])
    sep = "-+-".join(["-" * w for w in widths])
    
    print(f"\n{ConsoleColors.BOLD}{fmt.format(*headers)}{ConsoleColors.ENDC}")
    print(sep)
    for row in rows:
        print(fmt.format(*[str(r) for r in row]))
    print()
