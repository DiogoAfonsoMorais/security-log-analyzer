#!/usr/bin/env python3
"""
Generate sample log files for testing on Windows
"""

import random
from datetime import datetime, timedelta
import os

def generate_timestamp(base_time, offset_seconds):
    """Generate a timestamp string"""
    time_obj = base_time + timedelta(seconds=offset_seconds)
    return time_obj.strftime('%b %d %H:%M:%S')

def generate_log_line(timestamp, ip, username, success=False):
    """Generate a single log line (Windows OpenSSH format)"""
    month, day, time = timestamp.split()
    
    # Windows OpenSSH log format
    if success:
        return f"{month} {day} {time} COMPUTERNAME sshd: Accepted password for {username} from {ip} port 54321"
    else:
        return f"{month} {day} {time} COMPUTERNAME sshd: Failed password for {username} from {ip} port 54321"

def main():
    """Generate sample logs"""
    
    # Create samples directory if it doesn't exist
    os.makedirs('samples', exist_ok=True)
    
    # Base time (current time)
    base_time = datetime.now().replace(hour=10, minute=0, second=0)
    
    # Generate normal log file (mix of success and failures)
    with open('samples/auth_normal.log', 'w') as f:
        ips = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '172.16.1.100']
        users = ['alice', 'bob', 'charlie', 'david']
        
        for i in range(100):
            timestamp = generate_timestamp(base_time, i * 30)
            ip = random.choice(ips)
            username = random.choice(users)
            success = random.random() < 0.3
            
            line = generate_log_line(timestamp, ip, username, success)
            f.write(line + '\n')
    
    print("✅ Created samples/auth_normal.log")
    
    # Generate attack simulation (brute force)
    with open('samples/auth_attack.log', 'w') as f:
        attacker_ip = '185.156.73.52'
        legitimate_ip = '192.168.1.10'
        
        # Attacker tries many passwords
        for i in range(200):
            timestamp = generate_timestamp(base_time, i * 2)
            username = random.choice(['root', 'admin', 'user', 'test', 'ubuntu'])
            line = generate_log_line(timestamp, attacker_ip, username, False)
            f.write(line + '\n')
        
        # Legitimate user logs in successfully
        for i in range(5):
            timestamp = generate_timestamp(base_time, i * 60)
            line = generate_log_line(timestamp, legitimate_ip, 'alice', True)
            f.write(line + '\n')
    
    print("✅ Created samples/auth_attack.log")
    
    # Generate user enumeration simulation
    with open('samples/auth_enumeration.log', 'w') as f:
        attacker_ip = '45.155.205.33'
        common_users = ['root', 'admin', 'administrator', 'user', 'test', 
                       'ubuntu', 'centos', 'oracle', 'postgres', 'mysql']
        
        for i, username in enumerate(common_users):
            timestamp = generate_timestamp(base_time, i * 5)
            line = generate_log_line(timestamp, attacker_ip, username, False)
            f.write(line + '\n')
    
    print("✅ Created samples/auth_enumeration.log")
    
    print("\n📊 Generated test files:")
    print("  - auth_normal.log: Normal traffic")
    print("  - auth_attack.log: Brute force attack")
    print("  - auth_enumeration.log: User enumeration")

if __name__ == "__main__":
    main()