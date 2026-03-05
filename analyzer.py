#!/usr/bin/env python3
"""
Security Log Analyzer
Author: Diogo Morais
Description: Detects brute force attacks and suspicious patterns in authentication logs
"""

import re
import csv
import yaml
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import json


class LogAnalyzer:
    """
    Main class for log analysis and attack detection
    """
    
    def __init__(self, config_file='config.yaml'):
        """
        Initialize the analyzer with configuration
        
        Args:
            config_file (str): Path to YAML configuration file
        """
        # Load configuration
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Initialize data structures
        self.failed_attempts = defaultdict(list)  # IP -> list of timestamps
        self.used_usernames = defaultdict(set)    # IP -> set of usernames tried
        self.alerts = []
        
        # Compile regex patterns for better performance
        self.patterns = {
            'failed_password': re.compile(
                r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)'
            ),
            'invalid_user': re.compile(
                r'Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)'
            ),
            'timestamp': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)'
            )
        }
        
    def extract_timestamp(self, line):
        """
        Extract timestamp from log line
        
        Args:
            line (str): Log line
            
        Returns:
            datetime: Parsed timestamp or None if not found
        """
        match = self.patterns['timestamp'].search(line)
        if match:
            try:
                # Parse timestamp (format: "Mar 5 10:30:25")
                return datetime.strptime(match.group(1), '%b %d %H:%M:%S')
            except ValueError:
                return None
        return None
    
    def parse_line(self, line):
        """
        Parse a single log line and extract relevant information
        
        Args:
            line (str): Log line
            
        Returns:
            tuple: (ip_address, username, timestamp) or (None, None, None)
        """
        # Try to match failed password pattern
        match = self.patterns['failed_password'].search(line)
        if match:
            username, ip = match.groups()
            timestamp = self.extract_timestamp(line)
            return ip, username, timestamp
        
        # Try to match invalid user pattern
        match = self.patterns['invalid_user'].search(line)
        if match:
            username, ip = match.groups()
            timestamp = self.extract_timestamp(line)
            return ip, username, timestamp
        
        return None, None, None
    
    def analyze_file(self, logfile):
        """
        Analyze a log file for suspicious activity
        
        Args:
            logfile (str): Path to log file
            
        Returns:
            list: Alerts generated during analysis
        """
        print(f"🔍 Analyzing {logfile}...")
        
        # Clear previous data
        self.failed_attempts.clear()
        self.used_usernames.clear()
        self.alerts.clear()
        
        try:
            with open(logfile, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    ip, username, timestamp = self.parse_line(line)
                    
                    if ip and username and timestamp:
                        # Store failed attempt
                        self.failed_attempts[ip].append(timestamp)
                        self.used_usernames[ip].add(username)
                        
                        # Check for brute force (periodically)
                        if len(self.failed_attempts[ip]) % 5 == 0:
                            self.check_brute_force(ip)
                            
            # Final check for all IPs
            for ip in self.failed_attempts.keys():
                self.check_brute_force(ip)
                self.check_user_enumeration(ip)
                
            print(f"✅ Analysis complete. Found {len(self.alerts)} alerts.")
            return self.alerts
            
        except FileNotFoundError:
            print(f"❌ Error: File {logfile} not found!")
            return []
        except Exception as e:
            print(f"❌ Error analyzing file: {e}")
            return []
    
    def check_brute_force(self, ip):
        """
        Check if an IP is performing brute force attack
        
        Args:
            ip (str): IP address to check
        """
        attempts = self.failed_attempts[ip]
        if len(attempts) < self.config['thresholds']['brute_force']['max_attempts']:
            return
        
        # Sort timestamps
        attempts.sort()
        
        # Check time window
        time_window = self.config['thresholds']['brute_force']['time_window']
        max_attempts = self.config['thresholds']['brute_force']['max_attempts']
        
        # Sliding window check
        for i in range(len(attempts) - max_attempts + 1):
            window_start = attempts[i]
            window_end = window_start + timedelta(seconds=time_window)
            
            # Count attempts in this window
            attempts_in_window = sum(1 for t in attempts[i:] if t <= window_end)
            
            if attempts_in_window >= max_attempts:
                # Create alert
                alert = {
                    'type': 'BRUTE_FORCE',
                    'ip': ip,
                    'attempts': attempts_in_window,
                    'first_seen': attempts[i],
                    'last_seen': attempts[i + attempts_in_window - 1],
                    'unique_usernames': len(self.used_usernames[ip]),
                    'severity': 'HIGH' if attempts_in_window > 20 else 'MEDIUM'
                }
                
                # Avoid duplicate alerts
                if alert not in self.alerts:
                    self.alerts.append(alert)
                    print(f"⚠️ ALERT: Brute force detected from {ip} ({attempts_in_window} attempts)")
                break
    
    def check_user_enumeration(self, ip):
        """
        Check if an IP is performing user enumeration
        
        Args:
            ip (str): IP address to check
        """
        unique_users = len(self.used_usernames[ip])
        max_users = self.config['thresholds']['user_enumeration']['max_users']
        
        if unique_users >= max_users:
            alert = {
                'type': 'USER_ENUMERATION',
                'ip': ip,
                'unique_usernames': unique_users,
                'total_attempts': len(self.failed_attempts[ip]),
                'usernames': list(self.used_usernames[ip])[:10],  # First 10 only
                'severity': 'MEDIUM'
            }
            
            if alert not in self.alerts:
                self.alerts.append(alert)
                print(f"⚠️ ALERT: User enumeration from {ip} ({unique_users} different users)")
    
    def generate_csv_report(self, filename):
        """
        Generate CSV report of all alerts
        
        Args:
            filename (str): Output filename
        """
        if not self.alerts:
            print("ℹ️ No alerts to report")
            return
        
        # Ensure directory exists
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        
        with open(filename, 'w', newline='') as f:
            if self.alerts[0]['type'] == 'BRUTE_FORCE':
                fieldnames = ['type', 'ip', 'attempts', 'first_seen', 'last_seen', 'unique_usernames', 'severity']
            else:
                fieldnames = ['type', 'ip', 'unique_usernames', 'total_attempts', 'usernames', 'severity']
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for alert in self.alerts:
                # Convert datetime objects to strings
                alert_copy = alert.copy()
                if 'first_seen' in alert_copy:
                    alert_copy['first_seen'] = alert_copy['first_seen'].strftime('%Y-%m-%d %H:%M:%S')
                if 'last_seen' in alert_copy:
                    alert_copy['last_seen'] = alert_copy['last_seen'].strftime('%Y-%m-%d %H:%M:%S')
                if 'usernames' in alert_copy:
                    alert_copy['usernames'] = ', '.join(alert_copy['usernames'])
                
                writer.writerow(alert_copy)
        
        print(f"📊 Report saved to {filename}")
    
    def generate_json_report(self, filename):
        """
        Generate JSON report of all alerts
        
        Args:
            filename (str): Output filename
        """
        if not self.alerts:
            return
        
        # Ensure directory exists
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare data for JSON serialization
        report_data = []
        for alert in self.alerts:
            alert_copy = alert.copy()
            if 'first_seen' in alert_copy:
                alert_copy['first_seen'] = alert_copy['first_seen'].isoformat()
            if 'last_seen' in alert_copy:
                alert_copy['last_seen'] = alert_copy['last_seen'].isoformat()
            report_data.append(alert_copy)
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"📊 Report saved to {filename}")
    
    def print_summary(self):
        """Print a summary of the analysis"""
        print("\n" + "="*50)
        print("📋 ANALYSIS SUMMARY")
        print("="*50)
        
        # Top attacking IPs
        if self.failed_attempts:
            print("\n🔴 Top attacking IPs:")
            sorted_ips = sorted(self.failed_attempts.items(), 
                              key=lambda x: len(x[1]), reverse=True)[:5]
            for ip, attempts in sorted_ips:
                print(f"   {ip}: {len(attempts)} attempts ({len(self.used_usernames[ip])} users)")
        
        # Alert summary
        if self.alerts:
            print(f"\n⚠️ Total alerts: {len(self.alerts)}")
            brute_force = sum(1 for a in self.alerts if a['type'] == 'BRUTE_FORCE')
            enumeration = sum(1 for a in self.alerts if a['type'] == 'USER_ENUMERATION')
            print(f"   - Brute force: {brute_force}")
            print(f"   - User enumeration: {enumeration}")
        else:
            print("\n✅ No suspicious activity detected")
        
        print("="*50 + "\n")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Security Log Analyzer - Detect brute force attacks')
    parser.add_argument('logfile', help='Path to log file to analyze')
    parser.add_argument('--config', default='config.yaml', help='Configuration file (default: config.yaml)')
    parser.add_argument('--format', choices=['csv', 'json', 'both'], default='csv', 
                       help='Output format (default: csv)')
    parser.add_argument('--output', help='Output filename (default: reports/alerts_TIMESTAMP)')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = LogAnalyzer(args.config)
    
    # Analyze log file
    alerts = analyzer.analyze_file(args.logfile)
    
    if alerts:
        # Generate filename if not provided
        if not args.output:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_filename = f"reports/alerts_{timestamp}"
        else:
            base_filename = args.output
        
        # Generate reports
        if args.format in ['csv', 'both']:
            analyzer.generate_csv_report(f"{base_filename}.csv")
        if args.format in ['json', 'both']:
            analyzer.generate_json_report(f"{base_filename}.json")
    
    # Print summary
    analyzer.print_summary()


if __name__ == "__main__":
    main()