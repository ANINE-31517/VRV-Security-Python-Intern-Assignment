import re
import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    for log in logs:
        ip_match = re.match(r'(\S+) - -', log)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_count[ip_address] += 1

        endpoint_match = re.search(r'"(?:GET|POST) (\S+) HTTP', log)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_count[endpoint] += 1

        if '401' in log or 'Invalid credentials' in log:
            failed_login_attempts[ip_address] += 1

    return ip_count, endpoint_count, failed_login_attempts

def get_most_accessed_endpoint(endpoint_count):
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=(None, 0))
    return most_accessed

def detect_suspicious_activity(failed_login_attempts):
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_results_to_csv(ip_count, most_accessed, suspicious_ips, output_file='log_analysis_results.csv'):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_file_path = 'sample.log' 
    logs = parse_log_file(log_file_path)
    
    ip_count, endpoint_count, failed_login_attempts = count_requests_per_ip(logs)
    most_accessed_endpoint = get_most_accessed_endpoint(endpoint_count)
    suspicious_activity = detect_suspicious_activity(failed_login_attempts)
    
    print("IP Address           Request Count")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")
    
    save_results_to_csv(ip_count, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()