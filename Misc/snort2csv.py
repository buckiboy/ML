import csv

def parse_snort_log(log):
    parsed_logs = []
    log_entries = log.strip().split("\n\n")
    
    for entry in log_entries:
        try:
            lines = entry.strip().split("\n")
            if len(lines) < 3:
                raise ValueError(f"Log entry doesn't have enough lines: {entry}")
            
            # Extract signature name
            sig_name_line = lines[0]
            sig_name = sig_name_line.split('"')[1] if '"' in sig_name_line else "Unknown"
            
            # Extract timestamp and IP info
            ip_info_line = lines[2]
            parts = ip_info_line.split(" ")
            if len(parts) < 4:
                raise ValueError(f"IP info line doesn't have enough parts: {ip_info_line}")
            
            timestamp = parts[0]
            src_ip, src_port = parts[1].split(":")
            dst_ip, dst_port = parts[3].split(":")
            
            parsed_logs.append({
                "timestamp": timestamp,
                "sensor_address": "N/A",
                "sig_name": sig_name,
                "src": src_ip,
                "sport": src_port,
                "dst": dst_ip,
                "dport": dst_port
            })
        except IndexError as e:
            print(f"IndexError: {e}")
            print(f"Error parsing log entry: {entry}")
        except ValueError as e:
            print(f"ValueError: {e}")
            print(f"Error parsing log entry: {entry}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            print(f"Error parsing log entry: {entry}")
    
    return parsed_logs

# Read Snort logs from an external file
try:
    with open('snort_alerts.txt', 'r') as file:
        logs = file.read()
except FileNotFoundError:
    print("Error: snort_alerts.txt file not found.")
    exit(1)

# Parse the logs
parsed_logs = parse_snort_log(logs)

# Write to CSV
with open('snort_alerts.csv', 'w', newline='') as csvfile:
    fieldnames = ["timestamp", "sensor_address", "sig_name", "src", "sport", "dst", "dport"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for log in parsed_logs:
        writer.writerow(log)

