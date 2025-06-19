import re
from collections import Counter

# Define file paths
log_file = "./312/out_dst.txt"  # Change this to your Snort alert log file
output_file = "sum_dst.txt"  # Output summary file

# Regular expression to extract alert messages
alert_pattern = re.compile(r'\[.*?\] \[.*?\] "(.*?)" \[.*?\]')

# Dictionary to store alert counts
alert_counter = Counter()

# Read the log file and process alerts
with open(log_file, "r") as file:
    for line in file:
        match = alert_pattern.search(line)
        if match:
            alert_message = match.group(1)  # Extract alert description
            alert_counter[alert_message] += 1

# Write the summary to a file
with open(output_file, "w") as output:
    output.write("### Snort Alert Summary ###\n")
    for alert, count in alert_counter.most_common():
        output.write(f"{alert}: {count}\n")

print(f"Alert summary has been written to {output_file}")
