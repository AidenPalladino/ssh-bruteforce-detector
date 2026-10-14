# simple_analyzer.py
# Counts failed SSH logins per IP address and flags suspicious ones.

THRESHOLD = 10  # flag any IP with this many failed logins or more

failed_counts = {}  # dictionary: IP address -> number of failed logins

# Step 1: open the log file and read it one line at a time
file = open("sample_auth.log", "r")

for line in file:
    # Step 2: only care about failed login lines
    if "Failed password" in line:
        # Step 3: split the line into a list of words
        words = line.split()

        # The IP address is always the word right after "from"
        spot = words.index("from")
        ip = words[spot + 1]

        # Step 4: add 1 to this IP's count
        if ip in failed_counts:
            failed_counts[ip] = failed_counts[ip] + 1
        else:
            failed_counts[ip] = 1

file.close()

# Step 5: print every IP that went over the threshold
print("Suspicious IPs:")
for ip in failed_counts:
    if failed_counts[ip] >= THRESHOLD:
        print(ip, "-", failed_counts[ip], "failed logins")
