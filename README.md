# SSH Brute-Force Detector

A Python script that reads a Linux server's login log and flags IP addresses that look like they're trying to brute-force their way in.

## Why I built this

Brute-force attacks are one of the most common attacks on internet-facing servers. An attacker runs a tool that guesses passwords over and over until one works. I wanted to understand how security analysts spot this in log data, so I built a simple detector myself.

## How it works

Linux records every SSH login attempt in a log file called `auth.log`. A failed attempt looks like this:

```
Oct 14 02:14:03 webserver sshd[4821]: Failed password for root from 203.0.113.45 port 51234 ssh2
```

The script:

1. Reads the log file one line at a time
2. Skips every line that isn't a failed login
3. Splits the line into words and grabs the IP address, which always comes right after the word `from`
4. Keeps a count of failed logins for each IP in a dictionary
5. Prints every IP with 10 or more failed logins

## How to run it

Put `simple_analyzer.py` and `sample_auth.log` in the same folder, then run:

```
python simple_analyzer.py
```

No extra libraries are needed. It only uses built-in Python.


See the full script here: [simple_analyzer.py](simple_analyzer.py)

## Results

<img width="374" height="115" alt="image" src="https://github.com/user-attachments/assets/50fac538-e712-4cf7-8745-442e35131855" />



What the results show:

- **203.0.113.45** made 60 failed attempts in about two minutes, trying common usernames like `root`, `admin`, and `test`. This is a classic automated brute-force attack.
- **198.51.100.77** made 25 failed attempts on the `devops` account and then logged in successfully, which means it likely guessed the password. In a real environment, this account would need to be locked and investigated.
- **203.0.113.200** made 12 attempts spread out over several hours. This "low and slow" approach is a way attackers try to avoid getting noticed.

## About the test data

`sample_auth.log` is a generated log in the real Linux `auth.log` format. All IP addresses come from ranges reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so none of them are real hosts.

## Limitations and next steps

- **No time window.** The script counts total failures, so 10 failures in one minute looks the same as 10 failures over a month. Next I want to track timestamps and only flag IPs with many failures in a short period.
- **Doesn't detect successful break-ins.** I want to flag any IP that fails many times and then logs in successfully, since that's the most dangerous case.
- **Hardcoded file name.** I plan to let the user pass in any log file.

## What I learned

- How Linux records SSH login attempts in `auth.log`
- How to parse text data in Python using `split()` and list indexing
- How to use a dictionary to count events per IP
- How a basic detection rule works, and why a single rule can miss attacks
