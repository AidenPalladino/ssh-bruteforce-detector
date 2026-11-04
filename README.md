# SSH Brute-Force Detector

A short Python script that reads a Linux `auth.log` and flags IPs with 10 or more failed SSH logins.

## 1. What a failed login looks like

Linux logs every SSH attempt in `auth.log`. A failed one looks like this:

```
Oct 14 02:14:03 webserver sshd[4821]: Failed password for root from 203.0.113.45 port 51234 ssh2
```

The IP always comes right after the word `from`, so that's what the script grabs.

## 2. How the script works

[`simple_analyzer.py`](simple_analyzer.py) goes through the log line by line, skips anything that isn't a `Failed password` line, pulls the IP, and counts failures per IP in a dictionary. Anything at 10 or more gets printed. It only uses built-in Python.

```
python simple_analyzer.py
```

## 3. Run it on the sample log

I ran it against `sample_auth.log`, a generated log in the real format. The IPs are from ranges reserved for documentation, so they aren't real hosts. It flagged three IPs:

![Script output showing three flagged IPs](screenshot-results.png)

## 4. Check the flagged IPs in the log

- `203.0.113.45`: 60 failures in about two minutes, cycling through `root`, `admin`, `test`, etc. Classic automated attack.
- `198.51.100.77`: 25 failures on `devops`, then a successful login. This is the one that matters most, since it probably guessed the password. I found that by reading the log, not from the script.
- `203.0.113.200`: 12 failures spread over a few hours. It got flagged, but only because the script never looks at time.

## Limitations

- **No time window.** 10 failures in a minute and 10 failures in a month look the same.
- **Doesn't catch the break-in.** It never checks whether a failing IP later logged in successfully, which is the worst case.
- **Hardcoded file name.** You can't point it at a different log yet.
