# SSH Brute-Force Detector

A short Python script that reads a Linux `auth.log` and flags IPs with 10 or more failed SSH logins.

## How it works

A failed login in `auth.log` looks like this:

```
Oct 14 02:14:03 webserver sshd[4821]: Failed password for root from 203.0.113.45 port 51234 ssh2
```

The script goes line by line, skips anything that isn't a `Failed password` line, pulls the IP that comes after `from`, and counts failures per IP in a dictionary. Anything at 10 or more gets printed.

## Running it

```
python simple_analyzer.py
```

It reads `sample_auth.log` from the same folder. No extra libraries needed.

## Results

![results](screenshot-results.png)

Looking at those three IPs in the log:

- `203.0.113.45`: 60 failures in about two minutes, cycling through `root`, `admin`, `test`, etc. Classic automated attack.
- `198.51.100.77`: 25 failures on `devops`, then a successful login. This is the one that matters most, since it probably guessed the password. I found that by reading the log, not from the script.
- `203.0.113.200`: 12 failures spread over a few hours. It got flagged, but only because the script never looks at time.

`sample_auth.log` is a generated log in the real format. The IPs are from ranges reserved for documentation, so they aren't real hosts.

## Limitations

- **No time window.** 10 failures in a minute and 10 failures in a month look the same.
- **Doesn't catch the break-in.** It never checks whether a failing IP later logged in successfully, which is the worst case.
- **Hardcoded file name.** You can't point it at a different log yet.
