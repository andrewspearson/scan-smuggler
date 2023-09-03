# scan-smuggler
scan-smuggler.py downloads Nessus scan data from Tenable.IO and uploads it to Tenable.SC.

For a more complex and powerful version of this tool, take a look at [super-scan-smuggler](https://github.com/andrewspearson/super-scan-smuggler).
## Requirements
* python3
* [pyTenable](https://github.com/tenable/pyTenable)
* Tenable.SC 5.13 or later is required for [API keys](https://docs.tenable.com/tenablesc/Content/GenerateAPIKey.htm)
## Installation
### Python virtual environment
```
$ git clone https://github.com/andrewspearson/scan-smuggler.git /usr/local/bin/scan-smuggler
$ python3 -m venv /usr/local/bin/scan-smuggler/venv
$ . /usr/local/bin/scan-smuggler/venv/bin/activate
$ pip install -r requirements.txt
$ deactivate
```
### Cron entry
```
$ crontab -l

0 8 * * * /usr/local/bin/scan-smuggler/venv/bin/python /usr/local/bin/scan-smuggler/scan-smuggler.py --config /usr/local/bin/scan-smuggler/tenable.ini
```
## Usage
### Python virtual environment
View the help menu
```
$ cd /usr/local/bin
$ ./venv/bin/python scan-smuggler.py -h

usage: scan-smuggler.py [-h] (--config <tenable.ini> | --config-gen)

Copy scan data from tenable.io to tenable.sc

optional arguments:
  -h, --help            show this help message and exit
  --config <tenable.ini>
                        INI config file
  --config-gen          Generate a new INI config file.
```
Generate a configuration file
```
$ ./venv/bin/python scan-smuggler.py --config-gen

Wrote file: tenable.ini
Edit the new INI configuration file for your environment.
```
Edit the configuration file so it looks something like this
```
$ cat tenable.ini

########
# Connection info
########

# API keys
# Example: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
access_key = deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
secret_key = deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

# Verify SSL connection or ignore SSL verification errors
# Example: True or False (case-sensitive)
ssl_verify = True

# HTTPS proxy
# IP, hostname, or FQDN
# blank = no proxy
# Example: 192.0.2.1:8080, proxy.example.com or blank
https_proxy = 

########
# Scan download options
########

# Scan IDs to download
# Example: 100 or 100, 101, 102
scan_ids = 100, 101, 102

# Maximum scan result age
# Only download scan data if scan completed within x day(s)
# This value should coincide with your timer/cron entry. If the timer/cron entry runs daily then sent this value to 1,
# if the timer/cron entry runs weekly then set this value to 7, etc.
# Example: 1
age = 1

[tenable_sc]
########
# Connection info
########

# IP, hostname, or FQDN
# Example: 192.0.2.2 or tenablesc.example.com
host = 192.0.2.2

# API keys
# Example: deadbeefdeadbeefdeadbeefdeadbeef
access_key = deadbeefdeadbeefdeadbeefdeadbeef
secret_key = deadbeefdeadbeefdeadbeefdeadbeef

# Verify SSL connection or ignore SSL verification errors
# By default tenable.sc uses a self signed certificate so SSL verification must be skipped to complete a connection.
# Example: True or False (case-sensitive)
ssl_verify = False

# HTTPS proxy
# IP, hostname, or FQDN
# blank = no proxy
# Example: 192.0.2.1:8080, proxy.example.com or blank
https_proxy = 

########
# Scan upload settings
# See https://docs.tenable.com/security-center/Content/UploadScanResults.htm and
# https://docs.tenable.com/security-center/Content/ActiveScanSettings.htm for context
########

# Repository ID to upload to
# Example: 1
repository_id = 1

# Track hosts which have been issued new IP address, (e.g. DHCP)
# Example: true (case-sensitive)
dhcp = true

# Scan Virtual Hosts (e.g. Apache VirtualHosts, IIS Host Headers)
# Example: false (case-sensitive)
virtual_hosts = false

# Immediately remove vulnerabilities from scanned hosts that do not reply
# Number of days to wait before removing dead hosts
# 0 = Immediately remove
# Example: 0
dead_hosts_wait = 0
```
Run the script
```
$ ./venv/bin/python scan-smuggler.py --config tenable.ini

Scan ID 2366:
Downloading scan id 2366 from tenable.io to /tmp/2366.nessus
Uploading /tmp/2366.nessus to tenable.sc
Deleted file /tmp/2366.nessus from local disk
Scan ID 2368:
Downloading scan id 2368 from tenable.io to /tmp/2368.nessus
Uploading /tmp/2368.nessus to tenable.sc
Deleted file /tmp/2368.nessus from local disk
```
## Results

![uploaded-scans](https://andrewspearson.github.io/file-server/repositories/scan-smuggler/uploaded-scans.png)
