import argparse
import configparser
import os
import tempfile
import time
import zipfile

from tenable.io import TenableIO
from tenable.sc import TenableSC

# Create and read configuration file
config_file_name = 'tenable.ini'
config_file_data = """[tenable_io]
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
# By default tenable.sc uses a self signed SSL certificate so SSL verification will need to be skipped unless you have
# applied a valid SSL certificate. Most users will need to change this setting to False.
# Example: True or False (case-sensitive)
ssl_verify = True

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
"""
tempdir = tempfile.gettempdir()
parser = argparse.ArgumentParser(description='Copy scan data from tenable.io to tenable.sc')
parser_group = parser.add_mutually_exclusive_group(required=True)
parser_group.add_argument('--config', metavar='<tenable.ini>', dest='config_file',
                          help='INI config file')
parser_group.add_argument('--config-gen', dest='config_gen', action='store_true',
                          help='Generate a new INI config file.')
config_file = parser.parse_args().config_file
config_gen = parser.parse_args().config_gen
if config_file:
    if not os.path.isfile(config_file):
        print(config_file + ' does not exist. Use the --config-gen flag to create one.')
        exit()
    else:
        config = configparser.ConfigParser()
        config.read(config_file)
        tio_config = config['tenable_io']
        tsc_config = config['tenable_sc']
elif config_gen:
    if os.path.isfile('tenable.ini'):
        print('tenable.ini config file already exists and will NOT be overwritten.\nIf you want to create a new '
              'config file then either rename or delete the existing tenable.ini file.')
        exit()
    else:
        file = open(config_file_name, mode='w')
        file.write(config_file_data)
        file.close()
        if not os.path.isfile(config_file_name):
            print('Unable to write file: ' + config_file_name)
        else:
            print('Wrote file: ' + config_file_name)
        print('Edit the new INI configuration file for your environment.')
        exit()
else:
    print('Input error')
    exit()


def ssl_warn(product, config_section):
    if config_section.getboolean('ssl_verify') == False:
        print('WARNING: ' + product + ' SSL Verification has been disabled!')


ssl_warn('tenable.io', tio_config)
ssl_warn('tenable.sc', tsc_config)

# Create API clients
tio_client = TenableIO(
    tio_config['access_key'],
    tio_config['secret_key'],
    ssl_verify=tio_config.getboolean('ssl_verify'),
    proxies={"https": tio_config['https_proxy']}
)

tsc_client = TenableSC(
    tsc_config['host'],
    tsc_config['access_key'],
    tsc_config['secret_key'],
    ssl_verify=tsc_config.getboolean('ssl_verify'),
    proxies={"https": tsc_config['https_proxy']}
)

# Smuggle
scan_ids = tio_config['scan_ids'].replace(' ', '').split(',')
cutoff = int(time.time()) - (int(tio_config['age']) * 86400)
for scan_id in scan_ids:
    print('Scan ID ' + scan_id + ':')
    absolute_path_file = os.path.join(tempdir, scan_id + '.nessus')
    absolute_path_zip = absolute_path_file + '.zip'
    # Download scan from tenable.io
    for scan in tio_client.scans.history(scan_id, limit=1, pages=1):
        if scan['status'] == 'completed' and scan['time_end'] > cutoff:
            print('Downloading scan id ' + scan_id + ' from tenable.io to ' + absolute_path_file)
            with open(absolute_path_file, 'wb') as fobj:
                tio_client.scans.export(scan_id, fobj=fobj)
            print('Zipping ' + absolute_path_file)
            zipfile.ZipFile(
                absolute_path_zip,
                mode='w',
                compression=zipfile.ZIP_DEFLATED
            ).write(absolute_path_file, arcname=scan_id + '.nessus')
            # Upload scan to tenable.sc
            if os.path.getsize(absolute_path_zip) <= (1500 * 1000000):
                print('Uploading ' + absolute_path_zip + ' to tenable.sc')
                with open(absolute_path_zip, 'rb') as fobj:
                    tsc_client.scan_instances.import_scan(
                        fobj=fobj,
                        repo=tsc_config['repository_id'],
                        host_tracking=tsc_config['dhcp'],
                        vhosts=tsc_config['virtual_hosts'],
                        auto_mitigation=tsc_config['dead_hosts_wait']
                    )
            else:
                print('Scan file exceeds tenable.sc\'s default maximum upload size of 1500 MB.')
            
            # Remove files from disk
            def verified_remove(absolute_path_file):
                os.remove(absolute_path_file)
                if os.path.isfile(absolute_path_file):
                    print('Unable to delete file ' + absolute_path_file + ' from disk')
                else:
                    print('Deleted file ' + absolute_path_file + ' from disk')
            verified_remove(absolute_path_file)
            verified_remove(absolute_path_zip)
        else:
            print('This scan is either still running or more than ' + tio_config['age'] +
                  ' day(s) old, as specified in the config file. This scan will not be uploaded to tenable.sc.')
