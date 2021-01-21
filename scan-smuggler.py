import argparse
import configparser
import os
from tenable.io import TenableIO
from tenable.sc import TenableSC
import tempfile
import time

# Create and read configuration file
config_file_name = 'tenable.ini'
config_file_data = """[tenable_io]
########
# Connection info
########
access_key = {{ACCESS_KEY}}
secret_key = {{SECRET_KEY}}
https_proxy =
########
# Scan download options
########
# Scan IDs to download
scan_ids = 100, 101, 102, 103, 104
# Only download scan data if scan completed within x day(s)
# This value should coincide with your timer/cron entry. If the timer/cron entry runs daily then sent this value to 1,
# if the timer/cron entry runs weekly then set this value to 7, etc.
age = 1

[tenable_sc]
########
# Connection info
########
host = 127.0.0.1
access_key = {{ACCESS_KEY}}
secret_key = {{SECRET_KEY}}
ssl_verify = False
https_proxy =
########
# Scan upload settings
# See https://docs.tenable.com/sccv/Content/UploadScanResults.htm for context
########
# Repository ID to upload to
repository_id = 1
# Track hosts which have been issued new IP address, (e.g. DHCP)
dhcp = true
# Scan Virtual Hosts (e.g. Apache VirtualHosts, IIS Host Headers)
virtual_hosts = false
# Immediately remove vulnerabilities from scanned hosts that do not reply
# Number of days to wait before removing dead hosts
# 0 = Immediately remove
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

# Establish API clients
tio_client = TenableIO(tio_config['access_key'], tio_config['secret_key'])
tsc_client = TenableSC(tsc_config['host'], tsc_config['access_key'], tsc_config['secret_key'])

# Smuggle
scan_ids = tio_config['scan_ids'].replace(' ', '').split(',')
cutoff = int(time.time()) - (int(tio_config['age']) * 86400)
for scan_id in scan_ids:
    print('Scan ID ' + scan_id + ':')
    file_loc = os.path.join(tempdir, scan_id + '.nessus')
    # Download scan from tenable.io
    for scan in tio_client.scans.history(scan_id, limit=1, pages=1):
        if scan['status'] == 'completed' and scan['time_end'] > cutoff:
            print('Downloading scan id ' + scan_id + ' from tenable.io to ' + file_loc)
            with open(file_loc, 'wb') as fobj:
                tio_client.scans.export(scan_id, fobj=fobj)
            # Upload scan to tenable.sc
            if os.path.getsize(file_loc) <= (300 * 1000000):
                print('Uploading ' + file_loc + ' to tenable.sc')
                with open(file_loc) as fobj:
                    tsc_client.scan_instances.import_scan(
                        fobj=fobj,
                        repo=tsc_config['repository_id'],
                        host_tracking=tsc_config['dhcp'],
                        vhosts=tsc_config['virtual_hosts'],
                        auto_mitigation=tsc_config['dead_hosts_wait']
                    )
            else:
                print('Scan file exceeds tenable.sc\'s default maximum upload size of 300 MB. '
                      'See https://docs.tenable.com/sccv/Content/UploadScanResults.htm '
                      'for instructions to accommodate larger file uploads')
            # Delete .nessus file from local disk
            os.remove(file_loc)
            if os.path.isfile(file_loc):
                print('Unable to delete file ' + file_loc + ' from local disk')
            else:
                print('Deleted file ' + file_loc + ' from local disk')
        else:
            print('This scan is either still running or more than ' + tio_config['age'] +
                  ' days old, as specified in the config file. This scan will not be uploaded to tenable.sc.')
