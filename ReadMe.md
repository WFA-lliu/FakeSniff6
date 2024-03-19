# FakeSniff6
---

## Usage:

```sh
usage: fakesniff.py [-h] [-v] [-a] [-d directory] [-f filename] [-s suffix] [-i interpreted] [-o oriented] [-r report] [-u uploading]

CLI argument parsing

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbosity
  -a, --auto            auto-mode
  -d directory, --directory directory
                        directory of UCC log and capture
  -f filename, --filename filename
                        filename of UCC log
  -s suffix, --suffix suffix
                        suffix of capture
  -i interpreted, --interpreted interpreted
                        interpreted handle
  -o oriented, --oriented oriented
                        oriented IP
  -r report, --report report
                        filename of report after interpreted under auto-mode
  -u uploading, --uploading uploading
                        directory for uploading
```

Note: **ptftpd** package should be installed (before running).

<details>
<summary><i>fakecall.py</i>, a companion for generic testbed</summary>

```sh
usage: fakecall.py [-h] [-v] [-a] [-n name] [-d directory] [-f filename] [-i interpreted] [-o oriented] [-r report]

CLI argument parsing

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbosity
  -a, --auto            auto-mode
  -n name, --name name  display name for specific handle
  -d directory, --directory directory
                        directory of UCC log and capture
  -f filename, --filename filename
                        filename of UCC log
  -i interpreted, --interpreted interpreted
                        interpreted handle
  -o oriented, --oriented oriented
                        oriented IP
  -r report, --report report
                        filename of report after interpreted under auto-mode
```

</details>

## Description:

A utility (tool) to validate the sniffer-agent by existing logs&captures. Test environments are simplified into sniffer-agent and this utility; elapsed time is shortened to the interaction time between sniffer-agent and this utility. This utility is design to be used in preliminary regression-test; this utility is not an alternate of regression-test.

## Prerequisite:

Current captured-file restoring mechanism is TFTP. This utility is built-in a TFTP client. A TFTP server is required to be installed on the sniffer-agent; tftpd-hpa is recommended.
<details>
<summary>tftpd-hpa setup</summary>

To install tftpd-hpa:

```sh
sudo apt-get install tftpd-hpa
```

To modify tftpd-hpa configuration file (/etc/default/tftpd-hpa) as:

```sh
# /etc/default/tftpd-hpa

TFTP_USERNAME="tftp"
# TFTP_DIRECTORY="/srv/tftp"
TFTP_DIRECTORY="/WTSSniffer"
TFTP_ADDRESS=":69"
# TFTP_OPTIONS="--secure"
TFTP_OPTIONS="-l -c -s"

#-c: Allow new files to be created
#-s: Change root directory on startup.
#-l: Run the server in standalone (listen) mode, rather than run from inetd.
```

To launch tftpd-hpa:

```sh
sudo service tftpd-hpa start
```
</details>

