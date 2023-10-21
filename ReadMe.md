# FakeSniff6
---

## Usage:

```sh
usage: fakesniff.py [-h] [-v] [-d directory] [-f filename] [-s suffix] [-i interpreted] [-o oriented]

CLI argument parsing

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbosity
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
```

## Motivation:

A utility/tool to validate the revised sniffer-agent by existing logs and captures would be helpful for regression test.

Current drawbacks for validating when the sniffer-agent is revised, either renewal or fixing:

- Machines are too many. Quality assurance member shall setup the environment for validating; a few machines including UCC core, testbeds, and the sniffer-agent, etc., should be setup accordingly. An environment just includes the revised sniffer-agent would be attractive.
- Elapsed time is too long. Every test case should be performed completely with testbeds and the revised sniffer-agent, the elapsed time is based on test case requirements and testbed performance. A procedure just includes the dissection of sniffer-agent would be attractive.

## Starting point:

> Read existing UCC log line by line;

> send the capture to sniffer-agent when _sniffer_control_start_ CAPI is read, perform dissection on sniffer-agent when _sniffer_control_field_check_ CAPI is read, and so on;

> determine whether the returned value of CAPI is the same as UCC log or not.

## Implementation considerations:

- The utility/tool might be running on a different machine of sniffer-agent; e.g. Python.
- The captured-file restoring mechanism should be trivial; e.g. TFTP.
