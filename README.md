# sneaky-bunny
behavior monitor for linux environments and termux

scans system pids via /proc filesystem
detects binaries running from temporary directories (/tmp, /dev/shm)
checks process memory maps for suspicious read-write-execute (rwx) permissions

requires root access to analyze core process memory structures
sudo python3 main.py
