# sneaky-bunny
behavior monitor for linux environments and termux

scans system pids via /proc filesystem
detects binaries running from temporary directories (/tmp, /dev/shm)
checks process memory maps for suspicious read-write-execute (rwx) permissions

requires root access to analyze core process memory structures
sudo python3 main.py
<img width="1845" height="853" alt="Screenshot_20260603_055307" src="https://github.com/user-attachments/assets/109e9222-f954-45c3-a944-eb0670dd0838" />
