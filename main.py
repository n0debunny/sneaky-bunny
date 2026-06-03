import sys
import os
from scanner import run_scan

def main():
    if os.getuid() != 0:
        print('error: root privileges required')
        sys.exit(1)
        
    print('[-] starting endpoint behavior scan...')
    results = run_scan()
    
    if not results:
        print('[+] scan finished: no suspicious processes detected')
        sys.exit(0)
        
    print(f'[!] warning: {len(results)} anomalies found\n')
    print(f'{"pid":<10} {"rwx":<6} {"path_alert":<12} {"binary_path"}')
    print('-' * 60)
    
    for alert in results:
        pid = alert['pid']
        rwx = 'yes' if alert['rwx'] else 'no'
        path_alert = 'yes' if alert['path_alert'] else 'no'
        path = alert['path']
        print(f'{pid::<10} {rwx:<6} {path_alert:<12} {path}')

if __name__ == '__main__':
    main()
