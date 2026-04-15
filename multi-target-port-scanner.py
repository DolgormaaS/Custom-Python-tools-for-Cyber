import socket #for scanning the ports
import sys #for reading command line args

def scanner(filename, choice):
    common_ports = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet (usually vulnerable)
        25,    # SMTP
        53,    # DNS
        67, 68,# DHCP
        69,    # TFTP
        80,    # HTTP
        110,   # POP3
        111,   # RPCBind
        119,   # NNTP
        123,   # NTP
        137, 138, 139,  # NetBIOS
        143,   # IMAP
        161,   # SNMP
        179,   # BGP
        389,   # LDAP
        443,   # HTTPS
        445,   # SMB (VERY important)
        465,   # SMTPS
        500,   # ISAKMP (VPN)
        514,   # Syslog
        515,   # Printer
        520,   # RIP
        587,   # SMTP (submission)
        636,   # LDAPS
        989, 990, # FTPS
        993,   # IMAPS
        995,   # POP3S
        1433,  # MSSQL
        1521,  # Oracle DB
        2049,  # NFS
        2082, 2083, # cPanel
        2086, 2087, # WHM
        2181,  # Zookeeper
        2222,  # Alt SSH
        2375, 2376, # Docker
        2483, 2484, # Oracle
        3000,  # Dev servers
        3306,  # MySQL
        3389,  # RDP
        3690,  # SVN
        4444,  # Metasploit default
        4567,  # Sinatra
        5000,  # Flask / dev servers
        5432,  # PostgreSQL
        5601,  # Kibana
        5900,  # VNC
        5985, 5986, # WinRM
        6379,  # Redis (common misconfig)
        6667,  # IRC
        7001,  # WebLogic
        8000, 8008, 8080, 8081, # Alt HTTP
        8088,  # Hadoop
        8090, 8091, # CouchDB
        8443,  # Alt HTTPS
        8888,  # Jupyter
        9000,  # SonarQube
        9042,  # Cassandra
        9090,  # Prometheus
        9092,  # Kafka
        9200,  # Elasticsearch (big one)
        9418,  # Git
        9999,  # Misc services
        27017  # MongoDB
    ]

    quick_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443]   

    with open(filename, 'r') as file:
        for host in file:
            if host == "":
                continue
            host = host.strip() #delete newline \n
            print("Scanning: " + host)
            if choice == 1:
                for port in common_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    exists = sock.connect_ex((host, port))
                    if exists == 0:
                        print(f"{port} is open")
                    sock.close()
            elif choice == 2:
                for port in quick_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    exists = sock.connect_ex((host, port))
                    if exists == 0:
                        print(f"{port} is open")
                    sock.close()

if len(sys.argv) < 2:
    print("Usage: python3 multi-target-port-scanner.py <filename>")
    sys.exit(1)

choice = int(input("Choose 1 for full scan, 2 for quick scan: "))
if choice != 1 and choice != 2:
    print("Choose 1 or 2")
    sys.exit(1)
scanner(sys.argv[1], choice)
