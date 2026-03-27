"""
Author: <Muhammet Yusuf OZCAN>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""


# socket, threading, sqlite3, os, platform, datetime
import socket
import sys
import platform
import threading
import sqlite3
import datetime
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)
result = sock.connect_ex(("127.0.0.1", 80))
if result == 0:
    print("Port open")
else:
    print("Port closed")
sock.close()



PythonVersion = platform.python_version()
name = platform.system();
print("Python version:", PythonVersion)
print("OS Name:", name)

# Maps port numbers to their service names like HTTP, SSH, FTP
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self,target):
        self.__target = target

# Q3: What is the benefit of using @property and @target.setter?
# @property lets us read the private __target attribute safely.
# @target.setter lets us add validation when setting a new value.
# For example, if someone tries to set an empty string, the setter
# rejects it and keeps the old value instead of allowing invalid data.
    @property
    def target(self):
            return self.__target

    @target.setter
    def target(self,target):
        if target == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = target

    def __del__(self):
        print("NetworkTool instance destroyed")



# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool by calling super().__init__(target),
# which sets up the target attribute and its validation. For example,
# PortScanner uses the @property getter and @setter from NetworkTool
# without rewriting them. Without inheritance we would have to
# re define the target property and validation in PortScanner again.
class PortScanner(NetworkTool):
    def __init__(self,target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

# Q4: What would happen without try-except here?
# Without try-except, if an error occurs while scanning a port,
# the program would crash and stop immediately. With try-except,
# we can catch the error, understand what the issue is,
# and the program continues scanning the remaining ports.
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            if port in common_ports:
                service_name = common_ports[port]
            else:
                service_name = "Unknown"

            self.lock.acquire()
            self.scan_results.append((port,status,service_name))
            self.lock.release()
        except socket.error as errorMessage:
            print(f"Error scanning port {port}: {errorMessage}")
        finally:
            sock.close()

    def get_open_ports(self):

        return [result for result in self.scan_results
            if result[1] == "Open"]


# Q2: Why do we use threading instead of scanning one port at a time?
# Threading lets us scan multiple ports at the same time. Without threading,
# each port would be scanned one by one and it would take much more time.

    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port):
            t = threading.Thread(target = self.scan_port, args = (port,))
            threads.append(t)

        for t in threads:
                t.start()


        for t in threads:
                t.join()




def save_results(target, results):
        try:
            scan_history = sqlite3.connect("scan_history.db")
            cursor = scan_history.cursor()

            cursor.execute('''CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )''')

            for port,status, service in results:
                cursor.execute(
                    "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                    (target, port,status,service, str(datetime.datetime.now()))
                )

            scan_history.commit()
            scan_history.close()

        except sqlite3.Error as e:
            print(f"Database error: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            target, port, status, service, scan_date = row
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":

    # - Target IP (default "127.0.0.1" if empty)
    target_ip = input("Target IP: ").strip()
    if target_ip == "":
        target_ip = "127.0.0.1"


    try:
        start_port = int(input("Start Port (1-1024): "))
        end_port = int(input("End Port (1-1024): "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()
            print(f"--- Scan Results for {target_ip} ---")
            for port in open_ports:
                print(f"Port {port[0]}: {port[1]} ({port[2]})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target_ip, scanner.scan_results)

            history = input("Would you like to see past scan history? (yes/no): ")
            if history == "yes":
                load_past_scans()
    except ValueError:
        print("Invalid input. Please enter a valid integer")

# Q5: New Feature Proposal
# I would add a scan summary report that shows how many ports are open,
# closed, and how many open ports have known or unknown services.
# It would use a nested if-statement: the outer if checks if the port
# is open, and the inner if checks if the service is known or unknown.
# Diagram: See diagram_101462079.png in the repository root
