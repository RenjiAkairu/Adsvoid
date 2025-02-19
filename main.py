# main.py
from flask import Flask, render_template
import mysql.connector
import requests
import schedule
import time
from threading import Thread
from datetime import datetime
import socket
import struct
import config
from flask import Flask, render_template, request, redirect, url_for, jsonify
import signal
import sys
import logging
from logging.handlers import TimedRotatingFileHandler
import os
import psutil
import math

# Move DNSQuery class definition inside DNSServer to ensure it's accessible
class DNSServer:
    class DNSQuery:
        def __init__(self, data):
            self.data = data
            self.domain = ''
            tipo = (data[2] >> 3) & 15
            if tipo == 0:
                ini = 12
                lon = data[ini]
                while lon != 0:
                    self.domain += data[ini + 1:ini + lon + 1].decode() + '.'
                    ini += lon + 1
                    lon = data[ini]
                self.domain = self.domain[:-1]

        def response(self, ip):
            packet = self.data[:2] + b'\x81\x80'
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'
            packet += self.data[12:]
            packet += b'\xc0\x0c'
            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
            packet += struct.pack('!I', int.from_bytes(socket.inet_aton(ip), 'big'))
            return packet

    def __init__(self, db_config):
        self.db_config = db_config
        self.blocked_ip = '0.0.0.0'
        # Primary DNS servers
        self.primary_dns = [
            ('8.8.8.8', 53),    # Google DNS
            ('1.1.1.1', 53),    # Cloudflare
        ]
        # Backup DNS servers
        self.backup_dns = [
            ('8.8.4.4', 53),    # Google DNS backup
            ('1.0.0.1', 53),    # Cloudflare backup
            ('9.9.9.9', 53),    # Quad9
        ]
        self.cache = {}
        self.cache_timeout = 1800  # 30 minutes cache
        self.cache_min_timeout = 300  # 5 minutes minimum cache
        self.running = True
        self.udps = None
        self.max_packet_size = 4096
        self.query_timeout = 2  # DNS query timeout in seconds

    def stop(self):
        """Safely stop the DNS server"""
        self.running = False
        if self.udps:
            try:
                # Force socket to close and release port 53
                self.udps.shutdown(socket.SHUT_RDWR)
                self.udps.close()
            except:
                pass

    def is_domain_blocked(self, domain):
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM blocked_domains d
                    JOIN domain_sources ds ON d.id = ds.domain_id
                    JOIN blocklist_sources s ON ds.source_id = s.id
                    WHERE d.domain = %s AND s.enabled = TRUE
                )
            """, (domain,))
            
            is_blocked = cursor.fetchone()[0] > 0
            conn.close()
            return is_blocked
        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            return False

    def log_dns_query(self, domain, client_ip, action):
        """Log DNS query to database and file"""
        try:
            # Database logging
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO dns_logs (timestamp, domain, client_ip, action, log_entry)
                VALUES (NOW(), %s, %s, %s, %s)
            """, (
                domain,
                client_ip,
                action,
                f"{action} - Client: {client_ip}, Domain: {domain}"
            ))
            
            conn.commit()
            conn.close()
            
            # File logging
            log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {action} - Client: {client_ip}, Domain: {domain}"
            dns_logger.info(log_entry)
            
        except mysql.connector.Error as err:
            print(f"Database logging error: {err}")
            # Ensure file logging still works even if database fails
            log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {action} - Client: {client_ip}, Domain: {domain}"
            dns_logger.info(log_entry)
                
    def handle_dns_request(self, data, addr):
        """Handle a single DNS request"""
        try:
            query = self.DNSQuery(data)
            client_ip = addr[0]
            
            print(f"Processing query for {query.domain} from {client_ip}")
            
            # Check cache first
            cached = self.check_cache(query.domain)
            if cached:
                print(f"Cache hit for {query.domain}")
                self.log_dns_query(query.domain, client_ip, 'CACHED')
                return cached
            
            # Check if domain is blocked
            if self.is_domain_blocked(query.domain):
                print(f"Blocking domain: {query.domain}")
                response = query.response(self.blocked_ip)
                self.update_cache(query.domain, response)
                self.log_dns_query(query.domain, client_ip, 'BLOCKED')
                return response
            
            # Try primary DNS servers first
            response = self.query_dns_servers(data, self.primary_dns)
            if response:
                self.update_cache(query.domain, response)
                self.log_dns_query(query.domain, client_ip, 'ALLOWED')
                return response
            
            # If primary servers fail, try backup servers
            response = self.query_dns_servers(data, self.backup_dns)
            if response:
                self.update_cache(query.domain, response)
                self.log_dns_query(query.domain, client_ip, 'ALLOWED')
                return response
            
            # If all servers fail, return error response
            print(f"All DNS servers failed for {query.domain}")
            self.log_dns_query(query.domain, client_ip, 'ERROR')
            return query.response(self.blocked_ip)
            
        except Exception as e:
            print(f"Error processing DNS request: {e}")
            return query.response(self.blocked_ip)
        
    def query_dns_servers(self, data, dns_servers):
        """Query a list of DNS servers until successful response"""
        for dns_server in dns_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.query_timeout)
                sock.sendto(data, dns_server)
                response, _ = sock.recvfrom(self.max_packet_size)
                return response
            except socket.timeout:
                print(f"Timeout from DNS server {dns_server[0]}")
                continue
            except Exception as e:
                print(f"Error querying DNS server {dns_server[0]}: {e}")
                continue
            finally:
                sock.close()
        return None
    
    def update_cache(self, domain, response):
        """Update DNS cache with new response"""
        self.cache[domain] = {
            'response': response,
            'timestamp': time.time(),
            'hits': 0
        }

    def check_cache(self, domain):
        """Check if domain is in cache and not expired"""
        if domain in self.cache:
            entry = self.cache[domain]
            current_time = time.time()
            age = current_time - entry['timestamp']
            
            # Update cache hits
            entry['hits'] = entry['hits'] + 1
            
            # Extend cache time for frequently accessed domains
            if entry['hits'] > 10:
                timeout = self.cache_timeout
            else:
                timeout = self.cache_min_timeout
                
            if age < timeout:
                return entry['response']
            else:
                del self.cache[domain]
        return None

    def run_server(self):
        """Run the DNS server"""
        print("Starting DNS Server...")
        while self.running:
            try:
                if self.udps is None:
                    self.udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        self.udps.bind(('', 53))
                        print("Successfully bound to port 53")
                    except PermissionError:
                        print("Error: Permission denied. Make sure you run as administrator/root")
                        return
                    except socket.error as e:
                        print(f"Socket error: {e}")
                        print("Make sure no other DNS server is running on port 53")
                        return
                    
                    self.udps.settimeout(0.5)

                try:
                    data, addr = self.udps.recvfrom(self.max_packet_size)
                    if not self.running:
                        break
                        
                    response = self.handle_dns_request(data, addr)
                    if response:
                        self.udps.sendto(response, addr)
                        
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    print("Connection reset. Recreating socket...")
                    self.udps = None
                    continue
                except Exception as e:
                    print(f"Error in main loop: {e}")
                    if self.running:
                        time.sleep(1)

            except Exception as e:
                print(f"Critical error: {e}")
                if self.running:
                    time.sleep(1)
                    self.udps = None

        if self.udps:
            self.udps.close()
        print("DNS Server stopped.")
            
def setup_database():
    """Create the database and tables if they don't exist"""
    try:
        # First connection to create database
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD
        )
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config.DB_NAME}")
        cursor.execute(f"USE {config.DB_NAME}")  # Select the database first
        
        # Drop the existing dns_logs table if it exists
        cursor.execute("DROP TABLE IF EXISTS dns_logs")
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_domains (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain VARCHAR(255) UNIQUE,
                date_added DATETIME
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocklist_sources (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(512) UNIQUE,
                name VARCHAR(255),
                enabled BOOLEAN DEFAULT TRUE,
                last_update DATETIME,
                total_domains INT DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_sources (
                domain_id INT,
                source_id INT,
                FOREIGN KEY (domain_id) REFERENCES blocked_domains(id),
                FOREIGN KEY (source_id) REFERENCES blocklist_sources(id),
                PRIMARY KEY (domain_id, source_id)
            )
        """)

        # Create dns_logs table with correct ENUM values
        cursor.execute("""
            CREATE TABLE dns_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log_entry TEXT,
                domain VARCHAR(255),
                client_ip VARCHAR(45),
                action ENUM('BLOCKED', 'ALLOWED', 'ERROR', 'CACHED', 'localhost') NOT NULL,
                INDEX idx_timestamp (timestamp),
                INDEX idx_domain (domain),
                INDEX idx_action (action)
            )
        """)
        
        # Insert default sources if table is empty
        cursor.execute("SELECT COUNT(*) FROM blocklist_sources")
        if cursor.fetchone()[0] == 0:
            default_sources = [
                ("https://adaway.org/hosts.txt", "AdAway Default"),
                ("https://v.firebog.net/hosts/static/w3kbl.txt", "Firebog W3KBL")
            ]
            cursor.executemany("""
                INSERT IGNORE INTO blocklist_sources (url, name)
                VALUES (%s, %s)
            """, default_sources)
        
        conn.commit()
        print("Database setup completed successfully!")
        conn.close()
        return True
        
    except mysql.connector.Error as err:
        print(f"Database setup error: {err}")
        return False

def parse_domain_line(line):
    """Parse a line from hosts file and extract domain, handling different formats"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
        
    # Split the line into parts
    parts = line.split()
    
    # Common formats:
    # 1. "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
    # 2. "domain.com" (plain domain)
    # 3. "||domain.com^" (adblock format)
    # 4. "address=/domain.com/0.0.0.0" (dnsmasq format)
    
    if len(parts) >= 2 and (parts[0] == '0.0.0.0' or parts[0] == '127.0.0.1'):
        return parts[1]
    elif len(parts) == 1:
        if parts[0].startswith('||'):
            # Remove adblock syntax
            domain = parts[0].replace('||', '').replace('^', '')
            return domain
        elif not any(c in parts[0] for c in ['*', '/', '@', '!']):
            return parts[0]
    elif 'address=/' in line:
        # Handle dnsmasq format
        try:
            domain = line.split('address=/')[1].split('/')[0]
            return domain
        except:
            return None
            
    return None

def update_blocklist():
    try:
        # Create the db_config dictionary explicitly
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()
        
        # Get all enabled sources
        cursor.execute("SELECT id, url, name FROM blocklist_sources WHERE enabled = TRUE")
        sources = cursor.fetchall()
        
        for source_id, url, name in sources:
            try:
                print(f"Downloading from {name} ({url})")
                response = requests.get(url)
                if response.status_code == 200:
                    domain_count = 0
                    
                    # Start transaction
                    cursor.execute("START TRANSACTION")
                    
                    for line in response.text.splitlines():
                        domain = parse_domain_line(line)
                        if domain and '.' in domain and len(domain) > 3:
                            # Insert domain if it doesn't exist
                            cursor.execute("""
                                INSERT IGNORE INTO blocked_domains (domain, date_added)
                                VALUES (%s, %s)
                            """, (domain, datetime.now()))
                            
                            # Get domain_id (whether it was just inserted or already existed)
                            cursor.execute("SELECT id FROM blocked_domains WHERE domain = %s", (domain,))
                            domain_id = cursor.fetchone()[0]
                            
                            # Link domain to source
                            cursor.execute("""
                                INSERT IGNORE INTO domain_sources (domain_id, source_id)
                                VALUES (%s, %s)
                            """, (domain_id, source_id))
                            
                            domain_count += 1
                    
                    cursor.execute("""
                        UPDATE blocklist_sources 
                        SET last_update = %s, total_domains = %s 
                        WHERE id = %s
                    """, (datetime.now(), domain_count, source_id))
                    
                    conn.commit()
                    print(f"Successfully updated blocklist from {name}: {domain_count} domains")
                    
            except Exception as e:
                print(f"Error processing {url}: {e}")
                cursor.execute("ROLLBACK")
                
        conn.close()
        
    except mysql.connector.Error as err:
        print(f"Database error during update: {err}")

def run_scheduler():
    """Run the update scheduler"""
    schedule.every(24).hours.do(update_blocklist)
    while True:
        schedule.run_pending()
        time.sleep(60)

def test_blocked_domains():
    """Helper function to test if domains are being blocked"""
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()
        
        # Get a few blocked domains
        cursor.execute("SELECT domain FROM blocked_domains LIMIT 5")
        domains = cursor.fetchall()
        
        if domains:
            print("\nCurrently blocked domains (sample):")
            for domain in domains:
                print(f"- {domain[0]}")
        else:
            print("\nNo domains found in blocklist!")
            
        conn.close()
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")

# Add this to your main section, after update_blocklist():
test_blocked_domains()

def debug_blocklist():
    """Print some debug information about blocked domains"""
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM blocked_domains")
        total = cursor.fetchone()[0]
        print(f"\nTotal blocked domains: {total}")
        
        # Get a few example domains
        cursor.execute("SELECT domain FROM blocked_domains LIMIT 5")
        examples = cursor.fetchall()
        if examples:
            print("\nExample blocked domains:")
            for domain in examples:
                print(f"- {domain[0]}")
        
        conn.close()
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")

# Add this line right after update_blocklist() in your main section:
debug_blocklist()

def cleanup_domains():
    """Clean up the domains database and reset IDs"""
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()

        # Reset auto increment for both tables
        cursor.execute("ALTER TABLE blocklist_sources AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE blocked_domains AUTO_INCREMENT = 1")
        
        conn.commit()
        conn.close()
        print("Database cleanup completed")
        return True
    except mysql.connector.Error as err:
        print(f"Database cleanup error: {err}")
        return False

def signal_handler(sig, frame):
    print("\nShutting down Adsvoid...")
    try:
        # Stop DNS server
        if 'dns_server' in globals() and dns_server:
            dns_server.stop()
        
        # Stop Flask
        if 'app' in globals() and app:
            func = request.environ.get('werkzeug.server.shutdown')
            if func is not None:
                func()
    except Exception as e:
        print(f"Error during shutdown: {e}")
    
    print("Shutdown complete!")
    sys.exit(0)

def setup_logging():
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Configure DNS logger
    dns_logger = logging.getLogger('dns_log')
    dns_logger.setLevel(logging.INFO)
    
    # File handler for DNS logs
    dns_handler = TimedRotatingFileHandler(
        'logs/dns_requests.log',
        when='midnight',
        interval=1,
        backupCount=30
    )
    dns_format = logging.Formatter('%(asctime)s - %(message)s')
    dns_handler.setFormatter(dns_format)
    dns_logger.addHandler(dns_handler)
    
    # Configure source management logger
    source_logger = logging.getLogger('source_log')
    source_logger.setLevel(logging.INFO)
    
    # File handler for source management logs
    source_handler = TimedRotatingFileHandler(
        'logs/source_management.log',
        when='midnight',
        interval=1,
        backupCount=30
    )
    source_format = logging.Formatter('%(asctime)s - %(message)s')
    source_handler.setFormatter(source_format)
    source_logger.addHandler(source_handler)
    
    # Make sure both loggers don't propagate to root logger
    dns_logger.propagate = False
    source_logger.propagate = False
    
    return dns_logger, source_logger

def get_system_stats():
    """Get system resource usage"""
    try:
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory Usage
        mem = psutil.virtual_memory()
        ram_percent = mem.percent
        ram_used = f"{math.floor(mem.used/1024/1024)} MB"
        ram_total = f"{math.floor(mem.total/1024/1024)} MB"
        
        # Disk Usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used = f"{math.floor(disk.used/1024/1024/1024)} GB"
        disk_total = f"{math.floor(disk.total/1024/1024/1024)} GB"
        
        return {
            'cpu_percent': cpu_percent,
            'ram_percent': ram_percent,
            'ram_used': ram_used,
            'ram_total': ram_total,
            'disk_percent': disk_percent,
            'disk_used': disk_used,
            'disk_total': disk_total
        }
    except Exception as e:
        print(f"Error getting system stats: {e}")
        return {
            'cpu_percent': 0,
            'ram_percent': 0,
            'ram_used': '0 MB',
            'ram_total': '0 MB',
            'disk_percent': 0,
            'disk_used': '0 GB',
            'disk_total': '0 GB'
        }
    
def log_source_action(action, name, url, status=""):
    """Log source management actions"""
    try:
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {action} - Name: {name}, URL: {url} {status}"
        source_logger.info(log_entry)
    except Exception as e:
        print(f"Error logging source action: {e}")



# Register signals
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Create the Flask web application
app = Flask(__name__)

# In main.py, replace the existing @app.route('/') function

@app.route('/')
def dashboard():
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        
        # Get domains on adlists
        cursor.execute("SELECT COUNT(*) as total FROM blocked_domains")
        domains_total = cursor.fetchone()['total']
        
        # Get query statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                COALESCE(SUM(CASE WHEN action = 'BLOCKED' THEN 1 ELSE 0 END), 0) as blocked,
                COALESCE(SUM(CASE WHEN action = 'ALLOWED' THEN 1 ELSE 0 END), 0) as allowed
            FROM dns_logs
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        query_stats = cursor.fetchone()
        if query_stats is None:
            query_stats = {
                'total': 0,
                'blocked': 0,
                'allowed': 0
            }
        
        # Get system stats
        system_stats = get_system_stats()
        
        conn.close()
        return render_template('dashboard.html',
                             domains_total=domains_total,
                             query_stats=query_stats,
                             system_stats=system_stats)
    except mysql.connector.Error as err:
        print(f"Error getting statistics: {err}")
        return render_template('dashboard.html',
                             domains_total=0,
                             query_stats={'total': 0, 'blocked': 0, 'allowed': 0},
                             system_stats=get_system_stats())

@app.route('/sources')
def list_sources():
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, url, name, enabled, 
                   last_update, total_domains 
            FROM blocklist_sources
        """)
        sources = cursor.fetchall()
        conn.close()
        return render_template('sources.html', sources=sources)
    except mysql.connector.Error as err:
        return f"Database error: {err}", 500

@app.route('/sources/add', methods=['POST'])
def add_source():
    url = request.form.get('url')
    name = request.form.get('name', url)
    
    if not url:
        return "URL is required", 400
        
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blocklist_sources (url, name)
            VALUES (%s, %s)
        """, (url, name))
        conn.commit()
        conn.close()
        
        # Log source addition
        log_source_action("ADD", name, url)
        
        # Update blocklist immediately
        update_blocklist()
        return redirect(url_for('list_sources'))
    except mysql.connector.Error as err:
        log_source_action("ADD_ERROR", name, url, f"Error: {str(err)}")
        return f"Database error: {err}", 500

@app.route('/sources/delete/<int:source_id>', methods=['POST'])
def delete_source(source_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Get source info for logging
        cursor.execute("SELECT name, url FROM blocklist_sources WHERE id = %s", (source_id,))
        source_info = cursor.fetchone()
        
        if source_info:
            name, url = source_info
            log_source_action("DELETE", name, url)
            
        # Rest of your delete logic...
        
    except mysql.connector.Error as err:
        if source_info:
            log_source_action("DELETE_ERROR", name, url, f"Error: {str(err)}")
        return f"Database error: {err}", 500

@app.route('/sources/toggle/<int:source_id>', methods=['POST'])
def toggle_source(source_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Get current state
        cursor.execute("SELECT name, url, enabled FROM blocklist_sources WHERE id = %s", (source_id,))
        source_info = cursor.fetchone()
        
        # Toggle state
        cursor.execute("""
            UPDATE blocklist_sources 
            SET enabled = NOT enabled 
            WHERE id = %s
        """, (source_id,))
        conn.commit()
        
        # Log state change
        if source_info:
            new_state = "Enabled" if not source_info[2] else "Disabled"
            source_logger.info(f"Source {new_state} - Name: {source_info[0]}, URL: {source_info[1]}")
            
        return redirect(url_for('list_sources'))
    except mysql.connector.Error as err:
        source_logger.error(f"Error Toggling Source ID: {source_id}, Error: {str(err)}")
        return f"Database error: {err}", 500

# Add this route to trigger cleanup manually
@app.route('/sources/cleanup', methods=['POST'])
def trigger_cleanup():
    cleanup_domains()
    return redirect(url_for('list_sources'))

@app.route('/logs')
def view_logs():
    # Get search parameters
    date = request.args.get('date', '')
    domain = request.args.get('domain', '')
    client_ip = request.args.get('client_ip', '')
    log_type = request.args.get('type', 'dns')  # 'dns' or 'source'
    
    try:
        logs = []
        log_file = os.path.join('logs', 'dns_requests.log' if log_type == 'dns' else 'source_management.log')
        
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                all_logs = f.readlines()
                
                # Apply filters
                for line in all_logs:
                    if date and date not in line:
                        continue
                    if domain and domain.lower() not in line.lower():
                        continue
                    if client_ip and client_ip not in line:
                        continue
                    logs.append(line.strip())
                
                # Get last 100 logs if no filters and reverse them
                if not any([date, domain, client_ip]):
                    logs = logs[-100:]
                
                # Reverse the logs to show newest first
                logs.reverse()
        
        # Return the template with logs and search parameters
        return render_template('logs.html',
                             logs=logs,
                             date=date,
                             domain=domain,
                             client_ip=client_ip,
                             log_type=log_type)
                             
    except Exception as e:
        print(f"Error reading logs: {e}")
        return render_template('logs.html',
                             logs=[f"Error reading logs: {str(e)}"],
                             date=date,
                             domain=domain,
                             client_ip=client_ip,
                             log_type=log_type)



@app.route('/api/stats')
def get_stats():
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        
        # Get domains on adlists
        cursor.execute("SELECT COUNT(*) as total FROM blocked_domains")
        domains_total = cursor.fetchone()['total']
        
        # Get query statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN action = 'BLOCKED' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN action = 'ALLOWED' THEN 1 ELSE 0 END) as allowed
            FROM dns_logs
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        query_stats = cursor.fetchone()
        
        # Get system stats
        system_stats = get_system_stats()
        
        conn.close()
        
        return jsonify({
            'domains_total': domains_total,
            'query_stats': query_stats,
            'system_stats': system_stats
        })
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 500



# Then put your if __name__ == "__main__": block here
if __name__ == "__main__":
    print("Setting up Adsvoid...")
    
    # Setup logging
    dns_logger, source_logger = setup_logging()

    if setup_database():
        print("Initial blocklist update starting...")
        update_blocklist()
        
        # Database configuration for DNS server
        db_config = {
            'host': config.DB_HOST,
            'user': config.DB_USER,
            'password': config.DB_PASSWORD,
            'database': config.DB_NAME
        }
        
        # Start the DNS server in a separate thread
        dns_server = DNSServer(db_config)
        dns_thread = Thread(target=dns_server.run_server, daemon=True)
        dns_thread.start()
        print("DNS Server started on port 53")
        
        # Start the scheduler in a background thread
        scheduler_thread = Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        print(f"\nStarting web dashboard on port {config.WEB_PORT}")
        print(f"You can view your dashboard at: http://localhost:{config.WEB_PORT}")
        app.run(host='0.0.0.0', port=config.WEB_PORT)
    else:
        print("Failed to set up database. Please check your database settings in config.py")