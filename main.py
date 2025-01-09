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
from flask import Flask, render_template, request, redirect, url_for
import signal
import sys

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
        self.upstream_dns = ('8.8.8.8', 53)
        self.running = True
        self.udps = None

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

    def handle_dns_request(self, data):
        """Handle a single DNS request"""
        try:
            # Parse the query
            query = self.DNSQuery(data)
            
            # Check if domain is blocked
            if self.is_domain_blocked(query.domain):
                print(f"Blocking domain: {query.domain}")
                return query.response(self.blocked_ip)
            
            # Forward to upstream DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)  # Reduced timeout to 1 second
            
            try:
                # Send to Google DNS
                sock.sendto(data, self.upstream_dns)
                response, _ = sock.recvfrom(4096)
                return response
            except socket.timeout:
                print(f"Timeout forwarding {query.domain}, blocking")
                return query.response(self.blocked_ip)
            finally:
                sock.close()
                
        except Exception as e:
            print(f"Error handling request: {e}")
            # Return blocked response in case of any error
            query = self.DNSQuery(data)
            return query.response(self.blocked_ip)

    def run_server(self):
        print("Starting DNS Server...")
        try:
            self.udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Add this to ensure port is released on restart
            self.udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udps.bind(('', 53))
            self.udps.settimeout(0.1)

            while self.running:
                try:
                    data, addr = self.udps.recvfrom(1024)
                    if not self.running:
                        break
                    response = self.handle_dns_request(data)
                    self.udps.sendto(response, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"Error in main loop: {e}")

        except Exception as e:
            print(f"DNS Server error: {e}")
        finally:
            self.stop()
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
        
        # Create database
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config.DB_NAME}")
        conn.close()
        
        # Connect to our new database
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_domains (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain VARCHAR(255) UNIQUE,
                date_added DATETIME
            )
        """)

        # Create blocklist sources table
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

        # Add new table to track which domains came from which sources
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_sources (
                domain_id INT,
                source_id INT,
                FOREIGN KEY (domain_id) REFERENCES blocked_domains(id),
                FOREIGN KEY (source_id) REFERENCES blocklist_sources(id),
                PRIMARY KEY (domain_id, source_id)
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

# Register signals
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Create the Flask web application
app = Flask(__name__)

@app.route('/')
def dashboard():
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM blocked_domains")
        total_domains = cursor.fetchone()[0]
        conn.close()
        return render_template('dashboard.html', total_domains=total_domains)
    except mysql.connector.Error as err:
        print(f"Error getting statistics: {err}")
        return "Database error occurred", 500

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
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blocklist_sources (url, name)
            VALUES (%s, %s)
        """, (url, name))
        conn.commit()
        conn.close()
        
        # Update blocklist immediately
        update_blocklist()
        return redirect(url_for('list_sources'))
    except mysql.connector.Error as err:
        return f"Database error: {err}", 500

@app.route('/sources/delete/<int:source_id>', methods=['POST'])
def delete_source(source_id):
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()

        # First, get the domains from this source
        cursor.execute("""
            CREATE TEMPORARY TABLE temp_domains AS
            SELECT DISTINCT domain
            FROM blocked_domains
            WHERE domain IN (
                SELECT domain FROM blocked_domains d
                WHERE EXISTS (
                    SELECT 1 FROM blocklist_sources s
                    WHERE s.id = %s
                    AND d.date_added >= s.last_update
                    AND d.date_added <= DATE_ADD(s.last_update, INTERVAL 1 MINUTE)
                )
            )
        """, (source_id,))

        # Delete the domains that are only from this source
        cursor.execute("""
            DELETE FROM blocked_domains 
            WHERE domain IN (SELECT domain FROM temp_domains)
        """)

        # Delete the source
        cursor.execute("DELETE FROM blocklist_sources WHERE id = %s", (source_id,))
        
        # Reset auto increment if needed
        cursor.execute("ALTER TABLE blocklist_sources AUTO_INCREMENT = 1")
        
        conn.commit()
        conn.close()
        return redirect(url_for('list_sources'))
    except mysql.connector.Error as err:
        print(f"Error deleting source: {err}")
        return f"Database error: {err}", 500

@app.route('/sources/toggle/<int:source_id>', methods=['POST'])
def toggle_source(source_id):
    try:
        conn = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE blocklist_sources 
            SET enabled = NOT enabled 
            WHERE id = %s
        """, (source_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('list_sources'))
    except mysql.connector.Error as err:
        return f"Database error: {err}", 500

# Add this route to trigger cleanup manually
@app.route('/sources/cleanup', methods=['POST'])
def trigger_cleanup():
    cleanup_domains()
    return redirect(url_for('list_sources'))

# Then put your if __name__ == "__main__": block here
if __name__ == "__main__":
    print("Setting up Adsvoid...")
    
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