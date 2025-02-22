import os
import sys
import subprocess
import platform
import time
import getpass
import mysql.connector

def is_admin():
    try:
        return os.getuid() == 0  # Linux/Mac
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

def check_port_53():
    """Check if port 53 is available"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 53))
        sock.close()
        return True
    except:
        return False

def stop_dns_client():
    """Attempt to stop Windows DNS Client service"""
    if platform.system() == 'Windows':
        try:
            subprocess.run(['net', 'stop', 'DNSCache'], check=True)
            time.sleep(2)
            return True
        except:
            return False
    return True

def install_requirements():
    """Install Python packages from requirements.txt"""
    print("Installing Python requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        return True
    except Exception as e:
        print(f"Error installing requirements: {e}")
        return False

def get_mysql_credentials():
    """Get MySQL credentials from user input"""
    print("\nMySQL Configuration")
    print("==================")
    print("Please enter credentials for a MySQL user with privileges to create users and databases.")
    
    while True:
        username = input("MySQL Username: ").strip()
        if not username:
            print("Username cannot be empty. Please try again.")
            continue
            
        password = getpass.getpass("MySQL Password: ")
        if not password:
            print("Password cannot be empty. Please try again.")
            continue
            
        try:
            # Test connection
            conn = mysql.connector.connect(
                host="localhost",
                user=username,
                password=password
            )
            conn.close()
            return username, password
            
        except mysql.connector.Error as err:
            if err.errno == mysql.connector.errorcode.ER_ACCESS_DENIED_ERROR:
                print("\nError: Invalid username or password. Please try again.")
            else:
                print(f"\nError connecting to MySQL: {err}")
                retry = input("Would you like to try again? (y/n): ").lower()
                if retry != 'y':
                    return None, None
                
def verify_user_privileges(username, password):
    """Verify if the user has necessary privileges"""
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user=username,
            password=password
        )
        cursor = conn.cursor()
        
        # Check CREATE USER privilege
        cursor.execute("SHOW GRANTS")
        grants = cursor.fetchall()
        has_privileges = False
        
        for grant in grants:
            grant_str = grant[0].upper()
            if 'ALL PRIVILEGES' in grant_str or 'CREATE USER' in grant_str:
                has_privileges = True
                break
                
        conn.close()
        return has_privileges
        
    except Exception as e:
        print(f"Error checking privileges: {e}")
        return False

def setup_mysql_user(admin_username, admin_password):
    """Setup AdsvoidAdmin user with appropriate privileges"""
    try:
        # Connect with provided credentials
        conn = mysql.connector.connect(
            host="localhost",
            user=admin_username,
            password=admin_password
        )
        cursor = conn.cursor()
        
        print("\nSetting up AdsvoidAdmin user...")
        
        # Create adsvoid database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS adsvoid")
        
        # Create AdsvoidAdmin user if it doesn't exist
        try:
            cursor.execute("CREATE USER IF NOT EXISTS 'AdsvoidAdmin'@'localhost' IDENTIFIED BY '@AD-BlockMaster01'")
        except mysql.connector.Error as err:
            if err.errno != 1396:  # Error code for "Operation CREATE USER failed"
                raise
        
        # Grant necessary privileges
        cursor.execute("""
            GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, 
            REFERENCES, TRIGGER, EVENT ON adsvoid.* TO 'AdsvoidAdmin'@'localhost'
        """)
        
        # Flush privileges
        cursor.execute("FLUSH PRIVILEGES")
        
        print("Successfully created AdsvoidAdmin user with required privileges")
        conn.close()
        
        # Test connection with new user
        test_conn = mysql.connector.connect(
            host="localhost",
            user="AdsvoidAdmin",
            password="@AD-BlockMaster01",
            database="adsvoid"
        )
        test_conn.close()
        print("Successfully verified AdsvoidAdmin user access")
        
        # Update config.py with new credentials
        with open('config.py', 'r') as file:
            config_content = file.read()
        
        config_content = config_content.replace('DB_USER = "root"', 'DB_USER = "AdsvoidAdmin"')
        
        with open('config.py', 'w') as file:
            file.write(config_content)
        
        print("Updated config.py with new database user")
        return True
        
    except Exception as e:
        print(f"MySQL User Setup Error: {e}")
        return False

def check_mysql():
    """Verify MySQL connection and create AdsvoidAdmin user"""
    print("\nChecking MySQL configuration...")
    
    # Get MySQL credentials from user
    admin_username, admin_password = get_mysql_credentials()
    if not admin_username or not admin_password:
        print("MySQL configuration cancelled.")
        return False
        
    # Verify privileges
    if not verify_user_privileges(admin_username, admin_password):
        print("\nError: The provided MySQL user does not have sufficient privileges.")
        print("Please provide credentials for a user with privileges to create users and databases.")
        return False
        
    # Setup AdsvoidAdmin user
    return setup_mysql_user(admin_username, admin_password)

def setup_environment():
    """Setup the complete environment"""
    if not is_admin():
        print("Please run this script with administrator privileges!")
        return False

    print("\nChecking system requirements...")
    
    # Check and stop DNS Client if necessary
    if not check_port_53():
        print("Port 53 is in use. Attempting to stop DNS Client service...")
        if not stop_dns_client():
            print("Failed to free port 53. Please stop any DNS service manually.")
            return False

    # Install requirements
    if not install_requirements():
        print("Failed to install Python requirements")
        return False

    # Check MySQL and setup AdsvoidAdmin user
    if not check_mysql():
        print("\nMySQL setup failed!")
        return False

    # Create logs directory
    if not os.path.exists('logs'):
        os.makedirs('logs')
        open('logs/.gitkeep', 'a').close()

    return True

def main():
    print("Adsvoid Setup Script v1.1.0")
    print("===========================")

    if not setup_environment():
        sys.exit(1)

    print("\nSetup completed successfully!")
    print("\nTo start Adsvoid:")
    if platform.system() == "Windows":
        print("1. Run Command Prompt as Administrator")
    else:
        print("1. Open terminal")
    print("2. Navigate to the Adsvoid folder")
    print("3. Run: python main.py")
    print("\nAccess the dashboard at: http://localhost:5000")

if __name__ == "__main__":
    main()