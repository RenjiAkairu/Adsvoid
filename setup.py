import os
import sys
import subprocess
import platform
import time

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
            time.sleep(2)  # Wait for service to stop
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

def check_mysql():
    """Verify MySQL connection and database"""
    try:
        import mysql.connector
        # Try to connect with default credentials
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="@AD-BlockMaster01"
        )
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS adsvoid")
        
        conn.close()
        return True
    except Exception as e:
        print(f"MySQL Error: {e}")
        return False

def setup_environment():
    """Setup the complete environment"""
    if not is_admin():
        print("Please run this script with administrator privileges!")
        return False

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

    # Check MySQL
    if not check_mysql():
        print("\nMySQL check failed!")
        print("Please ensure MySQL Server is installed with these settings:")
        print("  Host: localhost")
        print("  Username: root")
        print("  Password: @AD-BlockMaster01")
        return False

    # Create logs directory
    if not os.path.exists('logs'):
        os.makedirs('logs')
        # Create .gitkeep to maintain directory
        open('logs/.gitkeep', 'a').close()

    return True

def main():
    print("Adsvoid Setup Script")
    print("===================")

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