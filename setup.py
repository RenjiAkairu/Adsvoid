import os
import sys
import subprocess
import platform

def is_admin():
    try:
        return os.getuid() == 0  # Linux/Mac
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

def install_requirements():
    print("Installing Python requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        return True
    except Exception as e:
        print(f"Error installing requirements: {e}")
        return False

def check_mysql():
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="@AD-BlockMaster01"
        )
        conn.close()
        return True
    except:
        return False

def setup_environment():
    if not is_admin():
        print("Please run this script with administrator privileges!")
        return False

    # Create requirements.txt if not exists
    if not os.path.exists("requirements.txt"):
        with open("requirements.txt", "w") as f:
            f.write("""flask==2.0.1
mysql-connector-python==8.0.26
requests==2.26.0
schedule==1.1.0""")

    # Install requirements
    if not install_requirements():
        print("Failed to install Python requirements")
        return False

    # Check MySQL
    if not check_mysql():
        print("\nMySQL check failed!")
        print("Please install MySQL Server and verify these settings:")
        print("  Host: localhost")
        print("  Username: root")
        print("  Password: @AD-BlockMaster01")
        return False

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