# Adsvoid Ad-Blocker

A DNS-based ad-blocking system with a web dashboard for managing various systems and monitoring DNS traffic.

## Version 1.1.0 Changes

- Added interactive MySQL credential configuration during setup
- Added dedicated database user 'AdsvoidAdmin' with restricted privileges
- Enhanced database security by removing root user dependency
- Added flexibility to use existing MySQL users with appropriate privileges
- Added privilege verification during setup process
- Updated setup process to automatically configure secure database access
- Improved error handling for database operations
- Added secure password input for MySQL configuration

## Features
- DNS-level ad blocking with caching system
- Primary and backup DNS server support (Google, Cloudflare, Quad9)
- Real-time web dashboard with system monitoring
- Comprehensive logging system for DNS queries and source management
- Multiple blocklist source management with automatic updates
- System resource monitoring (CPU, RAM, Disk usage)
- Database management and cleanup tools
- Secure database access with dedicated user
- Flexible MySQL configuration options

## Requirements
- Python 3.x
- MySQL Community Database
- Windows OS (for DNS server)
- Administrator privileges (for port 53)
- MySQL user with privileges to create users and databases

## Known Issues

### Antivirus False Positives
- **Issue**: Windows Defender and other antivirus software may flag Adsvoid.exe as malicious
- **Cause**: This is a false positive due to:
  - DNS traffic manipulation required for ad-blocking
  - Use of PyInstaller for creating the executable
  - Network socket operations on port 53
  - Database operations
- **Solutions**:
  1. Add exception in your antivirus software for Adsvoid.exe
  2. Run from source code instead of executable:
     ```bash
     git clone https://github.com/your-repo/adsvoid.git
     cd adsvoid
     python setup.py
     python main.py
     ```
  3. Verify file integrity using provided checksums (see Release Notes)

### Security Notes
- Adsvoid is open-source, and you can inspect the code on GitHub
- The executable is built using PyInstaller from the public source code
- No malicious code is included
- The program requires administrator privileges only for:
  - DNS server operation (port 53)
  - Network configuration
  - Database setup

### Alternative Installation Methods
If you're concerned about antivirus warnings, you can:
1. Clone the repository and run from source
2. ~~Build the executable yourself using build.py~~
3. ~~Use portable version (if available)~~

### Why Does This Happen?
DNS manipulation software often triggers antivirus warnings because:
- They modify network settings
- They intercept DNS queries
- They require administrator privileges
- They use system-level networking features

## Verifying Your Download

### Checking File Signatures
When downloading Adsvoid.exe, you can verify its authenticity:

1. File Properties:
   - Right-click Adsvoid.exe → Properties
   - Check "Digital Signatures" tab
   - Publisher should be listed as "RenjiAkairu"
   - Version should match release version

2. File Information:
   ```
   Name: Adsvoid.exe
   Version: 1.1.0
   Publisher: RenjiAkairu
   File Size: [Size will vary by version]
   ```

### Building from Source
To avoid antivirus issues, build from source:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/adsvoid.git
   ```

2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

3. Build the executable:
   ```bash
   python build.py
   ```

4. The built executable will be in the dist/Adsvoid directory

### Running Without Installation
You can run Adsvoid directly from Python without building an executable:

1. Install Python 3.x
2. Clone the repository
3. Run setup.py
4. Run main.py

This method bypasses antivirus warnings while maintaining full functionality.

## Verifying Your Download
1. Get the checksum of your downloaded file:
   - Windows: `Get-FileHash Adsvoid.exe -Algorithm SHA256`
   - Linux/Mac: `sha256sum Adsvoid.exe`
2. Compare with the checksum in SHA256SUMS.txt
3. If they match, the file is authentic

## Quick Installation
1. Install MySQL Server
   ```bash
   # Download from: https://dev.mysql.com/downloads/mysql/
   ```

2. Install Python requirements
   ```bash
   pip install -r requirements.txt
   ```

3. Run the setup script
   ```bash
   python setup.py
   ```
   During setup:
    - Enter credentials for a MySQL user with privileges to create users and databases
    - The script will create a dedicated 'AdsvoidAdmin' user for Adsvoid
    - All necessary database configurations will be handled automatically

4. Run the program
   ```bash
   # Run as administrator (required for DNS server)
   python main.py
   ```

5. Access the dashboard at: http://localhost:5000

## Database Configuration
The setup script will:

 1. Prompt for MySQL administrator credentials
 2. Verify the user has necessary privileges
 3. Create the AdsvoidAdmin user automatically
 4. Configure all required database permissions
 5. Update the configuration files

If you need to manually configure the database user:
```sql
CREATE USER 'AdsvoidAdmin'@'localhost' IDENTIFIED BY '@AD-BlockMaster01';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, 
      REFERENCES, TRIGGER, EVENT ON adsvoid.* TO 'AdsvoidAdmin'@'localhost';
FLUSH PRIVILEGES;
```

## Testing Ad Blocking
1. Method 1 - Test locally:
   - Change your computer's DNS to 127.0.0.1

2. Method 2 - Test on network:
   - Change router's DNS to your computer's IP address

## Project Structure
```
adsvoid/
├── main.py              # Main application with DNS server and web interface
├── config.py            # Configuration settings
├── setup.py            # Installation helper
├── requirements.txt    # Python dependencies 
├── templates/          # Web interface templates
│   ├── dashboard.html  # Main dashboard with statistics
│   ├── sources.html   # Blocklist source management
│   └── logs.html      # Log viewer
└── logs/              # Application logs directory
    ├── dns_requests.log
    └── source_management.log
```

## Troubleshooting
   1. Port 53 Error:
      - Ensure you're running as administrator
      - Check if Windows DNS Client service is using port 53:
      ```
      net stop "DNS Client"
      ```
   2. MySQL Connection Issues:
      - Verify MySQL service is running
      - Check credentials in config.py
      - Ensure database 'adsvoid' exists
   3. DNS Server Issues:
      - Primary DNS servers: Google (8.8.8.8), Cloudflare (1.1.1.1)
      - Backup DNS servers: Google (8.8.4.4), Cloudflare (1.0.0.1), Quad9 (9.9.9.9)

# Features
## DNS Server
- Custom DNS query handling
- Cache system with timeout management
- Multiple DNS server fallback
- Comprehensive query logging

## Web Dashboard

- Real-time statistics and graphs
- System resource monitoring
- Blocklist source management
- Log viewer with filtering

## Security

- DNS query logging with retention
- Source management logging
- Error handling and logging
- Secure database operations

## Contributing
See CONTRIBUTING.md for details on how to contribute to this project.

## License
MIT License - See LICENSE file for details
