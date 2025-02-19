# Adsvoid Ad-Blocker

A DNS-based ad-blocking system similar to Pi-hole, with a web dashboard for managing various systems and monitoring DNS traffic.

## Features
- DNS-level ad blocking with caching system
- Primary and backup DNS server support (Google, Cloudflare, Quad9)
- Real-time web dashboard with system monitoring
- Comprehensive logging system for DNS queries and source management
- Multiple blocklist source management with automatic updates
- System resource monitoring (CPU, RAM, Disk usage)
- Database management and cleanup tools

## Requirements
- Python 3.x
- MySQL Community Database
- Windows OS (for DNS server)
- Administrator privileges (for port 53)

## Quick Installation
1. Install MySQL Server
   ```bash
   # Download from: https://dev.mysql.com/downloads/mysql/
   # Use these settings during installation:
   Username: root
   Password: @AD-BlockMaster01
   ```

2. Install Python requirements
   ```bash
   pip install -r requirements.txt
   ```

3. Run the program
   ```bash
   # Run as administrator (required for DNS server)
   python main.py
   ```

4. Access the dashboard at: http://localhost:5000

## Automated Installation
Run the setup script:
```bash
python setup.py
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

## Features
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
