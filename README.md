# Adsvoid Ad-Blocker

A DNS-based ad-blocking system with web interface for managing block lists.

## Requirements
- Python 3.8 or higher
- MySQL Server 8.0 or higher
- Administrator privileges (for DNS server)

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
   pip install flask mysql-connector-python requests schedule
   ```

3. Run the program
   ```bash
   # Clone repository
   git clone https://github.com/YOUR_USERNAME/adsvoid.git
   cd adsvoid

   # Run as administrator
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

## Features
- Web dashboard for managing block lists
- Automatic updates every 24 hours
- Support for multiple blocklist formats
- Enable/disable specific sources

## Project Structure
```
adsvoid/
├── main.py           # Main program
├── config.py         # Configuration
├── setup.py         # Installation helper
├── templates/       # Web interface
│   ├── dashboard.html
│   └── sources.html
└── README.md
```

## Troubleshooting
1. Port 53 already in use:
   ```bash
   # Windows: Stop DNS Client service
   net stop "DNS Client"
   ```

2. MySQL Connection Issues:
   - Verify MySQL is running
   - Check credentials in config.py

## Contributing
Feel free to submit issues and enhancement requests!

## License
MIT License - See LICENSE file for details
