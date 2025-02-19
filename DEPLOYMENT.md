# Deployment Guide

This guide helps you deploy Adsvoid in a production environment.

## Prerequisites

1. A dedicated server/machine running Windows
2. Python 3.8 or higher
3. MySQL Server 8.0 or higher
4. Administrator privileges

## Production Setup

### 1. System Preparation

```bash
# Create a dedicated user
# Enable necessary Windows features
# Configure firewall for port 53 (DNS) and 5000 (Web UI)
```

### 2. Security Considerations

1. Change default MySQL password
2. Use environment variables for sensitive data
3. Set up SSL for web interface
4. Configure proper logging rotation
5. Set up database backups

### 3. Environment Variables

Set these environment variables for security:
```bash
ADSVOID_DB_HOST=localhost
ADSVOID_DB_USER=your_user
ADSVOID_DB_PASSWORD=your_password
ADSVOID_DB_NAME=adsvoid
ADSVOID_WEB_PORT=5000
```

### 4. Running as a Service

1. Install NSSM (Non-Sucking Service Manager)
2. Create a service for Adsvoid:
```bash
nssm install Adsvoid "python" "C:\path\to\main.py"
nssm set Adsvoid AppDirectory "C:\path\to\adsvoid"
```

### 5. Monitoring

1. Set up Windows Event Log monitoring
2. Configure alerts for service status
3. Monitor disk space for logs

### 6. Backup Strategy

1. Database backup (daily)
2. Configuration backup
3. Log rotation and archive

### 7. Updating

1. Stop the service
2. Backup configuration
3. Pull latest code
4. Update dependencies
5. Start the service

## Performance Tuning

1. Adjust cache settings in main.py
2. Optimize MySQL configuration
3. Configure proper logging levels

## Troubleshooting

1. Check Windows Event Logs
2. Verify DNS service status
3. Monitor resource usage
4. Check database connectivity