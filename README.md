# CloudTerm

🚀 **A modern web-based terminal application that automatically discovers and organizes your AWS EC2 instances**

CloudTerm provides secure access to AWS EC2 instances through AWS Systems Manager Session Manager with intelligent 4-level hierarchical organization.

<img width="1675" height="1387" alt="image" src="https://github.com/user-attachments/assets/ee7423c1-8362-46f9-b359-58e2c09e94b8" />



## ✨ Key Features

- **🔍 Dynamic Discovery**: Automatically scans AWS EC2 instances across multiple profiles and regions
- **💾 Smart Caching**: Save discovered instances to YAML for fast terminal connections
- **🏗️ 4-Level Hierarchy**: Organizes instances by AWS Account → Region → Customer (TAG1) → Environment (TAG2)
- **🔐 Secure Access**: Uses AWS Systems Manager Session Manager for keyless, secure terminal connections
- **🔍 Real-time Search**: Filter instances by name, ID, tags, or any metadata with auto-expansion
- **📊 Visual Indicators**: Color-coded instance states (running, stopped, transitioning) and platform icons
- **🐳 Container Ready**: Fully containerized with Docker and Docker Compose support
- **⚡ One-Click Workflow**: Scan automatically discovers and saves instances

## 🔄 How It Works

### **Step 1: Scan & Auto-Save** 🔍💾
- Click "Scan Instances" or wait for auto-scan on page load
- Automatically discovers EC2 instances across all AWS profiles and regions
- Organizes instances in a 4-level hierarchy (Account → Region → Customer → Environment)
- **Automatically saves** discovered instances to `instances_list.yaml` for terminal connections
- Shows real-time instance status and metadata

### **Step 2: Connect** 🔗
- Click any instance to open a secure terminal session
- Uses AWS Systems Manager Session Manager
- No SSH keys or open ports required
- Instance connection details are automatically available from the saved configuration

### 🔐 **Security & Reliability**
- **AWS Session Manager**: Secure connections without open ports
- **Profile-Based Auth**: Uses AWS credential profiles
- **Graceful Fallback**: Falls back to static configuration if needed
- **Docker Containerized**: Isolated and portable deployment

### 🌐 **Modern Interface**
- **Web-Based Terminal**: XtermJS-powered terminal interface
- **Multiple Sessions**: Concurrent terminal connections
- **Responsive Design**: Works on desktop and mobile
- **Real-Time Updates**: Live instance status monitoring

## 🏗️ Architecture

```
☁️ AWS Account: 123456789012
  🌍 Region: us-east-1
    📁 Customer (TAG1): ACME Corp
      📁 Environment (TAG2): production
        🖥️ 🟢 Web Server 1 (i-1234567890abcdef0)
        🖥️ 🟢 Database Server (i-0987654321fedcba0)
      📁 Environment (TAG2): development  
        🖥️ 🔴 Dev Server (i-1111222233334444)
  🌍 Region: eu-west-1
    📁 Customer (TAG1): ACME Corp
      📁 Environment (TAG2): production
        🖥️ 🟢 EU Web Server (i-5555666677778888)
```

## 🚀 Deployment Guide

Choose your preferred deployment method based on your environment and requirements:

### 📋 Prerequisites
- AWS Account with EC2 and Session Manager permissions
- AWS credentials configured
- Python 3.11+ (for manual deployment)
- Docker (for containerized deployment)

### 🔧 Initial Setup

#### 1. Clone Repository
```bash
git clone https://github.com/subbareddyalamur1/cloudterm.git
cd cloudterm
```

#### 2. Configure AWS Credentials
```bash
# Create AWS credentials directory
mkdir -p ~/.aws

# Add to ~/.aws/credentials
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY

[prod]
aws_access_key_id = PROD_ACCESS_KEY
aws_secret_access_key = PROD_SECRET_KEY

# Add to ~/.aws/config
[default]
region = us-east-1
output = json

[profile prod]
region = us-west-2
output = json
```

#### 3. Configure Tag-Based Organization
```bash
# Set environment variables for instance grouping
export TAG1="Customer"     # Root level tag (e.g., Customer, Project, Team)
export TAG2="Environment"  # Branch level tag (e.g., Environment, Stage)

# Or use the provided script
./run_with_tags.sh
```

---

## 🎯 Option 1: Manual Python Deployment

**Best for**: Development, testing, and local debugging

### Step 1: Setup Python Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Install AWS Session Manager Plugin
```bash
# macOS
brew install --cask session-manager-plugin

# Ubuntu/Debian
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
sudo dpkg -i session-manager-plugin.deb

# Windows
# Download and install from: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html
```

### Step 3: Run Application
```bash
# Set environment variables
export TAG1="Customer"
export TAG2="Environment"
export PORT=5000

# Start the application
python3 app.py
```

### Step 4: Access Application
Open your browser: **http://localhost:5000**

---

## 🐳 Option 2: Docker Container Deployment

**Best for**: Isolated environments, testing, and single-container deployments

### Step 1: Build Docker Image
```bash
# Build the CloudTerm image
docker build -t cloudterm:latest .

# Verify the image
docker images | grep cloudterm
```

### Step 2: Run Container
```bash
# Run with default configuration
docker run -d \
  --name cloudterm-app \
  -p 5000:5000 \
  -v ~/.aws:/home/appuser/.aws:ro \
  -v $(pwd)/instances_list.yaml:/app/instances_list.yaml:rw \
  -e TAG1="Customer" \
  -e TAG2="Environment" \
  -e AWS_DEFAULT_REGION="us-east-1" \
  cloudterm:latest

# Check container status
docker ps
docker logs cloudterm-app
```

### Step 3: Access Application
Open your browser: **http://localhost:5000**

### Step 4: Container Management
```bash
# Stop the container
docker stop cloudterm-app

# Start the container
docker start cloudterm-app

# Remove the container
docker rm cloudterm-app

# View logs
docker logs -f cloudterm-app
```
---

## 🔧 Option 3: Docker Compose Deployment

**Best for**: Production, automated deployments, and persistent services

### Step 1: Update docker-compose.yml
```bash
# Update the docker-compose.yml file with TAG1 and TAG2 values
  ...
  environment:
    - TAG1="Customer"
    - TAG2="Environment"
  ...
```

### Step 2: Deploy with Docker Compose
```bash
# Build and start services
docker-compose up --build -d

# Check service status
docker-compose ps
docker-compose logs -f
```

### Step 3: Access Application
Open your browser: **http://localhost:5000**

### Step 3: Service Management
```bash
# View logs
docker-compose logs -f cloudterm

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Update and redeploy
docker-compose pull
docker-compose up --build -d
```

### Step 4: Health Monitoring
```bash
# Check health status
docker-compose ps

# View detailed container info
docker inspect cloudterm-app

# Monitor resource usage
docker stats cloudterm-app
```
---

## 🎉 Success!

Regardless of your chosen deployment method, CloudTerm will:

1. **🔄 Auto-scan** your AWS accounts on startup
2. **🏗️ Organize** instances in a 4-level hierarchy
3. **🔍 Enable** smart search across all levels
4. **🖥️ Provide** secure terminal access via Session Manager

**Next Steps:**
- Tag your EC2 instances with `TAG1` and `TAG2` values
- Use the search functionality to find instances quickly
- Connect to instances securely through the web interface

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TAG1` | `Customer` | Root level AWS tag for grouping |
| `TAG2` | `Environment` | Branch level AWS tag for grouping |
| `PORT` | `5000` | Application port |

### AWS Tag Requirements

For optimal organization, tag your EC2 instances:

```yaml
# Example instance tags
Tags:
  Name: "Web Server 1"           # Display name
  Customer: "ACME Corp"          # TAG1 - Root grouping
  Environment: "production"      # TAG2 - Branch grouping
  Project: "WebApp"              # Optional additional tags
```

## 🔍 Smart Search

Powerful search functionality across all hierarchy levels:

### Search Capabilities
- 🏦 **Account IDs**: "123456789012", "prod-account"
- 🌍 **Regions**: "us-east-1", "eu-west-1", "ap-south-1"
- 📁 **Customers**: "ACME Corp", "ProjectX", "TeamAlpha"
- 🎯 **Environments**: "production", "dev", "staging"
- 🖥️ **Instance Names**: "web-server", "database", "api"
- 🏷️ **Instance IDs**: "i-1234567890abcdef0"

### Search Features
- **Real-time filtering** as you type
- **Auto-expansion** of matching tree nodes
- **Hierarchical matching** - parent nodes stay visible
- **Multi-level search** across all organization levels

## 🛠️ Advanced Usage

### Custom Tag Configuration

```bash
# Use different tag names for organization
export TAG1="Project"       # Group by project instead of customer
export TAG2="Stage"         # Group by stage instead of environment

# Example: Project -> Stage hierarchy
# 📁 WebApp (Project)
#   📁 alpha (Stage)
#   📁 beta (Stage)
#   📁 production (Stage)
```

### Multi-Profile Setup

```bash
# ~/.aws/credentials
[dev-account]
aws_access_key_id = DEV_KEY
aws_secret_access_key = DEV_SECRET

[staging-account]
aws_access_key_id = STAGING_KEY
aws_secret_access_key = STAGING_SECRET

[prod-account]
aws_access_key_id = PROD_KEY
aws_secret_access_key = PROD_SECRET

# ~/.aws/config
[profile dev-account]
region = us-east-1

[profile staging-account]
region = us-west-2

[profile prod-account]
region = eu-west-1
```

## 📊 Monitoring & Troubleshooting

### Application Logs
```bash
# View application logs
docker-compose logs -f cloudterm

# Check specific container logs
docker logs cloudterm-app
```

### Common Issues

| Issue | Solution |
|-------|----------|
| No instances found | Check AWS credentials and permissions |
| Scan fails | Verify Session Manager is enabled on instances |
| Connection timeout | Check security groups and VPC settings |
| Tag organization not working | Ensure TAG1/TAG2 environment variables are set |

### Required AWS Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ssm:StartSession",
        "ssm:TerminateSession",
        "ssm:ResumeSession",
        "ssm:DescribeSessions",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## 📚 Development

### Project Structure
```
cloudterm/
├── app.py                    # Flask application & AWS integration
├── templates/
│   └── index.html           # Main UI with auto-scan functionality
├── instances_list.yaml       # Static configuration (fallback)
├── run_with_tags.sh          # Environment setup script
├── requirements.txt          # Python dependencies
├── Dockerfile               # Container configuration
└── docker-compose.yml       # Orchestration setup
```

### Local Development
```bash
# Setup development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run with auto-scan enabled
export TAG1="Customer"
export TAG2="Environment"
python app.py
```

### API Endpoints
- `GET /` - Main application interface
- `GET /scan-instances` - Auto-scan AWS instances
- `POST /save-scanned-instances` - Save instances to YAML
- `POST /connect/<instance_id>` - Start terminal session

## 🔒 Security

- ✅ **No open ports** - Uses AWS Session Manager
- ✅ **Credential isolation** - AWS profiles from host system
- ✅ **Non-root container** - Runs as unprivileged user
- ✅ **Secure sessions** - Encrypted terminal connections
- ✅ **IAM-based access** - Leverages AWS permissions

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📜 License

MIT License - see LICENSE file for details.

---


