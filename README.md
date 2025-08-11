# CloudTerm

🚀 **A modern web-based terminal application that automatically discovers and organizes your AWS EC2 instances**

CloudTerm provides secure access to AWS EC2 instances through AWS Systems Manager Session Manager with intelligent 4-level hierarchical organization.

![CloudTerm Interface](https://github.com/user-attachments/assets/c030d8f7-30cb-4809-ad65-f0765531c20f)

## ✨ Key Features

### 🔄 **Automatic Instance Discovery**
- **Zero Configuration**: Automatically scans AWS accounts on startup
- **4-Level Hierarchy**: Account → Region → Customer → Environment
- **Multi-Account Support**: Seamlessly handles multiple AWS accounts
- **Real-Time Status**: Live instance state indicators

### 🎯 **Smart Organization**
- **Tag-Based Grouping**: Uses custom AWS tags (TAG1/TAG2) for organization
- **Visual Indicators**: Color-coded status dots (🟢 Running, 🔴 Stopped, 🟡 Transitioning)
- **Platform Detection**: Automatic Linux 🐧 / Windows 🪟 icons
- **Intelligent Search**: Search across all hierarchy levels

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

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- AWS Account with EC2 and Session Manager permissions
- AWS credentials configured

### 1. Clone Repository
```bash
git clone https://github.com/subbareddyalamur1/cloudterm.git
cd cloudterm
```

### 2. Configure AWS Credentials
```bash
# Create AWS credentials file
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

### 3. Configure Tag-Based Organization
```bash
# Set environment variables for tag-based grouping
export TAG1="Customer"     # Root level tag (e.g., Customer, Project, Team)
export TAG2="Environment"  # Branch level tag (e.g., Environment, Stage)

# Or use the provided script
./run_with_tags.sh
```

### 4. Launch Application
```bash
docker-compose up --build -d
```

### 5. Access CloudTerm
Open your browser: **http://localhost:5000**

🎉 **That's it!** CloudTerm automatically scans your AWS accounts and displays instances in an organized hierarchy.

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

### Manual Instance Management

For environments where auto-scanning isn't suitable, you can still use static configuration:

```yaml
# instances_list.yaml
acme_corp:
  region: us-east-1
  aws_profile: prod
  instances:
    production:
      - name: Web Server 1
        instance_id: i-1234567890abcdef0
      - name: Database Server
        instance_id: i-0987654321fedcba0
    development:
      - name: Dev Server
        instance_id: i-1111222233334444
```

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

**Made with ❤️ for AWS infrastructure management**
