#!/bin/bash
# deploy_auto.sh - Automated deployment with password

REMOTE_SERVER="root@192.142.44.140"  # Change this
REMOTE_PASSWORD="EaD7dvi8DmVtwAWG9oKE"  # Change this
REMOTE_PATH="/tmp/setup.sh"

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo "Installing sshpass..."
    sudo apt-get install -y sshpass  # Ubuntu/Debian
    # sudo yum install -y sshpass    # CentOS/RHEL
fi

echo "Deploying to remote server..."

# Step 1: Copy setup.sh to remote server
echo "Step 1: Copying setup.sh to remote server..."
sshpass -p "$REMOTE_PASSWORD" scp -o StrictHostKeyChecking=no setup.sh $REMOTE_SERVER:$REMOTE_PATH

if [ $? -ne 0 ]; then
    echo "Error: Failed to copy setup.sh to remote server"
    exit 1
fi

# Step 2: Run setup.sh on remote server
echo "Step 2: Running setup.sh on remote server..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t $REMOTE_SERVER "
    chmod +x $REMOTE_PATH && 
    echo '$REMOTE_PASSWORD' | sudo -S $REMOTE_PATH
"

if [ $? -ne 0 ]; then
    echo "Error: Failed to run setup.sh on remote server"
    exit 1
fi

# Step 3: Start the api_parser service
echo "Step 3: Starting api_parser service..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t $REMOTE_SERVER "
    echo '$REMOTE_PASSWORD' | sudo -S systemctl start api_parser.service
"

if [ $? -eq 0 ]; then
    echo "Deployment completed successfully!"
    # Check service status
    sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no $REMOTE_SERVER "
        echo '$REMOTE_PASSWORD' | sudo -S systemctl status api_parser.service
    "
else
    echo "Error: Failed to start api_parser service"
    exit 1
fi