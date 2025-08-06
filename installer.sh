#!/bin/bash

sudo yum install python3 python3-pip cronie -y
sudo pip3 install dropbox boto3 configparser 
sudo mkdir upload
CURRENT_DIR=$(pwd)
SCRIPT_PATH="$CURRENT_DIR/AWSDataJack.py"
LOG_PATH="$CURRENT_DIR/awsdatajack.log"
PYTHON_PATH=$(which python3)

# Cron job line
CRON_JOB="30 23 * * * cd $CURRENT_DIR && $PYTHON_PATH AWSDataJack.py >> $LOG_PATH 2>&1"

# Check if cron job already exists
crontab -l 2>/dev/null | grep -F "$SCRIPT_PATH" >/dev/null

if [ $? -eq 0 ]; then
    echo "Cron job already exists. Skipping addition."
else
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "Cron job added to run every day at 23:30."
fi
sudo python3 AWSDataJack.py
