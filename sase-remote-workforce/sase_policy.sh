#!/bin/bash

LOGFILE="sase.log"

echo "=============================="
echo "SASE REMOTE WORKFORCE SIMULATOR"
echo "=============================="

while true; do

    echo ""
    echo "Enter 'exit' as username to stop."
    echo "--------------------------------"

    read -r -p "Enter username: " username

    username="${username//$'\r'/}"

    if [[ "${username,,}" == "exit" ]]; then
        echo "Simulator stopped."
        break
    fi

    read -r -p "Enter role (employee/admin): " role
    read -r -p "Enter device status (trusted/untrusted): " device
    read -r -p "Enter MFA status (yes/no): " mfa
    read -r -p "Enter location (office/remote/public): " location
    read -r -p "Enter application (HR/Finance/CRM/Admin): " app
    read -r -p "Enter risk level (low/medium/high): " risk

    # Remove Windows carriage returns
    role="${role//$'\r'/}"
    device="${device//$'\r'/}"
    mfa="${mfa//$'\r'/}"
    location="${location//$'\r'/}"
    app="${app//$'\r'/}"
    risk="${risk//$'\r'/}"

    # Convert to lowercase
    role="${role,,}"
    device="${device,,}"
    mfa="${mfa,,}"
    location="${location,,}"
    app="${app,,}"
    risk="${risk,,}"

    echo ""
    echo "===== SASE POLICY EVALUATION ====="

    decision="ALLOW"
    reason="All SASE policy requirements satisfied"

    if [[ "$device" != "trusted" ]]; then
        decision="DENY"
        reason="Untrusted device"

    elif [[ "$mfa" != "yes" ]]; then
        decision="DENY"
        reason="MFA not enabled"

    elif [[ "$risk" == "high" ]]; then
        decision="DENY"
        reason="High risk access attempt"

    elif [[ "$location" == "public" && "$app" == "admin" ]]; then
        decision="DENY"
        reason="Admin access from public network is restricted"

    elif [[ "$role" == "employee" && "$app" == "admin" ]]; then
        decision="DENY"
        reason="Employee role is not authorized for Admin application"
    fi

    echo ""
    echo "Username    : $username"
    echo "Role        : $role"
    echo "Device      : $device"
    echo "MFA         : $mfa"
    echo "Location    : $location"
    echo "Application : $app"
    echo "Risk Level  : $risk"
    echo "Decision    : $decision"
    echo "Reason      : $reason"

    # Write structured event to log
    echo "$(date '+%Y-%m-%d %H:%M:%S') | User=$username | Role=$role | Device=$device | MFA=$mfa | Location=$location | App=$app | Risk=$risk | Decision=$decision | Reason=$reason" >> "$LOGFILE"

    echo ""
    echo "Access attempt recorded in $LOGFILE"
    echo "================================="

done