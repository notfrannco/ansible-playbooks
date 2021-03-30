#!/bin/bash

# 1) Ensure Logrotate Runs Periodically
# Ensure_Logrotate_Runs_Periodically
GROTATE_CONF_FILE="/etc/logrotate.conf"
CRON_DAILY_LOGROTATE_FILE="/etc/cron.daily/logrotate"

# daily rotation is configured
grep -q "^daily$" $LOGROTATE_CONF_FILE|| echo "daily" >> $LOGROTATE_CONF_FILE

# remove any line configuring weekly, monthly or yearly rotation
sed -i -r "/^(weekly|monthly|yearly)$/d" $LOGROTATE_CONF_FILE

# configure cron.daily if not already
if ! grep -q "^[[:space:]]*/usr/sbin/logrotate[[:alnum:][:blank:][:punct:]]*$LOGROTATE_CONF_FILE$" $CRON_DAILY_LOGROTATE_FILE; then
    echo "#!/bin/sh" > $CRON_DAILY_LOGROTATE_FILE
    echo "/usr/sbin/logrotate $LOGROTATE_CONF_FILE" >> $CRON_DAILY_LOGROTATE_FILE
fi




# 2) Ensure gpgcheck Enabled for All yum Package Repositories
# Ensure_gpgcheck_Enabled_for_All_yum_Package_Repositories
sed -i 's/gpgcheck\s*=.*/gpgcheck=1/g' /etc/yum.repos.d/*




# 3 Ensure System Log Files Have Correct Permissions
# Ensure_System_Log_Files_Have_Correct_Permissions
# List of log file paths to be inspected for correct permissions
# * Primarily inspect log file paths listed in /etc/rsyslog.conf
RSYSLOG_ETC_CONFIG="/etc/rsyslog.conf"
# * And also the log file paths listed after rsyslog's $IncludeConfig directive
#   (store the result into array for the case there's shell glob used as value of IncludeConfig)
readarray -t RSYSLOG_INCLUDE_CONFIG < <(grep -e "\$IncludeConfig[[:space:]]\+[^[:space:];]\+" /etc/rsyslog.conf | cut -d ' ' -f 2)
# Declare an array to hold the final list of different log file paths
declare -a LOG_FILE_PATHS

# Browse each file selected above as containing paths of log files
# ('/etc/rsyslog.conf' and '/etc/rsyslog.d/*.conf' in the default configuration)
for LOG_FILE in "${RSYSLOG_ETC_CONFIG}" "${RSYSLOG_INCLUDE_CONFIG[@]}"
do
    # From each of these files extract just particular log file path(s), thus:
    # * Ignore lines starting with space (' '), comment ('#"), or variable syntax ('$') characters,
    # * Ignore empty lines,
    # * From the remaining valid rows select only fields constituting a log file path
    # Text file column is understood to represent a log file path if and only if all of the following are met:
    # * it contains at least one slash '/' character,
    # * it doesn't contain space (' '), colon (':'), and semicolon (';') characters
    # Search log file for path(s) only in case it exists!
    if [[ -f "${LOG_FILE}" ]]
    then
        MATCHED_ITEMS=$(sed -e "/^[[:space:]|#|$]/d ; s/[^\/]*[[:space:]]*\([^:;[:space:]]*\)/\1/g ; /^$/d" "${LOG_FILE}")
        # Since above sed command might return more than one item (delimited by newline), split the particular
        # matches entries into new array specific for this log file
        readarray -t ARRAY_FOR_LOG_FILE <<< "$MATCHED_ITEMS"
        # Concatenate the two arrays - previous content of $LOG_FILE_PATHS array with
        # items from newly created array for this log file
        LOG_FILE_PATHS+=("${ARRAY_FOR_LOG_FILE[@]}")
        # Delete the temporary array
        unset ARRAY_FOR_LOG_FILE
    fi
done

for LOG_FILE_PATH in "${LOG_FILE_PATHS[@]}"
do
    # Sanity check - if particular $LOG_FILE_PATH is empty string, skip it from further processing
    if [ -z "$LOG_FILE_PATH" ]
    then
        continue
    fi

    

    # Also for each log file check if its permissions differ from 600. If so, correct them
    if [ "$(/usr/bin/stat -c %a "$LOG_FILE_PATH")" -ne 600 ]
    then
        /bin/chmod 600 "$LOG_FILE_PATH"
    fi
done
