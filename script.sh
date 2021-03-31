#!/bin/bash

# 1) xccdf_org.ssgproject.content_rule_auditd_audispd_syslog_plugin_activated
var_syslog_active="yes"


AUDISP_SYSLOGCONFIG=/etc/audisp/plugins.d/syslog.conf
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}

replace_or_append $AUDISP_SYSLOGCONFIG '^active' "$var_syslog_active" ""





















# 3) xccdf_org.ssgproject.content_rule_audit_rules_login_events
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/tallylog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/tallylog" "wa" "logins"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/var/run/faillock/" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/run/faillock/" "wa" "logins"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/lastlog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/lastlog" "wa" "logins"




































# xccdf_org.ssgproject.content_rule_audit_rules_time_stime
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}


# Function to perform remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on RHEL, Fedora or OL systems.
# Remediation performed for both possible tools: 'auditctl' and 'augenrules'.
#
# Note: 'stime' system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
# therefore excluded from the list of time group system calls to be audited on this arch
#
# Example Call:
#
#      perform_audit_adjtimex_settimeofday_stime_remediation
#
function perform_audit_adjtimex_settimeofday_stime_remediation {

# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

	PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
	# Create expected audit group and audit rule form for particular system call & architecture
	if [ ${ARCH} = "b32" ]
	then
		# stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
		# so append it to the list of time group system calls to be audited
		GROUP="\(adjtimex\|settimeofday\|stime\)"
		FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
	elif [ ${ARCH} = "b64" ]
	then
		# stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
		# therefore don't add it to the list of time group system calls to be audited
		GROUP="\(adjtimex\|settimeofday\)"
		FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
	fi
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

perform_audit_adjtimex_settimeofday_stime_remediation






































# xccdf_org.ssgproject.content_rule_audit_rules_time_watch_localtime
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
fix_audit_watch_rule "augenrules" "/etc/localtime" "wa" "audit_time_rules"








































# xccdf_org.ssgproject.content_rule_audit_rules_time_adjtimex
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}


# Function to perform remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on RHEL, Fedora or OL systems.
# Remediation performed for both possible tools: 'auditctl' and 'augenrules'.
#
# Note: 'stime' system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
# therefore excluded from the list of time group system calls to be audited on this arch
#
# Example Call:
#
#      perform_audit_adjtimex_settimeofday_stime_remediation
#
function perform_audit_adjtimex_settimeofday_stime_remediation {

# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

	PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
	# Create expected audit group and audit rule form for particular system call & architecture
	if [ ${ARCH} = "b32" ]
	then
		# stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
		# so append it to the list of time group system calls to be audited
		GROUP="\(adjtimex\|settimeofday\|stime\)"
		FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
	elif [ ${ARCH} = "b64" ]
	then
		# stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
		# therefore don't add it to the list of time group system calls to be audited
		GROUP="\(adjtimex\|settimeofday\)"
		FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
	fi
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

perform_audit_adjtimex_settimeofday_stime_remediation
































# xccdf_org.ssgproject.content_rule_audit_rules_time_clock_settime
# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S clock_settime -F a0=.* \(-F key=\|-k \).*"
	GROUP="clock_settime"
	FULL_RULE="-a always,exit -F arch=$ARCH -S clock_settime -F a0=0x0 -k time-change"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done





















































# xccdf_org.ssgproject.content_rule_audit_rules_time_settimeofday
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}


# Function to perform remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on RHEL, Fedora or OL systems.
# Remediation performed for both possible tools: 'auditctl' and 'augenrules'.
#
# Note: 'stime' system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
# therefore excluded from the list of time group system calls to be audited on this arch
#
# Example Call:
#
#      perform_audit_adjtimex_settimeofday_stime_remediation
#
function perform_audit_adjtimex_settimeofday_stime_remediation {

# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

	PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
	# Create expected audit group and audit rule form for particular system call & architecture
	if [ ${ARCH} = "b32" ]
	then
		# stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
		# so append it to the list of time group system calls to be audited
		GROUP="\(adjtimex\|settimeofday\|stime\)"
		FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
	elif [ ${ARCH} = "b64" ]
	then
		# stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
		# therefore don't add it to the list of time group system calls to be audited
		GROUP="\(adjtimex\|settimeofday\)"
		FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
	fi
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

perform_audit_adjtimex_settimeofday_stime_remediation










































# xccdf_org.ssgproject.content_rule_audit_rules_file_deletion_events
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=unset -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="\(rmdir\|unlink\|rename\)"
	FULL_RULE="-a always,exit -F arch=$ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done









































# xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading
# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
        GROUP="modules"

        PATTERN="-a always,exit -F arch=$ARCH -S init_module -S delete_module -S finit_module -S create_module \(-F key=\|-k \).*"
        FULL_RULE="-a always,exit -F arch=$ARCH -S init_module -S delete_module -S finit_module -S create_module -k modules"

        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}

        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

# Then perform the remediations for the watch rules
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/insmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/insmod" "x" "modules"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/rmmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/rmmod" "x" "modules"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/modprobe" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/modprobe" "x" "modules"









































# xccdf_org.ssgproject.content_rule_audit_rules_networkconfig_modification
# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="set\(host\|domain\)name"
	FULL_RULE="-a always,exit -F arch=$ARCH -S sethostname -S setdomainname -k audit_rules_networkconfig_modification"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

# Then perform the remediations for the watch rules
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/issue" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/issue" "wa" "audit_rules_networkconfig_modification"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/issue.net" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/issue.net" "wa" "audit_rules_networkconfig_modification"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/hosts" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/hosts" "wa" "audit_rules_networkconfig_modification"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/sysconfig/network" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/sysconfig/network" "wa" "audit_rules_networkconfig_modification"










































# xccdf_org.ssgproject.content_rule_audit_rules_session_events
# Perform the remediation
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/var/run/utmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/run/utmp" "wa" "session"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/btmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/log/btmp" "wa" "session"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/wtmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/log/wtmp" "wa" "session"











































# xccdf_org.ssgproject.content_rule_audit_rules_usergroup_modification
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/group" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/group" "wa" "audit_rules_usergroup_modification"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/passwd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/passwd" "wa" "audit_rules_usergroup_modification"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/shadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/shadow" "wa" "audit_rules_usergroup_modification"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"














































# xccdf_org.ssgproject.content_rule_audit_rules_mac_modification
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/selinux/" "wa" "MAC-policy"
fix_audit_watch_rule "augenrules" "/etc/selinux/" "wa" "MAC-policy"


















































# xccdf_org.ssgproject.content_rule_audit_rules_sysadmin_actions
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/sudoers" "wa" "actions"
fix_audit_watch_rule "augenrules" "/etc/sudoers" "wa" "actions"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	# Backup IFS value
	IFS_BKP="$IFS"
	# Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
	# Get pair -- filepath : matching_row into @matches array
	IFS=$'\n'
	matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}

fix_audit_watch_rule "auditctl" "/etc/sudoers.d" "wa" "actions"
fix_audit_watch_rule "augenrules" "/etc/sudoers.d" "wa" "actions"














































# xccdf_org.ssgproject.content_rule_audit_rules_media_export
# Perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=unset -k *"
	GROUP="mount"
	FULL_RULE="-a always,exit -F arch=$ARCH -S mount -F auid>=1000 -F auid!=unset -k export"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	IFS_BKP="$IFS"
	# Check if particular audit rule is already defined
	IFS=$'\n'
	matches=($(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"
	for match in "${matches[@]}"
	do
		files_to_inspect=("${files_to_inspect[@]}" "${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		files_to_inspect="/etc/audit/rules.d/$key.rules"
		if [ ! -e "$files_to_inspect" ]
		then
			touch "$files_to_inspect"
			chmod 0640 "$files_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

	IFS_BKP="$IFS"
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	IFS=$'\n'
	existing_rules=($(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	# Reset IFS back to default
	IFS="$IFS_BKP"

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				IFS_BKP="$IFS"
				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done











































# xccdf_org.ssgproject.content_rule_grub2_audit_argument
# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*audit=.*"'  '/etc/default/grub' ; then
	# modify the GRUB command-line if an audit= arg already exists
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)audit=[^[:space:]]*\(.*"\)/\1 audit=1 \2/'  '/etc/default/grub'
else
	# no audit=arg is present, append it
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 audit=1"/'  '/etc/default/grub'
fi

# Correct the form of kernel command line for each installed kernel in the bootloader
grubby --update-kernel=ALL --args="audit=1"







































# 
