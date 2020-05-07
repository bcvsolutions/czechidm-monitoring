#!/bin/bash

# ********************************** READ ME **********************************
#
# General:
# Script is intended to do encrypted backups of whatever you implement in parts
# "do the dump" and "pack the dump". The result of your doing should be a tar
# archive called "current_backup.tar". This name is automatically recognized and
# script will take care of everything else. Presumed shell is BASH.
#
# Output of the script is saved into BACKUP_LOC directory in an encrypted form.
# Each backup consists of two files - symmetric key and public key. Because en-
# cryption is done by openssl, which cannot process an arbitrary file directly
# with RSA, files are first encrypted with random 32B key using AES-256-CBC.
# This 32B key is encrypted with RSA public key which is stored on the machine.
# Private RSA key SHOULD NOT be found anywhere on the same machine. If it was,
# you could do plain backups and not bother with this at all and security would
# be the same.
#
# Needed binaries and builtins:
# test,echo,stat,id,tar,openssl,touch,chmod,rm,mv,find,date,basename
#
# Setup:
# 1) Create separate system user to run this script, do not run it as root.
# 2) Generate public-private key pair of at least 2048b:
#		openssl genrsa -out backups-rsa-key 2048
#		openssl rsa -in backups-rsa-key -out backups-rsa-key.pub \
#			-outform PEM -pubout
# 3) The backups-rsa-key file contains private key, store it in the keepass
#	 or somewhere safe. Do not leave it on the machine!
# 4) Move backups-rsa-key.pub to BACKUP_ROOT, set correct privileges (400),
#	 name it as you wish and set RSA_ENC_KEY_FILE accordingly.
# 5) Fill in the "do the dump" and "pack the dump" parts of the script to suit
#	 your needs.
# 6) Adjust other settings in the script as needed. Ensure that service user
#	 used for dumping the DB, LDAP, whatever is dedicated to this and has
#	 read-only privileges! This is IMPORTANT!
# 7) Run the script as a cronjob. Preferred setting is in the crontallb, not in the
#	 /etc/cron.*/whatever file. But it does not really matter.
#
# Recovering backups:
# Backups are stored in BACKUP_LOC as a pair of files. One file is an actual
# backup encrypted symmetrically. The other file is a symmetric key for the
# specific backup. (New symmetric key is generated for each backup run.)
# Symmetric key is encrypted with RSA.
#
# To recover backups, do the following:
# 1) Get you backups, we will call them "data.tar.e" and "key.bin.e".
# 2) Get your private RSA key "backups-rsa-key".
# 3) Decrypt the AES key, you will obtain "key.bin" file:
#		openssl rsautl -decrypt -inkey backups-rsa-key \
#			-in key.bin.e -out key.bin
# 4) Decrypt the actual backup, you will get a tarball:
#               openssl enc -d -aes-256-cbc -in data.tar.e -out data.tar \
#                       -pass file:key.bin
#		- or use this command if you are using openssl 1.1.1 and newer 
#		openssl enc -d -pbkdf2 -aes-256-cbc -in data.tar.e -out data.tar \
#			-pass file:key.bin
# 5) Extract the tarball:
#		tar xf data.tar
# 6) Get your backups and restore whatever you need from them.
# *****************************************************************************
#
# TODO:
#		* better backups naming
#		* something like .d directory where backup scripts will lay to make whole
#			thing a bit more modular
#		* add actions like "init", "recover" and "backup" to make script more
#			user-friendly
#
# Revision history:
# 2020-03-27  Ludek Urban <ludek.urban@bcvsolutions.eu>
#   * added "backup encryption" and "decryption tutorial" for using openssl 1.1.1 and newer
# 2020-03-03  Petr Fiser  <petr.fiser@bcvsolutions.eu>
#   * reworked packing of dumps before encryption
#   * changed some default names, fixed typos
# 2017-05-16  Petr Fiser  <petr.fiser@bcvsolutions.eu>
#		* removed hardwired LDAP variables (original script was for LDAP backups)
#		* removed hardwired lockfile name
#		* PASS_FILE made optional
#		* backup timestamp with granularity to seconds instead of hours
# 2016-02-25  Petr Fiser  <petr.fiser@bcvsolutions.eu>
#		* first version of the script

# basic functions


errecho () {
	echo -e "$@" 1>&2;
}
err () {
	errecho "$1";
	exit "$2";
}

usage () {
	
	errecho "Backup script usage:";
        errecho "-----------";
	errecho "Use one of these parameters to set script function:";
	errecho "-c to run encrypt for cron usage / to execute backups manually";
	errecho "-d to run dencrypt manually - Must be used with options -o and -b. Can use options -k and -s";
	errecho "-----------";
	errecho "-b {\$PATH} to set path to backup file with will be decrypted. Script will also find key file with same name and in same directory if '-s' is not set.";
	errecho "-k {\$PATH} to set path to private key";
	errecho "-h to print this help";
	errecho "-o {\$PATH} to set path to decrypt output file";
	errecho "-s {\$PATH} to set path to encrypted symmetrical key";
	errecho "-v to run in verbose mode";
        errecho "-----------";
	errecho "script will also load variables from '${CONFIG_FILE}'. This file must exist and be radable."
	errecho "These variables will replace script defaults"
	exit 1
}
#create lock so we cannot run it more than once
lock_script () {
        touch "${RUN_LOCK}"
}

unlock_script () {
        rm -f "${RUN_LOCK}"
}

## check functions

# check if script function is already set 
function_check () {
        if [ "${FUNCTION}" != "" ]
        then
                errecho "Too many function parameters";
                usage;
        fi
}

# permition in work dir
wdir_wrcheck () {
        [ -w "{$BACKUP_ROOT}" ] || err "Can't write to '{$BACKUP_ROOT}'" 1
}


# check script lock
check_lock () {
        if test -e "$RUN_LOCK"; then
                echo "${RUN_LOCK} exists. Assuming ${0} already running." >&2
                exit 1
        fi
}

# check public async key
check_pub_async_key () {
        if test ! $(stat -c %a "${RSA_ENC_KEY_FILE}") -eq 400 || ! test $(stat -c %u "${RSA_ENC_KEY_FILE}") -eq "$EUID" || ! test $(stat -c %g "${RSA_ENC_KEY_FILE}") -eq `id -g`; then
        echo "File ${RSA_ENC_KEY_FILE} has incorrect permissions (should be 400) or owner/group (should be `stat -c %U ${0}`)." >&2
        exit 1
fi
}

# script functions

encrypt () {

        check_lock;
        # check correct permitions on public async key
        check_pub_async_key;
        lock_script;

        #generate symmetric key here and push it (asymmetrically encrypted) into a file. this file will accompany symmetrically encrypted tar
        #we use aes-256 to encrypt our dumps so we need 32*8=256b symmetric key
        SYM_KEY=`openssl rand -base64 32`

        #encrypt the symmetric key
        openssl rsautl -encrypt -pubin -inkey "$RSA_ENC_KEY_FILE" -out current_key.bin.e <<< "$SYM_KEY"
        chmod 600 current_key.bin.e

        #do the dump
        # say we run the actual backup and create dump1.dmp, dump2.dmp and dump3.dmp here
        # STRONGLY ADVISED TO GZIP YOUR BACKUPS, SCRIPT DOES NOT DO THAT FOR YOU !!!

        #pack the dump
        #tar usage "tar [parameters] archive_name file1 [file2 file3 ...]"
        tar --remove-files -cf current_backup.tar PUT-YOUR-FILES-HERE
        

        chmod 600 current_backup.tar

        #encrypt the dump with current symmetric key, also add a pinch of salt
        if [[ "${OPENSSL_VERSION}" > "1.1.1" || "${OPENSSL_VERSION}" = "1.1.1" ]]
        then
                openssl enc -aes-256-cbc -salt -pbkdf2 -in "current_backup.tar" -out "current_backup.tar.e" -pass stdin <<< "$SYM_KEY"
        else
                # If you are not using openssl 1.1.1 and newer use this command instead
                openssl enc -aes-256-cbc -salt -in "current_backup.tar" -out "current_backup.tar.e" -pass stdin <<< "$SYM_KEY"
        fi
	        #remove unencrypted dump and key
        rm -f current_backup.tar

        #move encrypted things to backup_loc
        mv current_backup.tar.e "${BACKUP_LOC}/${BACKUP_FILE_NAME}"
        mv current_key.bin.e "${BACKUP_LOC}/${BACKUP_AES_KEY_FILENAME}"

        #clean up backups older than $BACKUP_KEEP_DAYS days
        find "$BACKUP_LOC" -name "${BACKUP_PREFIX}*${BACKUP_SUFFIX}" -type f -mtime "+${BACKUP_KEEP_DAYS}" -delete
        find "$BACKUP_LOC" -name "${BACKUP_AES_KEY_PREFIX}*${BACKUP_AES_KEY_SUFFIX}" -type f -mtime "+${BACKUP_KEEP_DAYS}" -delete

        #we have finished, remove lock
        unlock_script;
}

decrypt () {

        #check input variables
        [ "${BACKUP_FILE_NAME_GIVEN}" != "" ] || errecho "Backup file parameter is not set'";
        [ "${BACKUP_FILE_NAME_GIVEN}" != "" ] || usage;
        [ -r "${BACKUP_FILE_NAME_GIVEN}" ] || err "Can't open backup file: '${BACKUP_FILE_NAME_GIVEN}'" 1;

        if [ "${BACKUP_AES_KEY_FILENAME_GIVEN}" == "" ]
        then
                basename "${BACKUP_FILE_NAME_GIVEN}" "${BACKUP_SUFFIX}"
                [ -r "${BACKUP_FILE_NAME_GIVEN}.${BACKUP_AES_KEY_SUFFIX}" ] || err "Can't open symetric key file: '${BACKUP_FILE_NAME_GIVEN}.${BACKUP_AES_KEY_SUFFIX}'" 1;
        fi

        # check work directory and target directory

        wdir_wrcheck;

        # decrypt symetric key

        # decrypt backup

        # clen work files

        # tmp   
        exit;

        #encrypt the dump with current symmetric key, also add a pinch of salt
        if [[ "${OPENSSL_VERSION}" > "1.1.1" || "${OPENSSL_VERSION}" = "1.1.1" ]]
        then
                openssl enc -aes-256-cbc -salt -pbkdf2 -in "current_backup.tar" -out "current_backup.tar.e" -pass stdin <<< "$SYM_KEY"
        else
                # If you are not using openssl 1.1.1 and newer use this command instead
                openssl enc -aes-256-cbc -salt -in "current_backup.tar" -out "current_backup.tar.e" -pass stdin <<< "$SYM_KEY"
        fi

}


# basic setup
export PATH="/bin:/usr/bin"
unset CDPATH
#directory where everything happens
#should be empty except for backup scripts, keys and BACKUP_LOC folder
BACKUP_ROOT="/opt/backup"

#set config file name from which will load variables
CONFIG_FILE="${BACKUP_ROOT}/encrypted_backup.conf"

#hic sunt backupes
BACKUP_LOC="${BACKUP_ROOT}/repository"
#lockfile
RUN_LOCK="${BACKUP_ROOT}/`basename ${0}`.lock"
BACKUP_PREFIX="backup."
BACKUP_SUFFIX=".tar.e"
BACKUP_AES_KEY_PREFIX="backup."
BACKUP_AES_KEY_SUFFIX=".aes.key.e"
#files with public RSA key and password file
RSA_ENC_KEY_FILE="${BACKUP_ROOT}/backups-rsa-key.pub"
#backups retention period
BACKUP_KEEP_DAYS="30"

# setup runtime variables
NOW=$(date +"%Y-%m-%d-%H%M%S")
BACKUP_FILE_NAME="${BACKUP_PREFIX}${NOW}${BACKUP_SUFFIX}"
BACKUP_AES_KEY_FILENAME="${BACKUP_AES_KEY_PREFIX}${NOW}${BACKUP_AES_KEY_SUFFIX}"

# loading config file from backup root if exist
if [ -e "${CONFIG_FILE}" ]
then
        # check if file can be read
        [ -r "${CONFIG_FILE}" ] || err "Can't open config file '${CONFIG_FILE}'. Exiting" "1";
        source "${CONFIG_FILE}"

fi

# parameter processing
# print help if no parameters
[ $# -ne 0 ] || usage;

while [ $# -gt 0 ]; do
key="$1";
case $key in
        -h)
                usage;
        ;;
        -v)
                VERBOSE="1";
        ;;
        -c)
                function_check ;
                FUNCTION="1";
        ;;
        -d)
                function_check ;
                FUNCTION="2";
        ;;
        -b)
                [ "$2" != "" ] || err "Missing second parameter near -b" 1
                BACKUP_FILE_NAME_GIVEN="$2";
                shift;
        ;;
        -s)
                [ "$2" != "" ] || err "Missing second parameter near -s" 1
                BACKUP_AES_KEY_FILENAME_GIVEN="$2";
                shift;
        ;;
        -k)
                [ "$2" != "" ] || err "Missing second parameter near -k" 1
                RSA_ENC_KEY_FILE="$2";
                shift;
        ;;
        -o)
                [ "$2" != "" ] || err "Missing second parameter near -o" 1

                DECRYPT_OUTPUT_FILE="$2";
                shift;
        ;;
        *)
        errecho "Unknown parameter '$key $2' specified.";
        usage;
        ;;
esac
shift; # procces next parameter or value
done

# print loaded parameters if verbose
if [ "${VERBOSE}" == "1" ]
then
        errecho "Backup script laoded parameters:";
        errecho "-----------";
        errecho "VERBOSE: ${VERBOSE}";
        errecho "PATH: ${PATH}";
        errecho "BACKUP_ROOT: ${BACKUP_ROOT}";
        errecho "CONFIG_FILE: ${CONFIG_FILE}";
        errecho "BACKUP_LOC: ${BACKUP_LOC}";
        errecho "RUN_LOCK: ${RUN_LOCK}";
        errecho "BACKUP_PREFIX: ${BACKUP_PREFIX}";
        errecho "BACKUP_SUFFIX: ${BACKUP_SUFFIX}";
        errecho "BACKUP_AES_KEY_PREFIX: ${BACKUP_AES_KEY_PREFIX}";
        errecho "BACKUP_AES_KEY_SUFFIX: ${BACKUP_AES_KEY_SUFFIX}";
        errecho "RSA_ENC_KEY_FILE: ${RSA_ENC_KEY_FILE}";
        errecho "BACKUP_KEEP_DAYS: ${BACKUP_KEEP_DAYS}";
        errecho "NOW: ${NOW}";
        errecho "BACKUP_FILE_NAME: ${BACKUP_FILE_NAME}";
        errecho "BACKUP_AES_KEY_FILENAME: ${BACKUP_AES_KEY_FILENAME}";
        errecho "FUNCTION(ENCRYPT=1,DECRYPT=2): ${FUNCTION}";
        errecho "BACKUP_FILE_NAME_GIVEN: ${BACKUP_FILE_NAME_GIVEN}";
        errecho "BACKUP_AES_KEY_FILENAME_GIVEN: ${BACKUP_AES_KEY_FILENAME_GIVEN}";
        errecho "DECRYPT_OUTPUT_FILE: ${DECRYPT_OUTPUT_FILE}";
        errecho "-----------";
        set -x;
fi

# parameter test

if [ "${FUNCTION}" == "" ]
then
        errecho "Function parameter is not set";
        usage;
fi

## run script checks
## these check are shared for all functions

# check root, must not run as root
if test "$EUID" -eq 0; then
        echo "Script MUST NOT be run as root." >&2
        exit 1
fi

# check binaries we need
if test ! -x `which tar`; then
        echo "'tar' not found or not executable" >&2
        exit 1
fi
if test ! -x `which openssl`; then
        echo "'openssl' not found or not executable" >&2
        exit 1
fi

#set openssl version
OPENSSL_VERSION="$( openssl version |cut -d ' ' -f2 )"

#cd to our working dir
cd "$BACKUP_ROOT"

case "${FUNCTION}" in
        1)
                encrypt;
                ;;
        2)
                #decrypt;
                errecho "TODO decrypt"
                ;;
        *)
                err "interenal error" 1;
                ;;
esac

exit 0









