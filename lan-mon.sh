#!/usr/bin/env bash

## @author:       Johan Alexis
## @github:       https://gihub.com/mind2hex
## Project Name:  http-enum.sh
## Description:   A simple script to enumerate http directories
## @style:        https://github.com/fryntiz/bash-guide-style
## @licence:      https://www.gnu.org/licences/gpl.txt
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>


#############################
##     CONSTANTS           ##
#############################

VERSION="[v1.09]"
AUTHOR="mind2hex"
DIRDB="$HOME/.config/lan_DB"
AUTHFILE="$DIRDB/authorized"
UNAUFILE="$DIRDB/unauthorized"
CHECKSUM="$DIRDB/.checksum.txt"

regEx="(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-b9]|[01]?[0-9][0-9]?)"
macRegEx="[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}"

#############################
##     BASIC FUNCTIONS     ##
#############################

banner(){
    echo -e " \e[31m"
    echo '                                    A   '
    echo '                                   /!\  '
    echo '                                  / ! \ '
    echo '                           /\     )___( '
    echo '                          (  `.____(_)_________'
    echo '                          |           __..--"" '
    echo '                          (       _.-|  '
    echo "    __    ___    _   __    \    ,' | |  "
    echo "   / /   /   |  / | / /     \  /   | |  "
    echo "  / /   / /| | /  |/ /       \(    | |  "
    echo " / /___/ ___ |/ /|  /         \`    | |  "
    echo "/_____/_/  |_/_/ |_/               | |  "
    echo -e " \e[32m "
    echo "    __  _______  _   ________________  ____  "
    echo "   /  |/  / __ \/ | / /  _/_  __/ __ \/ __ \ "
    echo "  / /|_/ / / / /  |/ // /  / / / / / / /_/ / "
    echo " / /  / / /_/ / /|  // /  / / / /_/ / _, _/  "
    echo "/_/  /_/\____/_/ |_/___/ /_/  \____/_/ |_|  "
    echo -e -n " \e[0m"
    echo "Version: $VERSION"
    echo " AUTHOR: mind2hex"
}

help(){
    echo 'usage: ./lan-monitor [OPTIONS] {-i|--interface}'
    echo "Description:"
    echo "   Files generated and used by this program:   "
    echo "     -->  $DIRDB         "
    echo "     -->  $UNAUFILE      "
    echo "     -->  $AUTHFILE      "    
    echo 'Options: '
    echo "     -i,--interface <iface>            : Specify interface               "
    echo "     -r,--range <ip-addr-range/CIDR>   : Specify ip address range to scan     "
    echo "     -P,--print-mode                   : Just print known and unknown group   "
    echo "     --add <mac>                       : Add mac address to known group           "
    echo "     --remove <mac>                    : Remove mac address from known group  "
    echo "     --restart                         : Restart Files used by this program "
    echo "     --usage                           : Print examples of usage         "
    echo "     -h,--help                         : Print this help message         "
    echo ""
    exit 0
}

usage(){
    echo "-----------------------------------------------------"
    echo "# To scan a network"
    echo "# This is the first thing you need to do"
    echo "# Simply use the flag -i <interface> -r <ip/range>"
    echo "  $ ./lan-monitor -i eth0 -r 192.168.0.1/24 "
    echo "-----------------------------------------------------"
    echo "# To add an address to Authorized group and to remove"
    echo "# the same address"
    echo "  $ ./lan-monitor --add ff:ff:ff:ff:ff:ff "
    echo "  $ ./lan-monitor --remove ff:ff:ff:ff:ff:ff "
    echo "-----------------------------------------------------"
    echo "# To name a host in Authorized group"
    echo "  $ ./lan-monitor --name-host home ff:ff:ff:ff:ff:ff "
    echo "-----------------------------------------------------"    
    echo "# Printing Mode, just run the program without args"
    echo "  $ ./lan-monitor "
    echo "-----------------------------------------------------"    
    exit 0
}

ERROR(){
    echo -e "[X] \e[0;31mError...\e[0m"
    echo "[*] Function: $1"
    echo "[*] Reason:   $2"
    echo "[X] Returning errorcode 1"
    exit 1
}

argument_parser(){
    ## Arguments check
    if [[ $# -eq 0 ]];then
	help
    fi

    while [[ $# -gt 0 ]];do
	case $1 in
	    -i|--interface) IFACE=$2 && shift && shift;;
	    -r|--range) RANGE=$2 && shift && shift;;
	    -P|--print-mode) PRINTMODE="TRUE" && shift;;
	    --add) AUTHADDR=(${AUTHADDR[@]} $2 ) && shift && shift;;
	    --remove) UNAUADDR=(${UNAUADDR[@]} $2 ) && shift && shift;;
	    --restart) RESTART="TRUE" && shift ;;
	    --usage) usage ;;
	    -h|--help) help;;
	    *) help ;;
	esac
    done

    ## Setting up default variables
    echo ${IFACE:="NONE"}      &>/dev/null # Interface to use for network tasks
    echo ${RANGE:=""}          &>/dev/null # range specified in CIDR notation
    echo ${PRINTMODE:="FALSE"} &>/dev/null # If True, just print the DB and exit
    echo ${AUTHADDR:="NONE"}       &>/dev/null # 
    echo ${UNAUADDR:="NONE"}       &>/dev/null #
    echo ${RESTART:="FALSE"}   &>/dev/null # If True, clean the DB 
}

generate_files(){
    ## Generate files necesary for this program
    ## This function usually is called from argument_checker function
    
    trap 'ERROR "generate_files" "Impossible "' 8
    echo "[@] files_generator  may  run  automatically  in  case the "
    echo "[@] configuration files or the database  does not exist or "
    echo "[@] if it is called by arguments"
    echo -e "========================================================="
    echo "[*] Creating DataBase..."
    echo -ne "[1] " && mkdir -v "$DIRDB"
    echo "[2] Generating $AUTHFILE" && touch $AUTHFILE
    echo "[3] Generating $UNAUFILE" && touch $UNAUFILE
    echo "[4] Generating $CHECKSUM" && md5sum $AUTHFILE $UNAUFILE > $CHECKSUM
    echo "[*] Done..."
    echo -e "=========================================================\n"
}

#############################
##     PROCESSING AREA     ##
############################# 

argument_processor(){
    
    ## if TRUE delete DB and create it again
    if [[ $RESTART == "TRUE" ]];then 
	rm -rf $DIRDB
	generate_files
    fi

    ## Just printmode 
    if [[ $PRINTMODE == "TRUE" ]];then
	printDB
	exit 0
    fi

    ## Scan mode, only if IFACE and RANGE is provided.
    if [[ "$IFACE"  != "NONE" && -n $RANGE ]];then
	##  ARP CACHE UPDATING
	echo "[*] Scanning network $RANGE"
	echo "[*] Updating arp cache tables"
	echo "[*] This can take a while "
	argument_processor_pingScanning "$IFACE" "$RANGE"
	argument_processor_ARP_table_handler "$IFACE"
	echo "[*] Finished..."
    fi

    ## Adding a host to authorization file
    if [[ ${AUTHADDR} !=  "NONE" ]];then
	num=$(expr ${#AUTHADDR[@]} - 1)
	for i in $(seq 0 $num);do
	    movAddr "${AUTHADDR[$i]}" "$UNAUFILE" "$AUTHFILE"
	done
    fi
    
    ## Removing a host from authorization file
    if [[ ${UNAUADDR} != "NONE" ]];then
	num=$(expr ${#UNAUADDR[@]} - 1)
	for i in $(seq 0 $num);do
	    movAddr "${UNAUADDR[$i]}" "$AUTHFILE" "$UNAUFILE"
	done
    fi

    ## Final step
    printDB
}

argument_processor_pingScanning(){
    ## This function updates the arp table using a nmap ping scan
    ## $1 = $IFACE
    ## $2 = $RANGE = <ip>/CIDR

    ## 2 scans to ensure all hosts are pinged
    
    ## Scan 1
    nmap -e $1 --send-ip -sP -n -T5 $2 &>/dev/null
    if [[ $? -ne 0 ]];then
	ERROR "argument_processor_pingScanning" "Error during the ping scan: $1 $2"
    fi

    ## Scan 2
    nmap -e $1 --send-ip -sP -n -T5 $2 &>/dev/null
    if [[ $? -ne 0 ]];then
	ERROR "argument_processor_pingScanning" "Error during the ping scan: $1 $2"
    fi

    return 0
}

argument_processor_ARP_table_handler(){
    ## This function extract a list of mac address and a list of ip address
    ## from the arp cache table
    ## After that, it search in the config files for matches, if there is no
    ## matches that means that the host is new, so it goes inside unauthorized file

    ## Getting arp info
    arpInfo=$(/usr/sbin/arp --device $1 -n | grep --invert-match "incomplete")
    wait

    ## Grep macs from arpInfo... Maybe i can improve this regular expression
    arpMacs=($(echo $arpInfo | grep -o -E "[0-9a-f]{2}\:[0-9a-f\:]*" | tr "\n" " "))

    ## Grep ip address
    arpAddr=($(echo $arpInfo | grep -o -E "$regEx" | tr "\n" " "))

    ## Actual BSSID from the interface
    BSSID=$(/sbin/iwgetid -r)
    
    num=$(expr ${#arpMacs[@]} - 1)
    for i in $(seq 0 $num);do
	## Ensuring to not repeat hosts in the AUTH and UNAU files
	if [[ -z $(cat $AUTHFILE | grep ${arpMacs[$i]}) && -z $(cat $UNAUFILE | grep ${arpMacs[$i]}) ]];then
	    printf "%-13s %17s  %-8s %-8s \n" ${arpAddr[$i]} ${arpMacs[$i]} ${IFACE:0:7} ${BSSID:0:7} >> $UNAUFILE
	else
	    continue
	fi
    done
}

printDB(){
    ## Esta funcion solo muestra los
    ## archivos de configuracion sin modificarlos
    
    ## Printing authorized file
    header=`printf "  %-13s %-17s  %-8s %-8s %-8s\n" "IP-ADDRESS" "MAC-ADDRESS" "IFACE" "SSID" "NAME"`
    echo -e "\e[32m" # Green
    echo "======== AUTHORIZED GROUP ========================================"
    echo "$header"
    echo "=================================================================="
    ## Sorting output
    cat "$AUTHFILE" |  grep --invert-match "^\#" | sort --version-sort | nl -w 1 | tr "\t" " " 

    ## Printing unauthorized file
    echo -e "\e[31m" # RED
    echo "======== UNAUTHORIZED GROUP ======================================"
    echo "$header"
    echo "=================================================================="
    ## Sorting output
    cat "$UNAUFILE" | grep --invert-match "^\#" | sort --version-sort | nl -w 1 | tr "\t" " "
    echo -e "\e[0m"
}

movAddr(){
    ## This function move address $1 from $src to $dst
    # $1 MAC
    # $2 src_file
    # $3 dst_file
    local aux
    
    ## Checking if MAC is not in dst
    if [[ -n $(cat $3 | grep "$1") ]];then
	ERROR "movAddr" "MAC: $1 is already in $3"
    fi

    ## Checking if MAC is in src
    if [[ -z $(cat $2 | grep "$1") ]];then
	ERROR "movAddr" "MAC: $1 is not in $2"
    fi

    ## Checking if MAC is in both [src,dst]
    if [[ -n $(cat $2 | grep "$1") && -n $(cat $3 | grep "$1") ]];then
	echo "[X] MAC: $1 is in both files. "
	echo "[!] Deleting $1 from $AUTHFILE"
	aux=$(cat $AUTHFILE | grep -n "$1" | grep -E -o "^[0-9]{1,3}")
	echo "$(sed ${aux}d $AUTHFILE)" > $AUTHFILE
    fi

    data=$(cat $2 | grep "$1")
    aux=$(cat $2 | grep -n "$1" | grep -E -o "^[0-9]{1,3}")
    echo "$(sed ${aux}d $2)" > $2
    echo "$data" >> $3

    ## Removing empty lines from files
    AUTHRESULT=$(cat $AUTHFILE | grep "\S" --color=never)
    echo "$AUTHRESULT" > $AUTHFILE
    
    UNAURESULT=$(cat $UNAUFILE | grep "\S" --color=never)
    echo "$UNAURESULT" > $UNAUFILE
}

DB_checkSum(){
    ## Checking if the DB has been changed using md5 verification sum
    md5sum --check $CHECKSUM &>/dev/null
    local aux=$?
    if [[ $RESTART != "TRUE" ]];then
	if [[ $aux -ne 0 ]];then
	    ERROR "DB_checkSum" "DB has been corrupted. Use --restart"
	fi
    fi
}

DB_checkSum_update(){
    md5sum $AUTHFILE $UNAUFILE > $CHECKSUM
}


#############################
##      STARTING POINT     ##
#############################

banner
argument_parser "$@"
source argument_checker.sh
DB_checkSum
argument_processor
DB_checkSum_update
exit 0

# - Add name host utility
