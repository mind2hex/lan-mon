argument_checker(){
    ## Print mode only print the DB so there is no need to do more checks
    if [[ $PRINTMODE == "TRUE" ]];then
        return 0
    fi
    
    ## Checking external programs used by this program
    argument_checker_requeriments
    
    ## configuration files check
    argument_checker_config_files

    ## Checking Mac address syntax
    argument_checker_mac  ## Uses global var $AUTHADDR $UNAUADDR $NAMEHOST $UNAMEHOST        
    
    ## Checking interface
    argument_checker_interface $IFACE

    ## ip scanning range
    argument_checker_range $RANGE

    ## Checking address existence inside auth group of the DB
    argument_checker_auth_addr # "${AUTHADDR}" "${UNAUADDR}" --> arrays


}

argument_checker_requeriments(){
    ## fping check
    if [[ -z $(which fping) ]];then # using which
	if [[ -z $(apt-cache policy fping | grep -o "^fping" | head -n 1) ]];then # using apt
	    ERROR "argument_checker_requeriments" "fping is not installed"
	fi
    fi

    ## nmap check
    if [[ -z $(which nmap) ]];then #using which
	if [[ -z $(apt-cache policy nmap | grep -o "^nmap" | head -n 1) ]];then # using apt
	    ERROR "argument_checker_requeriments" "nmap is not installed"
	fi
    fi

    ## iwgetid check
    if [[ -z $(which iwgetid) ]];then
	if [[ -z $(apt-cache policy iwgetid | grep -o "^iwgetid" | head -n 1) ]];then
	    ERROR "argument_checker_requeriments" "iwgetid is not installed"
	fi
    fi
}

argument_checker_config_files(){
    ## /home/$USER/.config file check
    if [[ ! -e /home/$USER/.config ]];then
	mkdir /home/$USER/.config # Creating .config file if it not exist
    fi
    
    ## Checking for program files existence
    for i in "$DIRDB" "$AUTHFILE" "$UNAUFILE" "$CHECKSUM";do
	if [[ -e $i ]];then
	    continue
	else
	    generate_files
	    DB_checkSum
	    break
	fi
    done
}

argument_checker_mac(){
    ## This function checks if mac address are valid

    ## Checking Mac address from AUTHADDR
    if [[ ${AUTHADDR} != "NONE" ]];then
	local aux=$(expr ${#AUTHADDR[@]} - 1)
	for i in $(seq 0 ${aux});do
	    if [[ -z $(echo ${AUTHADDR[$i]} | grep -o -E "${macRegEx}" | head -n 1) ]];then
		ERROR "argument_checker_mac" "Invalid Mac address ${AUTHADDR[$i]}"
	    fi
	done
    fi

    if [[ ${UNAUADDR} != "NONE" ]];then
	local aux=$(expr ${#UNAUADDR[@]} - 1)
	for i in $(seq 0 ${aux});do
	    if [[ -z $(echo ${UNAUADDR[$i]} | grep -o -E "${macRegEx}" | head -n 1) ]];then
		ERROR "argument_checker_mac" "Invalid Mac address ${AUTHADDR[$i]}"
	    fi
	done
    fi
}

argument_checker_interface(){
    ## iface provided check
    if [[ $1 == "NONE" ]];then
        ERROR "argument_checker_interface" "Interface not provided... Use -h for help"
    fi

    ## iface name check  [using ip command]
    ip link show $1 1>/dev/null
    if [[ $? -ne 0 ]];then # If IFACE doesn't exist.
        ERROR "argument_checker_interface" "Interface doesn't exist... Use -h for help"
    fi

    ## iface connection check
    if [[ $(cat /sys/class/net/$1/carrier) -ne 1 ]];then 
        ERROR "argument_checker_interface" "Interface is not connected to a network"
    fi
}

argument_checker_range(){
    ## ip check
    if [[ -z $(echo $1 | grep -E -o "${regEx}") ]];then
	ERROR "argument_checker_range" "Invalid ip address specification"
    fi
        
    ## CIDR check
    if [[ -z $(echo $1 | grep -E -o "\/[0-9]{1,2}") ]];then
       ERROR "argument_checker_range" "Invalid CIDR specification"
    fi

    ## Do more CIDR and IP checks here
}

argument_checker_auth_addr(){
    ## Checking AUTHADDR array
    if [[ ${AUTHADDR} != "NONE" ]];then
        aux=$(expr ${#AUTHADDR[@]} - 1)

	## Iterating AUTHADDR array
        for i in $(seq 0 $aux);do
	    ## Check if address is already in authorized file
            if [[ -n $(cat $AUTHFILE | grep "${AUTHADDR[$i]}")  ]];then
                ERROR "argument_checker_auth_addr" "MAC: ${AUTHADDR[$i]} is already in $AUTHFILE"
	    fi

	    ## Check if address is in unauthorized file
            if [[ -z $(cat $UNAUFILE | grep "${AUTHADDR[$i]}") ]];then
                ERROR "argument_checker_auth_addr" "MAC: ${AUTHADDR[$i]} is not in $UNAUFILE"
            fi
        done
    fi
    
    ## Checking UNAUADDR array
    if [[ ${UNAUADDR} != "NONE" ]];then
        aux=$(expr ${#UNAUADDR[@]} - 1)

	## Iterating UNAUADDR array
        for i in $(seq 0 $aux);do
	    ## Check if address is already in unauthorized file
            if [[ -n $(cat $UNAUFILE | grep "${UNAUADDR[$i]}" ) ]];then
                ERROR "argument_checker_auth_addr" "MAC: ${UNAUADDR[$i]} is already in $UNAUFILE"
	    fi

	    ## Check if address is in authorized file
            if [[ -z $(cat $AUTHFILE | grep "${UNAUADDR[$i]}") ]];then
                ERROR "argument_checker_auth_addr" "MAC: ${UNAUADDR[$i]} is not in $AUTHFILE "
            fi
        done
    fi    
}

argument_checker "$@"
