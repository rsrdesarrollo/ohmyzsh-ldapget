#!/bin/bash

_SCRIPT_DIR=${0:a:h}

for file in $_SCRIPT_DIR/config/*.conf; do 
    source $file; 
done

function ldapget(){
    USAGE="Usage: ldapget <objectclass> [-f <ldap_filter> | -z N | -H ldap_host | -b base_dn | --format <clean|bof|raw>] [<attrs>*] [@server]"
    POSITIONAL_ARGS=()
    ARGS=()

    LDAP_HOST=$DEFAULT_LDAP_SERVER
    LDAP_BASE_DN=$DEFAULT_BASE_DN
    LDAP_FILTER=""
    FORMAT="${DEFAULT_FORMAT:-clean}"

    if [ $# -lt 1 ]; then
        echo $USAGE
        return 1
    fi

    
    while [ $# -gt 0 ]; do
        case $1 in
            --all)
            shift # past argument
            ARGS+=("-E")
            ARGS+=("pr=1000/noprompt")
            ;;
            --format)
            FORMAT="$2"
            shift # past argument
            shift # past value
            ;;
            -H)
            LDAP_HOST="$2"
            shift # past argument
            shift # past value
            ;;
            -b)
            LDAP_BASE_DN="$2"
            shift # past argument
            shift # past value
            ;;
            -f)
            LDAP_FILTER="$2"
            shift # past argument
            shift # past value
            ;;
            -*|--*)
            ARGS+=($1 $2)
            shift # past argument
            shift # past value
            ;;
            @*)
            server=$(echo ${1#@} | tr '[:lower:]' '[:upper:]')
            var_server_name=${server}_LDAP_SERVER
            var_base_name=${server}_BASE_DN
            if [ -v ${var_server_name} ];then
                    LDAP_HOST=${(P)var_server_name}
                    LDAP_BASE_DN=${(P)var_base_name}
            else
                    echo "Server ${server} is not declared"
                    return 1
            fi
            shift
            ;;
            *)
            if [ "${1:l}" = "ntsecuritydescriptor" ]; then
                # ref: https://twitter.com/tifkin_/status/1372628611677753344
                ARGS+=("-E")
                ARGS+=("!1.2.840.113556.1.4.801=::MAMCAQc=")
            fi
            POSITIONAL_ARGS+=("$1") # save positional arg
            shift # past argument
            ;;
        esac
    done

    
    class=${POSITIONAL_ARGS[1]}

    if [ -z "$LDAP_FILTER" ]; then
        filter="(objectclass=$class)"
    else
        filter="(&(objectclass=$class)($LDAP_FILTER))"
    fi

    FILTER_ARGS=(
        "$filter"       #Filter
        dn description info sAMAccountName useraccountcontrol sAMAccountType objectsid #Selected attrs
    )

    if [ "$LDAPGET_DEBUG" = "true" ]; then
        set -x
    fi 

    ldapsearch -H "ldap://$LDAP_HOST" $LDAPSEARCH_OPTIONS -LLL -o ldif-wrap=no -b "$LDAP_BASE_DN" "${ARGS[@]}" "${FILTER_ARGS[@]}" "${POSITIONAL_ARGS[@]:1}" | ldapclean $FORMAT
}

function ldapclean(){
    python3 $_SCRIPT_DIR/ldif-cleaner.py $@
}

function ldap2csv(){
    $_SCRIPT_DIR/3rdparty/ldif-csv-conv/ldif2csv 
}

function ldap2json(){
    $_SCRIPT_DIR/3rdparty/ldif-csv-conv/ldif2json 
}