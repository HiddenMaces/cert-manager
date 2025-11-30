#!/bin/bash

# ==========================================
# PKI Certificate Manager 
# ==========================================

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CERT_DIR="./certs"
ROOT_DIR="./rootCA"
ROOT_CA="internal_rootca"

#Creating necessary directories
mkdir -p ${CERT_DIR}
mkdir -p ${ROOT_DIR}

# --- Input Gathering Function ---
get_details() {
    echo -e "${CYAN}--- Certificate Details ---${NC}"
    if [[ -z "$FQDN" ]]; then read -p "Enter FQDN (Common Name) [e.g., www.example.com]: " FQDN; fi

    OUT_DIR=".${CERT_DIR}/${FQDN}"
    # 1. Check if certificate exists
    if [[ -f "${OUT_DIR}/${FQDN}.crt" ]]; then
    	echo -ne "${RED}Certificate '${FQDN}' already exists. Do you want to continue? [y/N]:${NC} "
	read -r response
    	# 2. Check if the answer is NOT Yes (using regex for y or Y)
    	if [[ ! "$response" =~ ^[yY]$ ]]; then
        	echo -e "\n${CYAN}Exiting...${NC}"
        	exit 1 # Exit with a failure code
    	fi
    fi
    # create fqdn dir
    mkdir -p "${OUT_DIR}"
    
    if [[ -z "$COUNTRY" ]]; then read -e -i "NL" -p "Enter Country Code (2 letters) [e.g., US]: " COUNTRY; fi
    #if [[ -z "$STATE" ]]; then read -p "Enter State or Province [e.g., New York]: " STATE; fi
    if [[ -z "$CITY" ]]; then read -e -i "" -p "Enter Locality/City [e.g., Amsterdam]: " CITY; fi
    if [[ -z "$ORG" ]]; then read -e -i "Internal" -p "Enter Organization Name [e.g., MyCompany Ltd]: " ORG; fi
    if [[ -z "$ORG_UNIT" ]]; then read -p "Enter Organizational Unit [e.g., IT Dept]: " ORG_UNIT; fi

    if [[ -z "$FQDN" || -z "$COUNTRY" ]]; then
        echo -e "${RED}Error: FQDN and Country are mandatory.${NC}"
        return 1
    fi
}
get_root_details() {
    echo -e "${CYAN}--- RootCA Certificate Details ---${NC}"
    if [[ -z "$ROOT_CN" ]]; then read -e -i "My Internal rootCA" -p "Enter Description (used as Common Name) [My Internal rootCA]: " ROOT_CN; fi
    
    OUT_DIR="${CERT_DIR}${ROOT_DIR}"
    # 1. Check if rootCA exists
    if [[ -f "${OUT_DIR}/${ROOT_CA}.crt" ]]; then
    	echo -ne "${RED}The rootCA env '${OUT_DIR}/${ROOT_CA}.crt' already exists. Do you want to continue? [y/N]:${NC} "
	read -r response
    	# 2. Check if the answer is NOT Yes (using regex for y or Y)
    	if [[ ! "$response" =~ ^[yY]$ ]]; then
        	echo -e "\n${CYAN}Exiting...${NC}"
        	exit 1 # Exit with a failure code
    	fi
    fi
    
    if [[ -z "$COUNTRY" ]]; then read -e -i "NL" -p "Enter Country Code (2 letters) [e.g., NL]: " COUNTRY; fi
    if [[ -z "$STATE" ]]; then read -p "Enter State or Province [e.g., New York]: " STATE; fi
    if [[ -z "$CITY" ]]; then read -e -i "Amersfoort" -p "Enter Locality/City [e.g., Amersfoort]: " CITY; fi
    if [[ -z "$ORG" ]]; then read -e -i "Hiddenmaces.nl" -p "Enter Organization Name [e.g., HiddenMaces]: " ORG; fi
    if [[ -z "$ORG_UNIT" ]]; then read -p "Enter Organizational Unit [e.g., IT Dept]: " ORG_UNIT; fi

    if [[ -z "$ROOT_CN" || -z "$COUNTRY" ]]; then
        echo -e "${RED}Error: CommonName and Country are mandatory.${NC}"
        return 1
    fi
}

# --- Extension File Generator ---
create_ext_file() {

    EXT_FILE="${OUT_DIR}/${FQDN}.v3.ext"
    
    # Create a config file specifically for the v3 extensions
    # This adds the SAN (Subject Alternative Name) required by Chrome/Edge
    cat > "$EXT_FILE" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${FQDN}
# You can add more DNS.2, IP.1 here if needed manually later
EOF

echo -e "\n${YELLOW}You can now change the extensions for the certificate${NC}"
#echo -e "\n${YELLOW}Just hit :wq or (ESC)ZZ to stop... ${NC}"
read CRLF
# possibility to add items to the extension file
vi ${EXT_FILE}

}

# --- Main Creation Function ---
create_csr() {
    get_details
    if [ $? -ne 0 ]; then return; fi

    KEY_FILE="${OUT_DIR}/${FQDN}.key"
    CSR_FILE="${OUT_DIR}/${FQDN}.csr"
    # Create the extension file needed for the signing step
    echo -e "\n${YELLOW}Generating Extension File...${NC}"
    create_ext_file
    
    echo -e "\n${YELLOW}Generating 2048-bit RSA Private Key...${NC}"
    openssl genrsa -out "$KEY_FILE" 2048

    echo -e "${YELLOW}Generating CSR...${NC}"
    SUBJECT="/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${ORG_UNIT}/CN=${FQDN}"
    openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -subj "$SUBJECT"

    

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Success!${NC}"
        echo -e "Key: ${KEY_FILE}"
        echo -e "CSR: ${CSR_FILE}"
        echo -e "Ext: ${OUT_DIR}/${FQDN}.v3.ext (Required for signing)"
        show_exec_sign_cmd
    else
        echo -e "${RED}OpenSSL Error.${NC}"
    fi
    FQDN="" 
}

# --- Signing Command Display ---
show_exec_sign_cmd() {
    if [[ -z "$FQDN" ]]; then
	echo -ne "${CYAN}Enter the FQDN to generate certificate for: ${NC}" 
        read -r FQDN
    fi

    echo -e "\n${CYAN}--- Command to Sign with Internal Root CA ---${NC}"
    echo ""
    echo -e "${RED}--- Choose N and then option -3- to use the Self-Sign command ---${NC}"
    # Added -extfile to include the SAN and KeyUsage requirements
    SIGN_CMD="openssl x509 -req -in ${OUT_DIR}/${FQDN}.csr -CA ${ROOT_CA}/${ROOT_CA}.crt -CAkey ${ROOT_CA}/${ROOT_CA}.key -CAcreateserial -out ${OUT_DIR}/${FQDN}.crt -days 365 -sha256 -extfile ${OUT_DIR}/${FQDN}.v3.ext"
    echo -e "\n${YELLOW}${SIGN_CMD}${NC}"
    echo ""
    echo -ne "${RED}Run the command (y/N):${NC} "
    read -r ans
    echo "" 

    if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
    	echo -e "\n${CYAN}Running command...${NC}"
	${SIGN_CMD}
	if [ $? -eq 0 ]; then
		echo -e "\n${GREEN}${OUT_DIR}/${FQDN}.crt succesfully created${NC}"
	else
		echo -e "\n${RED}Something went, see errors above.${NC}"
	fi
    fi
    echo -e "${CYAN}---------------------------------------------${NC}"
}

show_exec_self_sign_cmd() {
    if [[ -z "$FQDN" ]]; then
	echo -ne "${CYAN}Enter the FQDN to generate certificate for: ${NC}" 
        read -r FQDN
    fi

    echo -e "\n${RED}--- Command to Self-Sign with Private key ---${NC}"
    echo ""
    # Added -extfile to include the SAN and KeyUsage requirements
    SIGN_CMD="openssl x509 -req -in ${CSR_FILE} -signkey ${KEY_FILE} -out ${OUT_DIR}/${FQDN}.crt -days 365 -sha256 -extfile ${OUT_DIR}/${FQDN}.v3.ext"
    echo -e "\n${YELLOW}${SIGN_CMD}${NC}"
    echo ""
    echo -ne "${RED}Run the command (y/N):${NC} "
    read -r ans
    echo "" 

    if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
    	echo -e "\n${CYAN}Running command...${NC}"
	${SIGN_CMD}
	if [ $? -eq 0 ]; then
		echo -e "\n${GREEN}${OUT_DIR}/${FQDN}.crt succesfully created${NC}"
	else
		echo -e "\n${RED}Something went, see errors above.${NC}"
	fi
    fi
    echo -e "${CYAN}---------------------------------------------${NC}"
}

create_pempf12() {
 
    if [[ -z "$FQDN" ]]; then
	echo -ne "${CYAN}Enter the FQDN to generate the .pem and pf12 files: ${NC}" 
        read -r FQDN
    fi
    OUT_DIR="./certs"
    KEY_FILE="${OUT_DIR}/${FQDN}/${FQDN}.key"
    CRT_FILE="${OUT_DIR}/${FQDN}/${FQDN}.crt"
    
    PEM_CMD="cat ${KEY_FILE} ${CRT_FILE} > ${OUT_DIR}/${FQDN}.pem"
    PF12_CMD="openssl pkcs12 -export -inkey ${KEY_FILE} -in ${CRT_FILE} -out ${OUT_DIR}/${FQDN}/${FQDN}.p12"

    echo -e "\n${YELLOW}--- Commands to create .pem and .p12 files ---${NC}"
    echo ""
    echo -e "\n${CYAN}${PEM_CMD}"
    echo -e "\n${CYAN}${PF12_CMD}"
    echo -ne "${RED}Run the commands (y/N):${NC} "
    read -r ans
    echo "" 

    if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
    	echo -e "\n${CYAN}Running command...${NC}"
    	cat ${KEY_FILE} ${CRT_FILE} > ${OUT_DIR}/${FQDN}/${FQDN}.pem
	if [ $? -eq 0 ]; then
		echo -e "\n${GREEN}${FQDN}.pem succesfully created${NC}"
	else
		echo -e "\n${RED}Something went, see errors above.${NC}"
	fi
	echo -e "\n${RED}Type in 2x the export password${NC}\n"
	${PF12_CMD}
	if [ $? -eq 0 ]; then
		echo -e "\n${GREEN}${FQDN}.p12 succesfully created${NC}"
	else
		echo -e "\n${RED}Something went, see errors above.${NC}"
	fi
    fi
    echo -e "${CYAN}---------------------------------------------${NC}"
}

create_rootca() {

    get_root_details

    if [[ ! -f "${ROOT_DIR}/${ROOT_CA}.crt" || ! -f "${ROOT_DIR}/${ROOT_CA}.key" ]]; then
        echo -e "\n${YELLOW}Creating Root CA...${NC}"
    
        # Generate Root CA Key
        openssl genrsa -out ${ROOT_DIR}/${ROOT_CA}.key 4096

        # Generate Root CA Certificate
        openssl req -x509 -new -nodes -key ${ROOT_DIR}/${ROOT_CA}.key -sha256 -days 1024 -out ${ROOT_DIR}/${ROOT_CA}.crt -subj "/C=${COUNTRY}/L=${CITY}/O=${ORG}/OU=${ORG_UNIT}/CN=${ROOT_CN}"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Root CA created successfully!${NC}"
            echo -e "Certificate: ${ROOT_DIR}/${ROOT_CA}.crt"
            echo -e "Key: ${ROOT_DIR}/${ROOT_CA}.key"
        else
            echo -e "${RED}Failed to create Root CA.${NC}"
        fi
    else
        echo -e "${YELLOW}Root CA already exists. Skipping creation.${NC}"
    fi
}

list_certificates() {
    
    #  Enable nullglob (handles case where directory is empty)
    shopt -s nullglob
    # Load full paths (e.g., "./certs/file1") into an array
    full_paths=("$CERT_DIR"/*)
    shopt -u nullglob

    if [ ${#full_paths[@]} -eq 0 ]; then
        echo -e "${RED}No files found in $CERT_DIR${NC}"
        exit 1
    fi

    echo -e "${CYAN}Found ${#full_paths[@]} files in '$CERT_DIR':${NC}"

    # Create a SECOND array containing only filenames (strips the path)
    # The syntax "${array[@]##*/}" removes everything up to the last '/' for every item.
    filenames=("${full_paths[@]##*/}")

    # Display the instruction text before the list
    echo "Available Certificates (Enter 0 to Go Back):"
    PS3="Select a cert number: "
    select file in "${filenames[@]}"; do
        # Check if the user entered 0
        if [[ "$REPLY" == "0" ]]; then
            echo "Going back..."
            FQDN="" # Optional: Ensure the variable is empty if they go back
            break
        fi
        # Standard check for valid selection
        if [[ -n "$file" ]]; then
            # Store the clean filename in the variable
            FQDN="$file"
            echo -e "${CYAN}--------------------------------${NC}"
            echo -e "$FQDN selected\n"
            OUT_DIR="${CERT_DIR}/${FQDN}"
            break
        else
            echo -e "${RED}Invalid selection. Try again.${NC}"
        fi
    done

    echo -e "${CYAN}--------------------------------${NC}"
    echo -e "No certificate selected\nChoose -3- to create a certificate"
}

# --- Menu ---
while true; do
    echo -e "\n${CYAN}PKI Management Menu${NC}"
    echo -e "${CYAN}-------------------${NC}"

    echo -e "First choose -1- to create the necessary files (csr and key)"
    echo -e "Then choose -2- or -3- to sign the certificate request\n"
    echo -e "${CYAN}----------------------------------------------${NC}"
    echo -e "${RED}1. Create rootCA (if not exists) just once${NC}"
    echo -e "${CYAN}----------------------------------------------${NC}"
    echo -e "2. List all certificates"
    echo -e "3. Create RSA Key, CSR & V3 Ext File"
    echo -e "4. Show (and execute) Root CA Signing Command"
    echo -e "5. Show (and execute) a Self-Signed Signing Command"
    echo -e "6. Create a pem and pf12 file"
    echo -e "${CYAN}----------------------------------------------${NC}"
    echo -e "9. Exit\n"
    
    echo -ne "${CYAN}Select an option: ${NC}"
    read -r choice

    case $choice in
        1) create_rootca ;;
        2) list_certificates ;;
        3) create_csr ;;
        4) show_exec_sign_cmd ;;
        5) show_exec_self_sign_cmd ;;
        6) create_pempf12 ;;
        9) exit 0 ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
done

