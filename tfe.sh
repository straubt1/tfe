# Adding helper aliases and functions for TFE debugging
alias tfe-logs='journalctl -xu cloud-final -o cat'
alias tfe-logs-follow='journalctl -xu cloud-final -o cat -f'
alias tfe-replicated='replicatedctl system status'
alias tfe-docker-containers="sudo docker ps --format 'table {{.Names}}\t{{.RunningFor}}\t{{.Status}} ago'"
alias tfe-docker-containers-all="sudo docker ps -a --format 'table {{.Names}}\t{{.RunningFor}}\t{{.Status}} ago'"

tfe_log(){
  local level=$1
  local message=$2

  echo "[${level}]  ${message}"
}

check_last_command(){
  local retVal=$1
  local passMessage=$2
  local failMessage=$3

  if [ $retVal -ne 0 ]; then
    tfe_log "FAIL" ${failMessage}
  else
    tfe_log "PASS" ${passMessage}
  fi
}

validate_s3(){

  tfe_log "INFO" "Getting S3 Information from replicatedctl"

  # TODO: Check which placement and update validate to call the proper cloud
  tfe_placement=$(replicatedctl app-config export | jq -r '.placement.value')
  s3_bucket=$(replicatedctl app-config export | jq -r '.s3_bucket.value')
  s3_endpoint=$(replicatedctl app-config export | jq -r '.s3_endpoint.value')
  s3_region=$(replicatedctl app-config export | jq -r '.s3_region.value')
  s3_sse=$(replicatedctl app-config export | jq -r '.s3_sse.value')
  s3_sse_kms_key_id=$(replicatedctl app-config export | jq -r '.s3_sse_kms_key_id.value')

  tfe_log "INFO" "S3 Bucket Configuration:"
  tfe_log "INFO" "  tfe_placement      ${tfe_placement}"
  tfe_log "INFO" "  s3_bucket          ${s3_bucket}"
  tfe_log "INFO" "  s3_endpoint        ${s3_endpoint}"
  tfe_log "INFO" "  s3_region          ${s3_region}"
  tfe_log "INFO" "  s3_sse             ${s3_sse}"
  tfe_log "INFO" "  s3_sse_kms_key_id  ${s3_sse_kms_key_id}"

  tfe_log "INFO" "Validate S3 Connectivity"
  sudo docker run --rm -it hashicorp/build-worker:now /bin/bash -c "aws s3 ls s3://${s3_bucket}"

  retVal=$?
  if [ $retVal -ne 0 ]; then
    tfe_log "FAIL" "Error connecting to s3"
  else
    tfe_log "PASS" "Success"
  fi
}

validate_postgres(){

  tfe_log "INFO" "Getting Postgres Information from replicatedctl"

  pg_netloc=$(replicatedctl app-config export | jq -r '.pg_netloc.value')
  pg_dbname=$(replicatedctl app-config export | jq -r '.pg_dbname.value')
  pg_user=$(replicatedctl app-config export | jq -r '.pg_user.value')
  pg_password=$(replicatedctl app-config export | jq -r '.pg_password.value')
  pg_extra_params=$(replicatedctl app-config export | jq -r '.pg_extra_params.value')
  pg_host=$(echo ${pg_netloc} | cut -d ":" -f 1)
  pg_port=$(echo ${pg_netloc} | cut -d ":" -f 2)

  tfe_log "INFO" "Postgres Configuration:"
  tfe_log "INFO" "  pg_netloc        ${pg_netloc}"
  tfe_log "INFO" "  pg_host          ${pg_host}"
  tfe_log "INFO" "  pg_port          ${pg_port}"
  tfe_log "INFO" "  pg_dbname        ${pg_dbname}"
  tfe_log "INFO" "  pg_user          ${pg_user}"
  tfe_log "INFO" "  pg_password      ${pg_password}"
  tfe_log "INFO" "  pg_extra_params  ${pg_extra_params}"


  tfe_log "INFO" "Lookup local Docker image with psql installed"
  # There are two with the initial grep, pipe to exclude down to the one without "registry"
  psql_image=$(sudo docker image list --format '{{.Repository}}:{{.Tag}}' | grep "hashicorp-ptfe-postgres" | grep -v "registry")
  tfe_log "INFO" "  Image: ${psql_image}"

  tfe_log "INFO" "Validate Postgres Connectivity"
  sudo docker run --rm -it ${psql_image} /bin/bash -c "PGPASSWORD='${pg_password}' psql -h $pg_host -p $pg_port -d ${pg_dbname} -U ${pg_user} -c '\list'"
  # Too much output
  # sudo docker run --rm -it 10.0.4.70:9874/hashicorp-ptfe-postgres:2738c44 /bin/bash -c "PGPASSWORD='${pg_password}' pg_isready -h $pg_host -p $pg_port -d ${pg_dbname} -U ${pg_user} -c 'SELECT * FROM pg_catalog.pg_tables;'"

  retVal=$?
  if [ $retVal -ne 0 ]; then
    tfe_log "FAIL" "Error connecting to postgres"
  else
    tfe_log "PASS" "Success"
  fi
}

validate_tls() {

  tfe_log "INFO" "Getting TFE Information from replicatedctl"

  hostname=$(replicatedctl app-config export | jq -r '.hostname.value')
  well-known-url="https://${hostname}/.well-known/terraform.json"

  tfe_log "INFO" "TFE Configuration:"
  tfe_log "INFO" "  hostname        ${hostname}"
  tfe_log "INFO" "  well-known-url  ${well-known-url}"

  tfe_log "INFO" "curl .well-known endpoint"
  curl -s ${well-known-url} | jq .
  check_last_command $? "Success" "Query failed."

  tfe_log "INFO" "nslookup on hostname"
  nslookup ${hostname}
  check_last_command $? "Success" "Lookup failed."

}

validate_replicated_conf_file() {

  tfe_log "INFO" "Getting Replicated config from /etc/replicated.conf"

  replicated_conf=$(cat /etc/replicated.conf)

  tfe_log "INFO" "Replicated Configuration:"
  echo ${replicated_conf} | jq .

  tfe_log "INFO" "Validating Replicated Configuration"
  ImportSettingsFrom=$(echo ${replicated_conf} | jq -r '.ImportSettingsFrom')
  ls -ll ${ImportSettingsFrom}
  check_last_command $? "ImportSettingsFrom Found at ${ImportSettingsFrom}" "ImportSettingsFrom NOT Found at ${ImportSettingsFrom}"

  LicenseFileLocation=$(echo ${replicated_conf} | jq -r '.LicenseFileLocation')
  ls -ll ${LicenseFileLocation}
  check_last_command $? "LicenseFileLocation Found at ${LicenseFileLocation}" "LicenseFileLocation NOT Found at ${LicenseFileLocation}"

  LicenseBootstrapAirgapPackagePath=$(echo ${replicated_conf} | jq -r '.LicenseBootstrapAirgapPackagePath | select (.!=null)')
  if [ -z "${LicenseBootstrapAirgapPackagePath}" ]
  then
    tfe_log "INFO" "LicenseBootstrapAirgapPackagePath is empty or missing, nothing to see here."
  else
    ls -ll ${LicenseBootstrapAirgapPackagePath}
    check_last_command $? "LicenseBootstrapAirgapPackagePath Found at ${LicenseBootstrapAirgapPackagePath}" "LicenseBootstrapAirgapPackagePath NOT Found at ${LicenseBootstrapAirgapPackagePath}"
  fi

  TlsBootstrapCert=$(echo ${replicated_conf} | jq -r '.TlsBootstrapCert | select (.!=null)')
  if [ -z "${TlsBootstrapCert}" ]
  then
    tfe_log "INFO" "TlsBootstrapCert is empty or missing, nothing to see here."
  else
    ls -ll ${TlsBootstrapCert}
    check_last_command $? "TlsBootstrapCert Found at ${TlsBootstrapCert}" "TlsBootstrapCert NOT Found at ${TlsBootstrapCert}"
  fi

  TlsBootstrapKey=$(echo ${replicated_conf} | jq -r '.TlsBootstrapKey | select (.!=null)')
  if [ -z "${TlsBootstrapKey}" ]
  then
    tfe_log "INFO" "TlsBootstrapKey is empty or missing, nothing to see here."
  else
    ls -ll ${TlsBootstrapKey}
    check_last_command $? "TlsBootstrapKey Found at ${TlsBootstrapKey}" "TlsBootstrapKey NOT Found at ${TlsBootstrapKey}"
  fi
  
  tfe_log "INFO" "Validating Replicated Configuration - Done"

}