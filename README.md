# tfe
Helper for TFE status/debugging.

## new

## How to Use


```sh
# Copy script to a TFE instance:
curl -o tfe.sh https://raw.githubusercontent.com/straubt1/tfe/master/tfe.sh

# Source functions
. tfe.sh

# Run functions
validate_replicated_conf_file
validate_postgres
validate_s3
validate_tls
```
