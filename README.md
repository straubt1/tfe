# tfe
Helper for TFE status/debugging.


## How to Use


```sh
# Copy script to a TFE instance:
curl -o tfe.sh https://

# Source functions
. tfe.sh

# Run functions
validate_replicated_conf_file
validate_postgres
validate_s3
validate_tls
```