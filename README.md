# tfe

Utility to validate common Terraform Enterprise Configurations on a running TFE instance.

**Goals**

- Ability to quickly download and run this utility to identify misconfigurations.
- Single binary that runs with a little dependencies as possible


## How to Use

Download and run:

```sh
# Copy the tfe cli
curl -L https://github.com/straubt1/tfe/raw/main/release/tfe -o tfe
chmod +x tfe
sudo ./tfe --help
```

## Checks

The following is a list of the things that we will check.

## All

**Command**: `tfe validate-all` 

Run every validate command below.

### Object Storage Connectivity

**Command**: `tfe validate-s3` 

In External Services mode, verify the instance can communicate with S3/SA/GCS.

- Is in ES mode
- Can connect to Object Storage
- Has proper permissions (write/delete a file?)

### Data Storage Connectivity

**Command**: `tfe validate-postgres` 

In External Services mode, verify the instance can communicate with postgres.

- Is in ES mode
- Can connect to Data Storage
- Has proper permissions, open connection

### Hostname DNS

**Command**: `tfe validate-hostname` 

Verify the TFE App hostname is resolvable from the instance and in the docker worker image.

- [Warning] Can reach hostname via DNS on the instance
- Can reach hostname via DNS within the builder docker container
- [Warning] Same as the Replicated settings

### .well-known 

**Command**: `tfe validate-wellknown`

Verify that the '.well-known/terraform.json' endpoint is accessible from the instance and in the docker worker image.

- [Warning] .well-known responses successfully on the instance
- .well-known responses successfully  within the builder docker container

## Alternative Worker Image

**Command**: `tfe validate-worker-image` 

If using an Alternative Worker Image, image is available in `docker images`.

- Is using Alt worker image
- [Warning] If  `tbw_image` == "default_image" but `custom_image_tag` is set
- Can see the docker image locally

## TLS

**Command**: `tfe validate-tls` 

Verify proper trust is available to the TFE instance from itself.

- [Warning] TLS trust on the instance
- TLS trust in the builder docker container

## Health Checks

**Command**: `tfe validate-healthchecks` 

TFE is serving healthy checks.

- Admin Console is healthy, `https://localhost:8800/ping`
```
All systems go!
```
- TFE is healthy, `https://localhost/_health_check?full`
```
{
  "postgres": "UP",
  "redis": "UP",
  "vault": "UP"
}
```
- Internal health check, `http://localhost:23005`
```
{
  "passed": true,
  "checks": [
    {
      "name": "Archivist Health Check",
      "passed": true
    },
    {
      "name": "Terraform Enterprise Health Check",
      "passed": true
    },
    {
      "name": "Terraform Enterprise Vault Health Check",
      "passed": true
    },
    {
      "name": "RabbitMQ Health Check",
      "passed": true
    },
    {
      "name": "Vault Server Health Check",
      "passed": true
    }
  ]
}
```

## Development

The CLI is built using Python and Click, and is then compiled into a single binary using PyInstaller.

### How to Build

Install Python3 and Virtual Environment:

```sh
brew upgrade python3
pip3 install virtualenv --user   
```

Run the following to start using locally:

```sh
# Create virtual environment
python3 -m venv ./venv

# Activate virtual environment
. venv/bin/activate

# Install pip dependencies
pip install -r requirements.txt 
```

### How to Package

From inside your python virtual environment:

```sh
pyinstaller --onefile tfe.py
```

Test:

```sh
./dist/tfe
```

## References

- [Python 3]()
- [Click](https://click.palletsprojects.com/en/7.x/quickstart/)
- [PyInstaller]()
