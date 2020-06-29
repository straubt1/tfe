
import click
import os
import subprocess
import json
import boto3
import psycopg2
import dns.resolver
import docker
import requests
import time
import ssl
import socket
import OpenSSL
from google.cloud import storage
from google.oauth2 import service_account

from replicatedctl import ReplicatedCtl


@click.group()
@click.version_option(version='%%version%%')
def cli():
    pass


@cli.command()
def validate_all():
    if not verify_replicated(): exit(1)
    p_validatehealthchecks()
    p_validatehostname()
    p_validates3()
    p_validatepostgres()
    p_validatealternativeworkerimage()
    p_validatetls()


@cli.command()
def validate_s3():
    if not verify_replicated(): exit(1)
    p_validates3()


@cli.command()
def validate_postgres():
    if not verify_replicated(): exit(1)
    p_validatepostgres()


@cli.command()
def validate_hostname():
    if not verify_replicated(): exit(1)
    p_validatehostname()


@cli.command()
def validate_wellknown():
    if not verify_replicated(): exit(1)
    p_validatewellknown()


@cli.command()
def validate_alternative_worker_image():
    if not verify_replicated(): exit(1)
    p_validatealternativeworkerimage()


@cli.command()
def validate_tls():
    if not verify_replicated(): exit(1)
    p_validatetls()


@cli.command()
def validate_healthchecks():
    if not verify_replicated(): exit(1)
    p_validatehealthchecks()


def p_validates3():
    click.echo(click.style('Validate Object Storage...', bold=True))
    settings = ReplicatedCtl().getObjectStorageSettings()

    production_type = settings.get("production_type")
    placement = settings.get("placement")

    click.echo(click.style('Read Configuration:', fg='blue'))
    click.echo(f'   {click.style("production_type", bold=True)}:  {production_type}')
    click.echo(f'   {click.style("placement", bold=True)}:        {placement}')

    if production_type != "external":
        click.echo(click.style(f'TFE Production Type is not External Services, it is {production_type}, skipping...', fg='blue'))
        return

    if placement == "placement_gcs":
        click.echo(click.style('GCS Configuration:', fg='blue'))
        click.echo(f'   {click.style("gcs_bucket", bold=True)}:       {settings.get("gcs_bucket")}')
        click.echo(f'   {click.style("gcs_project", bold=True)}:      {settings.get("gcs_project")}')
        click.echo(f'   {click.style("gcs_credentials", bold=True)}:  {settings.get("gcs_credentials")[0:6]}****')
        # TODO: expand out gcs credentials

        # Instantiates a client
        # service_account_info = settings.get("gcs_credentials")
        # # service_account_info = json.load(settings.get("gcs_credentials"))
        # click.echo(service_account_info)
        # credentials = service_account.Credentials.from_service_account_info(service_account_info)

        # # credentials = service_account.Credentials.from_service_account_info(settings.get("gcs_credentials"))
        # click.echo(credentials)

        click.echo(click.style('Google Configuration:', fg='blue'))
        try:
            f = open('cred.json', 'w')
            f.write(settings.get("gcs_credentials"))
            f.close()
            credentials = service_account.Credentials.from_service_account_file('cred.json')

            storage_client = storage.Client(credentials=credentials)

            bucket = storage_client.bucket(settings.get("gcs_bucket"))
            click.echo(f'   {click.style("Id", bold=True)}:             {bucket.id}')
            click.echo(f'   {click.style("Name", bold=True)}:           {bucket.name}')
            # click.echo(f'   {click.style("Storage Class", bold=True)}:  {bucket.storage_class}')
            # click.echo(f'   {click.style("Location", bold=True)}:       {bucket.location}')

            # roles = bucket.acl.user( 'tstraub-tfe-bucket@tom-straub-tfe.iam.gserviceaccount.com').get_roles()
            # print(roles)
            # storage_print_bucket_acl_for_user.print_bucket_acl_for_user(settings.get("gcs_bucket"), 'tstraub-tfe-bucket@tom-straub-tfe.iam.gserviceaccount.com')
            # Reload fetches the current ACL from Cloud Storage.
            # bucket.acl.reload()
            click.echo(click.style('GCS Configuration is Valid!', fg='green'))
        except:
            os.remove('cred.json')  # clean up file

    elif placement == "placement_s3":
        click.echo(click.style('S3 Configuration:', fg='blue'))
        click.echo(f'   {click.style("s3_bucket", bold=True)}:         {settings.get("s3_bucket")}')
        click.echo(f'   {click.style("s3_endpoint", bold=True)}:       {settings.get("s3_endpoint")}')
        click.echo(f'   {click.style("s3_region", bold=True)}:         {settings.get("s3_region")}')
        click.echo(f'   {click.style("s3_sse", bold=True)}:            {settings.get("s3_sse")}')
        click.echo(f'   {click.style("s3_sse_kms_key_id", bold=True)}: {settings.get("s3_sse_kms_key_id")}')

        click.echo(click.style(f'Read S3 Permissions:', fg='blue'))
        s3 = boto3.client('s3')
        result = s3.get_bucket_acl(Bucket=settings.get("s3_bucket"))
        permission = result['Grants'][0]['Permission']
        click.echo(f'   S3 Permissions: {permission}')

        click.echo(click.style(f'Count S3 Objects:', fg='blue'))
        s3 = boto3.resource('s3')
        bucket = s3.Bucket(settings.get("s3_bucket"))
        size = sum(1 for _ in bucket.objects.all())
        click.echo(f'   Object Count: {size}')
        # Printing the objects will trigger a failure
        # Might be a better way to do this
        # for obj in bucket.objects.all():
        # click.echo(obj.key)

        click.echo(click.style('S3 Configuration is Valid!', fg='green'))

    elif placement == "placement_azure":
        click.echo(click.style('SA Configuration:', fg='blue'))
        click.echo(f'   {click.style("azure_endpoint", bold=True)}:      {settings.get("azure_endpoint")}')
        click.echo(f'   {click.style("azure_account_name", bold=True)}:  {settings.get("azure_account_name")}')
        click.echo(f'   {click.style("azure_container", bold=True)}:     {settings.get("azure_container")}')
        click.echo(f'   {click.style("azure_account_key", bold=True)}:   {settings.get("azure_account_key")[0:6]}****')

        click.echo(click.style('SA Configuration is Valid!', fg='green'))

    else:
        click.echo(click.style(f'Enable to determine Object Storage Placement! {placement}', fg='red'))
    click.echo()


def p_validatepostgres():
    click.echo(click.style('Validate Data Storage...', bold=True))
    settings = ReplicatedCtl().getDataStorageSettings()

    production_type = settings.get("production_type")
    if production_type != "external":
        click.echo(click.style(f'TFE Production Type is not External Services, it is {production_type}, skipping...', fg='blue'))
        return

    click.echo(click.style('Configuration:', fg='blue'))
    click.echo(f'   {click.style("pg_netloc", bold=True)}:       {settings.get("pg_netloc")}')
    click.echo(f'   {click.style("pg_host", bold=True)}:         {settings.get("pg_host")}')
    click.echo(f'   {click.style("pg_port", bold=True)}:         {settings.get("pg_port")}')
    click.echo(f'   {click.style("pg_dbname", bold=True)}:       {settings.get("pg_dbname")}')
    click.echo(f'   {click.style("pg_user", bold=True)}:         {settings.get("pg_user")}')
    click.echo(f'   {click.style("pg_password", bold=True)}:     {settings.get("pg_password")[0:6]}****')
    click.echo(f'   {click.style("pg_extra_params", bold=True)}: {settings.get("pg_extra_params")}')

    conn = None
    try:
        # conn = psycopg2.connect(host=settings.get("pg_host"),database=settings.get("pg_dbname"), user=settings.get("pg_user"), password="wrong")
        conn = psycopg2.connect(host=settings.get("pg_host"), database=settings.get(
            "pg_dbname"), user=settings.get("pg_user"), password=settings.get("pg_password"))
        cursor = conn.cursor()
    except (Exception) as error:
        print(error)
        click.echo(click.style('Data Storage is Invalid!', fg='red'))
        return
    finally:
        if conn is not None:
            conn.close()
            click.echo('Database connection closed.')

    click.echo(click.style('Data Storage is Valid!', fg='green'))
    click.echo()


def p_validatehostname():
    click.echo(click.style('Validate Hostname...', bold=True))

    # TODO: check for sudo

    repl = ReplicatedCtl()
    settings = repl.getSettings()
    replicatedSettings = repl.getReplicatedSettings()

    hostname = settings.get('hostname').get('value')
    replicatedHostname = replicatedSettings.get('TLSBootstrapHostname')
    click.echo(click.style('Configuration:', fg='blue'))
    click.echo(f'   {click.style("TFE Hostname", bold=True)}:                {hostname}')
    click.echo(f'   {click.style("Replicated Hostname", bold=True)}:         {replicatedHostname}')

    click.echo(click.style(f'Resolving hostname from TFE instance:', fg='blue'))
    try:
        dns_query = dns.resolver.Resolver()
        resp = dns_query.query(hostname)
        click.echo(resp.rrset)
    except Exception:
        click.echo(click.style(f'Resolving hostname from TFE instance: FAILED', fg='red'))
    click.echo()

    click.echo(click.style(f'Resolving hostname from TFE worker image:', fg='blue'))
    try:
        client = docker.from_env()
        image_name = get_worker_image(client)
        click.echo(f'Worker Image: {image_name}')
        container = client.containers.run(image_name, f'getent hosts {hostname}', remove=True)
        click.echo(container.decode('utf-8'))
        client.close()
    except Exception:
        click.echo(click.style(f'Resolving hostname from TFE worker image: FAILED', fg='red'))
    # click.echo()

    click.echo(click.style('Done!', fg='green'))
    click.echo()


def p_validatewellknown():
    click.echo(click.style('Validate .well-known...', bold=True))

    # TODO: check for sudo

    repl = ReplicatedCtl()
    settings = repl.getSettings()
    replicatedSettings = repl.getReplicatedSettings()

    url = f'https://{settings.get("hostname").get("value")}/.well-known/terraform.json'
    click.echo(click.style('Configuration:', fg='blue'))
    click.echo(f'   {click.style("Endpoint", bold=True)}:  {url}')

    click.echo(click.style(f'Requesting .well-known from TFE instance:', fg='blue'))
    try:
        # ignore cert errors, TLS is checked in another test
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, verify=False)
        if resp.ok:
            click.echo(click.style('Success!', fg='green'))
        else:
            click.echo(click.style(f'[Failed] {resp} {resp.text}', fg='red'))
    except Exception:
        click.echo(click.style(f'[Failed] Requesting .well-known from TFE instance: {resp.text}', fg='red'))
    click.echo()

    click.echo(click.style(f'Requesting .well-known from TFE worker image:', fg='blue'))
    # TODO: Better job of ensuring this container is removed if an error
    try:
        client = docker.from_env()
        image_name = get_worker_image(client)
        click.echo(f'Worker Image: {image_name}')
        # sudo docker run --rm -it hashicorp/build-worker:now /bin/bash -c "curl -k https://<hostname>/.well-known/terraform.json"
        container = client.containers.run(image_name, f'curl -sk {url}', detach=True)
        container.wait()
        response = json.loads(container.logs())

        if "errors" in response:
            click.echo(click.style(f'[Failed] {response}', fg='red'))
        else:
            click.echo(click.style('Success!', fg='green'))

        container.remove()
        client.close()
    except Exception:
        click.echo(click.style(f'[Failed] Requesting .well-known from TFE worker image', fg='red'))
    click.echo()

    click.echo(click.style('Done!', fg='green'))
    click.echo()


def p_validatealternativeworkerimage():
    click.echo(click.style('Validate Alternative Worker Image...', bold=True))

    repl = ReplicatedCtl()
    settings = repl.getSettings()

    tbw_image = settings.get('tbw_image').get('value')
    custom_image_tag = settings.get('custom_image_tag').get('value')

    click.echo(click.style(f'Configuration', fg='blue'))
    click.echo(f'   {click.style("tbw_image", bold=True)}:         {tbw_image}')
    click.echo(f'   {click.style("custom_image_tag", bold=True)}:  {custom_image_tag}')

    # If default image is the type, but the custom image tag is also set, weird?
    if tbw_image == 'default_image' and custom_image_tag is not None:
        click.echo(click.style(f'[Warning] Unusual Worker Image configuration: tbw_image = {tbw_image}, custom_image_tag = {custom_image_tag}', fg='red'))

    if tbw_image == 'default_image':
        default_image_tag = 'hashicorp/build-worker:now'
        click.echo(f'Using the default Worker Image: {default_image_tag}')
        client = docker.from_env()
        image = get_docker_image_by_name(client, default_image_tag)
        click.echo(f'Worker Image Found in local registry: {image.tags} ({image.short_id})')
        client.close()
    elif tbw_image == 'custom_image':
        click.echo(f'Using an Alternative Worker Image: {custom_image_tag}')
        client = docker.from_env()
        image = get_docker_image_by_name(client, custom_image_tag)
        click.echo(f'Worker Image Found in local registry: {image.tags} ({image.short_id})')
        client.close()
    else:
        click.echo(click.style(f'[Failed] Using an Unknown Worker Image configuration: tbw_image = {tbw_image}', fg='red'))
        print()
        return

    click.echo(click.style('Done!', fg='green'))
    click.echo()


def p_validatetls():
    click.echo(click.style('Validate TLS...', bold=True))

    repl = ReplicatedCtl()
    settings = repl.getSettings()
    hostname = settings.get('hostname').get('value')
    url = f'https://{hostname}/_health_check'

    click.echo(click.style('Configuration:', fg='blue'))
    click.echo(f'   {click.style("TFE Hostname", bold=True)}:  {hostname}')

    click.echo(click.style(f'Requesting Certificate Information:', fg='blue'))
    try:
        cert = ssl.get_server_certificate((hostname, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        sans = {}
        for i in range(0, x509.get_extension_count()):
            ext = x509.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                sans = ext.__str__()

        click.echo(click.style('Certificate Information:', fg='yellow'))
        click.echo(f'   {click.style("commonName", bold=True)}:  {x509.get_subject().commonName}')
        click.echo(f'   {click.style("issuer", bold=True)}:      {x509.get_issuer().organizationName}, {x509.get_issuer().commonName}')
        click.echo(f'   {click.style("notBefore", bold=True)}:   {x509.get_notBefore().decode("utf-8")}')
        click.echo(f'   {click.style("notAfter", bold=True)}:    {x509.get_notAfter().decode("utf-8")}')
        click.echo(f'   {click.style("sans", bold=True)}:        {sans}')
    except Exception as e:
        click.echo(click.style(f'[Failed] Requesting Certificate Information: {e}', fg='red'))
    click.echo()

    click.echo(click.style(f'Requesting Certificate from TFE instance:', fg='blue'))
    try:
        requests.get(url, verify=True)
        click.echo(click.style('Success!', fg='green'))
    except requests.exceptions.SSLError as e:
        click.echo(click.style(f'[Failed] Requesting Certificate from TFE instance: {e}', fg='red'))
    click.echo()

    click.echo(click.style(f'Requesting Certificate from TFE worker image:', fg='blue'))
    try:
        client = docker.from_env()
        image_name = get_worker_image(client)
        click.echo(f'Worker Image: {image_name}')
        container = client.containers.run(image_name, f'curl {url}', detach=True)
        container.wait()
        response = container.logs().decode("utf-8")
        if '--insecure' in response:
            click.echo(click.style(f'[Failed] {response}', fg='red'))
        else:
            click.echo(click.style('Success!', fg='green'))

        container.remove()
        client.close()
    except Exception as e:
        click.echo(click.style(f'[Failed] Requesting Certificate from TFE worker image: {e}', fg='red'))
    click.echo(click.style('Done!', fg='green'))
    click.echo()


def p_validatehealthchecks():
    click.echo(click.style('Validate Health Checks...', bold=True))

    repl = ReplicatedCtl()
    settings = repl.getSettings()
    replicatedSettings = repl.getReplicatedSettings()

    url = 'https://localhost:8800/ping'
    click.echo(click.style(f'Requesting Admin Console Health Check: {url}', fg='blue'))
    try:
        # TODO: read admin console port
        # print(replicatedSettings) #.get('TLSBootstrapHostname')
        # ignore cert errors, TLS is checked in another test
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, verify=False)
        if resp.ok and "All systems go" in resp.text:
            click.echo(click.style('Success!', fg='green'))
        else:
            click.echo(click.style(f'[Failed] {resp} {resp.text}', fg='red'))
    except Exception:
        click.echo(click.style(f'[Failed] Requesting Admin Console Health Check: {resp.text}', fg='red'))
    click.echo()

    url = 'https://localhost/_health_check'
    click.echo(click.style(f'Requesting TFE Health Check: {url}', fg='blue'))
    try:
        # TODO: read admin console port
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, verify=False)
        if resp.ok and "OK" == resp.text:
            click.echo(click.style('Success!', fg='green'))
        else:
            click.echo(click.style(f'[Failed] {resp} {resp.text}', fg='red'))
    except Exception:
        click.echo(click.style(f'[Failed] Requesting TFE Health Check: {resp.text}', fg='red'))
    click.echo()

    url = 'http://localhost:23005'
    click.echo(click.style(f'Requesting Internal TFE Health Check: {url}', fg='blue'))
    try:
        # TODO: read admin console port
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, verify=False)

        # check if all checks are "passed" = true
        checks = resp.json()['checks']
        all_checks_pass = all(value['passed'] for value in checks)
        if resp.ok and all_checks_pass:
            click.echo(click.style('Success!', fg='green'))
        else:
            click.echo(click.style(f'[Failed] {resp} {json.dumps(checks, indent=2)}', fg='red'))
    except Exception:
        click.echo(click.style(f'[Failed] Requesting Internal TFE Health Check: {resp.text}', fg='red'))
    click.echo()

    click.echo(click.style('Done!', fg='green'))
    click.echo()


def verify_replicated():
    try:
        # Determine if replicated is running
        out = subprocess.Popen(['/usr/local/bin/replicatedctl'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()
        if out.returncode != 0:
            click.echo(click.style(f'TFE is not running: {stdout}', fg='red'))
            return False    
        else:
            return True
    except:
        click.echo(click.style("TFE is not running: Failure running `replicatedctl`", fg='red'))
        return False

def get_worker_image(client):
    # Get worker iamge
    image_name = 'hashicorp/build-worker:now'

    images = client.images.list()
    for i in images:
        # print(i.attrs['RepoTags'])
        if image_name in i.attrs['RepoTags']:
            # print(f'Found image {image_name}: {i.attrs["RepoTags"]}')
            break
    return image_name


def get_docker_image_by_name(client, name):

    images = client.images.list()
    image = {}
    for i in images:
        # print(i.attrs['RepoTags'])
        if name in i.attrs['RepoTags']:
            image = i
            break
    return image


if __name__ == '__main__':
    cli()
