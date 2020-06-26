import time

import click

from tfe.objectstorage import ObjectStorage


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Use verbose output.")
@click.version_option()
@click.pass_context
def cli(ctx, verbose):
    click.echo(f"verbose: {verbose}")


@cli.command(help='Validate All')
@click.pass_context
def validate(ctx):
    click.echo('Validate All', nl=False)
    functions = [
        validate_health_checks,
        validate_object_storage,
        validate_data_storage,
    ]

    results = []
    for f in functions:
        results.append(ctx.invoke(f))

    click.echo(results)


@cli.command(help='Validate Health Checks Responses')
def validate_health_checks():
    ObjectStorage().validate()
    # click.echo('Validate health checks')
    # time.sleep(2)
    # return 1


@cli.command(help='Validate Object Storage Connections')
def validate_object_storage():
    click.echo('Validate object storage')
    time.sleep(2)


@cli.command(help='Validate Data Storage Connections')
def validate_data_storage():
    click.echo('Validate data storage')
    time.sleep(2)


# So we can debug
if __name__ == '__main__':
    cli()
