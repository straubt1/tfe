import click


class ObjectStorage():

    def validate(self):
        click.echo(click.style('Validate Object Storage...', bold=True))

        click.echo(click.style('Read Configuration:', fg='blue'))
        settings = {}
        click.echo(f'   {click.style("s3_bucket", bold=True)}:    {settings.get("s3_bucket")}')
        click.echo(f'   {click.style("s3_endpoint", bold=True)}:  {settings.get("s3_endpoint")}')
        click.echo(f'   {click.style("s3_region", bold=True)}:    {settings.get("s3_region")}')

        click.echo(click.style('Check Permissions:', fg='blue'))
        click.echo(f'   {click.style("Permissions", bold=True)}:    {settings.get("s3_bucket")}')

        click.echo(click.style('Success', fg='green'))
        click.echo(click.style('Warning', fg='yellow'))
        click.echo(click.style('Failure', fg='red'))
