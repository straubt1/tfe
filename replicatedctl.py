import subprocess
import json

# TODO: look up path to replicatedctl?


class ReplicatedCtl(object):
    settings = {}
    replicatedSettings = {}

    def __init__(self):
        # Get TFE Application Settings
        out = subprocess.Popen(['/usr/local/bin/replicatedctl', 'app-config', 'export'],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()
        self.settings = json.loads(stdout)

        # Get Replicated Settings
        out = subprocess.Popen(['/usr/local/bin/replicatedctl', 'params', 'export'],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()
        self.replicatedSettings = json.loads(stdout)

    # Get all settings

    def getSettings(self):
        return self.settings

    def getReplicatedSettings(self):
        return self.replicatedSettings

    def getObjectStorageSettings(self):
        rtn_settings = {}

        rtn_settings['production_type'] = self.settings.get('production_type').get('value', '')
        rtn_settings['placement'] = self.settings.get('placement').get('value', '')
        rtn_settings['s3_bucket'] = self.settings.get('s3_bucket').get('value', '')
        rtn_settings['s3_endpoint'] = self.settings.get('s3_endpoint').get('value', '')
        rtn_settings['s3_region'] = self.settings.get('s3_region').get('value', '')
        rtn_settings['s3_sse'] = self.settings.get('s3_sse').get('value', '')
        rtn_settings['s3_sse_kms_key_id'] = self.settings.get('s3_sse_kms_key_id').get('value', '')
        rtn_settings['aws_instance_profile'] = self.settings.get('aws_instance_profile').get('value', '')
        rtn_settings['aws_access_key_id'] = self.settings.get('aws_access_key_id').get('value', '')
        rtn_settings['aws_secret_access_key'] = self.settings.get('aws_secret_access_key').get('value', '')

        rtn_settings['gcs_bucket'] = self.settings.get('gcs_bucket').get('value', '')
        rtn_settings['gcs_credentials'] = self.settings.get('gcs_credentials').get('value', '')
        rtn_settings['gcs_project'] = self.settings.get('gcs_project').get('value', '')

        rtn_settings['azure_endpoint'] = self.settings.get('azure_endpoint').get('value', '')
        rtn_settings['azure_account_name'] = self.settings.get('azure_account_name').get('value', '')
        rtn_settings['azure_container'] = self.settings.get('azure_container').get('value', '')
        rtn_settings['azure_account_key'] = self.settings.get('azure_account_key').get('value', '')
        return rtn_settings

    def getDataStorageSettings(self):
        rtn_settings = {}

        rtn_settings['production_type'] = self.settings.get('production_type').get('value', '')
        rtn_settings['pg_netloc'] = self.settings.get('pg_netloc').get('value', '')
        rtn_settings['pg_host'] = self.settings.get('pg_netloc').get('value', '').split(':')[0]
        rtn_settings['pg_port'] = self.settings.get('pg_netloc').get('value', '').split(':')[1]
        rtn_settings['pg_dbname'] = self.settings.get('pg_dbname').get('value', '')
        rtn_settings['pg_user'] = self.settings.get('pg_user').get('value', '')
        rtn_settings['pg_password'] = self.settings.get('pg_password').get('value', '')
        rtn_settings['pg_extra_params'] = self.settings.get('pg_extra_params').get('value', '')
        return rtn_settings
