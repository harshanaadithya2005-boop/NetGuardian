"""Run locally to configure a NetGuardian admin password; never enables router writes."""
from getpass import getpass
from pathlib import Path
import secrets
import shutil
import sys
from datetime import datetime
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dotenv import dotenv_values,set_key
from werkzeug.security import generate_password_hash


def main():
    password=getpass('Choose NetGuardian administrator password (12+ characters): ')
    if len(password)<12 or password!=getpass('Confirm password: '):
        raise SystemExit('Passwords do not match or are too short. No settings changed.')
    path=Path(__file__).resolve().parents[1]/'.env'
    values=dotenv_values(path) if path.exists() else {}
    if path.exists():
        shutil.copyfile(path,path.with_name('.env.before_admin_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f')))
    set_key(path,'NETGUARDIAN_ADMIN_PASSWORD_HASH',generate_password_hash(password))
    if len(values.get('SECRET_KEY') or '')<32:
        set_key(path,'SECRET_KEY',secrets.token_hex(32))
    print('Administrator credentials configured locally. Restart NetGuardian to load them. Router writes were not enabled.')

if __name__=='__main__':main()
