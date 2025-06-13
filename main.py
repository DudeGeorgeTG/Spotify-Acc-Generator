import httpx
import capsolver
import json
import re
import threading
import os
from uuid import uuid4
from random import choice, randint
from time import sleep
from modules.faker import Faker
from modules.mail_service import Mail
from colorama import init, Fore, Back, Style

init(autoreset=True)

capsolver.api_key = input('[x] Input Capsolver Key: ')

THREADS = 10 

os.system("cls" if os.name == "nt" else "clear")

BANNER = f"""
{Fore.CYAN}
   _____             __  __           _______        __ 
  / ___/____  ____  / /_/ /_  ___    / ____(_)____ _/ /_
  \__ \/ __ \/ __ \/ __/ __ \/ _ \  / /_  / / __ `/ __/
 ___/ / /_/ / /_/ / /_/ / / /  __/ / __/ / / /_/ / /_  
/____/ .___/\____/\__/_/ /_/\___(_)_/   /_/\__, /\__/  
    /_/                                    /____/       
{Fore.MAGENTA}Spotify Account Generator{Style.RESET_ALL}
{Fore.YELLOW}By @DudeGeorges{Style.RESET_ALL}
"""

print(BANNER)

def ensure_saved_folder():
    os.makedirs('saved', exist_ok=True)

def load_proxies():
    try:
        with open('data/proxies.txt', 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []

def get_proxy(proxies):
    if not proxies:
        return None
    return choice(proxies)

def get_sitekey_from_challenge(session, challenge_url):
    try:
        r = session.get(challenge_url)
        match = re.search(r'data-sitekey="([a-zA-Z0-9-_]+)"', r.text)
        if match:
            return match.group(1)
        match_json = re.search(r'"siteKey"\s*:\s*"([a-zA-Z0-9-_]+)"', r.text)
        if match_json:
            return match_json.group(1)
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Sitekey not found in challenge page: {challenge_url}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error fetching sitekey from challenge page: {e}")
        return None

def solve_captcha(challenge_url, site_key, proxy=None):
    task_type = "ReCaptchaV2Task" if proxy else "ReCaptchaV2TaskProxyLess"
    task = {
        "type": task_type,
        "websiteURL": challenge_url,
        "websiteKey": site_key
    }
    if proxy and task_type == "ReCaptchaV2Task":
        task["proxy"] = f"http://{proxy}" if not proxy.startswith("http") else proxy
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Solving reCAPTCHA with CapSolver...")
    solution = capsolver.solve(task)
    return solution.get("gRecaptchaResponse") or solution.get("solution")

def bypass_challenge(session, client_token, client_id, session_id, proxy=None):
    while True:
        try:
            payload = {'session_id': session_id}
            headers = {
                'accept': 'application/json',
                'accept-encoding': 'gzip',
                'accept-language': 'en-US',
                'app-platform': 'Android',
                'client-token': client_token,
                'connection': 'Keep-Alive',
                'content-type': 'application/json',
                'host': 'spclient.wg.spotify.com',
                'spotify-app-version': '8.8.56.538',
                'user-agent': 'Spotify/8.8.56.538 Android/28 (SM-S908E)',
                'x-client-id': client_id
            }
            r = session.post('https://spclient.wg.spotify.com/challenge-orchestrator/v1/get-session', headers=headers, json=payload)
            if r.status_code == 200:
                resp_json = r.json()
                in_progress = resp_json.get('in_progress')
                if not in_progress:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No 'in_progress' in challenge response: {resp_json}")
                    break
                challenge_details = in_progress.get('challenge_details', {})
                web_launcher = challenge_details.get('web_challenge_launcher', {})
                challenge_url = web_launcher.get('url')
                if not challenge_url:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No 'url' in challenge_details: {challenge_details}")
                    break
                challenge_id_parts = challenge_url.strip('/').split('/')
                if len(challenge_id_parts) < 2:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Malformed challenge_url: {challenge_url}")
                    break
                challenge_id = challenge_id_parts[-2]
                headers2 = {
                    'authority': 'challenge.spotify.com',
                    'accept': 'application/json',
                    'accept-language': 'en-US,en;q=0.9',
                    'content-type': 'application/json',
                    'origin': 'https://challenge.spotify.com',
                    'referer': str(r.url),
                    'sec-ch-ua': '"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                }
                if challenge_url.endswith('recaptcha'):
                    site_key = get_sitekey_from_challenge(session, challenge_url)
                    if not site_key:
                        break
                    captcha_token = solve_captcha(challenge_url, site_key, proxy)
                    if not captcha_token:
                        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to solve reCAPTCHA with CapSolver.')
                        break
                    payload2 = {
                        'session_id': session_id,
                        'challenge_id': challenge_id,
                        'recaptcha_challenge_v1': {'solve': {'recaptcha_token': captcha_token}}
                    }
                elif challenge_url.endswith('dummy'):
                    payload2 = {
                        'session_id': session_id,
                        'challenge_id': challenge_id,
                        'dummy_challenge_v1': {'noop': {}}
                    }
                else:
                    print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Account creation failed: {r.text}')
                    break
                r2 = session.post('https://challenge.spotify.com/api/v1/invoke-challenge-command', headers=headers2, json=payload2)
                if r2.status_code == 200:
                    r3 = session.post('https://spclient.wg.spotify.com/signup/public/v2/account/complete-creation', headers=headers, json={'session_id': session_id})
                    if r3.status_code == 200 and 'success' in r3.text:
                        return r3.json()['success']
                    else:
                        print(f'{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Failed bypassing challenge. Retrying...')
                else:
                    print(f'{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Error invoking challenge command, retrying...')
                    continue
            else:
                print(f'{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Error bypassing, retrying...')
                continue
        except Exception as e:
            print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error bypassing, retrying... Exception: {e}')
            continue

def save_account(email, password):
    ensure_saved_folder()
    try:
        with open('saved/accounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"{email}:{password}\n")
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {Fore.CYAN}{email}:{password}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not save account: {e}")

def get_client_token(session):
    payload = {
        'client_data': {
            'client_version': '1.2.18.564.g83d531e5',
            'client_id': 'd8a5ed958d274c2e8ee717e6a4b0971d',
            'js_sdk_data': {
                'device_brand': 'unknown',
                'device_model': 'unknown',
                'os': 'windows',
                'os_version': 'NT 10.0',
                'device_id': str(uuid4()),
                'device_type': 'computer'
            }
        }
    }
    headers = {
        'authority': 'clienttoken.spotify.com',
        'accept': 'application/json',
        'content-type': 'application/json'
    }
    r = session.post('https://clienttoken.spotify.com/v1/clienttoken', headers=headers, json=payload)
    if r.status_code == 200:
        return r.json()['granted_token']['token']
    else:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to get Client Token')
        return None


def worker(proxies):
    faker = Faker()
    mail_tm = Mail()
    while True:
        try:
            proxy = get_proxy(proxies)
            proxies_httpx = {'http://': f'http://{proxy}', 'https://': f'http://{proxy}'} if proxy else None
            session = httpx.Client(proxies=proxies_httpx, timeout=30)
            username = faker.getUsername("y")
            mail, mail_token, mail_id = mail_tm.generateMail(proxies=proxies_httpx)
            password = faker.getPassword(12)
            birthday = faker.getBirthday()
            client_token = get_client_token(session)
            client_id = str(uuid4()).replace('-', '')
            payload = {
                'account_details': {
                    'birthdate': birthday,
                    'consent_flags': {'eula_agreed': True, 'send_email': True, 'third_party_email': True},
                    'display_name': username,
                    'email_and_password_identifier': {'email': mail, 'password': password},
                    'gender': randint(1, 2)
                },
                'callback_uri': 'https://auth-callback.spotify.com/r/android/music/signup',
                'client_info': {
                    'api_key': '142b583129b2df829de3656f9eb484e6',
                    'app_version': '8.8.56.538',
                    'capabilities': [1],
                    'installation_id': str(uuid4()),
                    'platform': 'Android-ARM'
                },
                'tracking': {
                    'creation_flow': '',
                    'creation_point': 'client_mobile',
                    'referrer': ''
                }
            }
            headers = {
                'accept': 'application/json',
                'app-platform': 'Android',
                'client-token': client_token,
                'content-type': 'application/json',
                'spotify-app-version': '8.8.56.538',
                'user-agent': 'Spotify/8.8.56.538 Android/28 (SM-S908E)',
                'x-client-id': client_id
            }
            r = session.post('https://spclient.wg.spotify.com/signup/public/v2/account/create', headers=headers, json=payload)
            if r.status_code == 200 and 'success' in r.text:
                print(f"{Fore.GREEN}[ACCOUNT CREATED]{Style.RESET_ALL} {Fore.CYAN}{mail}:{password}{Style.RESET_ALL}")
                login_token = r.json()['success']['login_token']
                save_account(mail, password)
            elif 'challenge' in r.text:
                print(f'{Fore.BLUE}[INFO]{Style.RESET_ALL} Account not created. Bypassing captcha challenge...')
                session_id = r.json()['challenge']['session_id']
                account_data = bypass_challenge(session, client_token, client_id, session_id, proxy)
                if account_data is not None:
                    print(f"{Fore.GREEN}[ACCOUNT CREATED]{Style.RESET_ALL} {Fore.CYAN}{mail}:{password}{Style.RESET_ALL}")
                    login_token = account_data['login_token']
                    save_account(mail, password)
            elif 'VPN' in r.text or 'invalid_country' in r.text:
                print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Bad proxy or location: {proxy}')
                continue
            else:
                print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Account not created.')
        except Exception as e:
            print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Exception: {e}')
            continue

def main():
    ensure_saved_folder()
    proxies = load_proxies()
    
    print(f"{Fore.YELLOW}Starting Spotify Account Generator{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Threads: {THREADS}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Proxies Loaded: {len(proxies)}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Made by @DudeGeorges{Style.RESET_ALL}\n")
    
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(proxies,))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

if __name__ == '__main__':
    main()