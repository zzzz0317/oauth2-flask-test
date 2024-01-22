import base64
import os
import sys
import json

import requests
from flask import Flask, redirect, request, render_template, session

from const import *

if not os.path.exists(CONFIG_FILE_NAME):
    print("Config file", CONFIG_FILE_NAME, "not found!")
    sys.exit(1)

with open(CONFIG_FILE_NAME, "r", encoding="utf-8") as f_config:
    config = json.load(f_config)

app_url = config.get("app_url", None)
app_url_callback = app_url + "/callback"
endpoint = config.get("endpoint", None)
client_id = config.get("client_id", None)
client_secret = config.get("client_secret", None)
dict_key_whitelist = config.get("dict_key_whitelist", [])

well_known_url = endpoint + '/.well-known/openid-configuration'
response = requests.get(well_known_url)
well_known_config = json.loads(response.text)
authorization_endpoint = well_known_config['authorization_endpoint']
token_endpoint = well_known_config['token_endpoint']
userinfo_endpoint = well_known_config['userinfo_endpoint']

app = Flask(__name__)
app.secret_key = config.get("app_secret_key", 'your_secret_key')

state = "qwerasdf"


@app.route('/')
def default_index():
    url = f'{authorization_endpoint}?client_id={client_id}&response_type=code&redirect_uri={app_url_callback}&scope=read&state={state}'
    return redirect(url)


@app.route('/callback')
def callback():
    code = request.args.get("code")
    response = requests.post(token_endpoint, data={
        'code': code,
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': app_url_callback
    })
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data['access_token']
        session['access_token'] = access_token
        return redirect('/info')
    return render_template("error.html", content='Failed to obtain access token')


@app.route('/info_access_token', methods=['GET'])
def info_access_token():
    access_token = session.get('access_token')
    decoded_msg = access_token.split(".")[1]
    decoded_msg = base64.urlsafe_b64decode(decoded_msg + '=' * (-len(decoded_msg) % 4)).decode('utf-8')
    decoded_msg = json.loads(decoded_msg)
    if dict_key_whitelist:
        data = {}
        for k in decoded_msg.keys():
            if k in dict_key_whitelist:
                data[k] = decoded_msg[k]
        return render_template("info.html", my_dict=data)
    return render_template(
        "info.html",
        my_dict=decoded_msg,
        src_value="\n\n".join(access_token.split("."))
    )


@app.route('/info', methods=['GET'])
def info():
    access_token = session.get('access_token')
    if access_token:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(userinfo_endpoint, headers=headers)
        if response.status_code == 200:
            userinfo = response.json()
            if dict_key_whitelist:
                data = {}
                for k in userinfo.keys():
                    if k in dict_key_whitelist:
                        data[k] = userinfo[k]
                return render_template("info.html", my_dict=data)
            return render_template("info.html", my_dict=userinfo)
        else:
            return render_template("error.html", content='Failed to obtain user info')
    return render_template("error.html", content='Access token not found')


if __name__ == '__main__':
    app.run(host=config.get("listen_addr", "127.0.0.1"), port=config.get("listen_port", 8080))
