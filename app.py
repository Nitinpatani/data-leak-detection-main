from flask import Flask, render_template, request, redirect, url_for, session, flash
import pandas as pd
import socket
import os
from utils.email_utils import send_alert_email
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)
app.secret_key = 'fadufadvnouefb'  
from itsdangerous import URLSafeSerializer
serializer = URLSafeSerializer(app.secret_key)
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'your_email@gmail.com')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', 'your_app_password')

CRED_PATH = os.path.join('data', 'user_credential.csv')
USER_DB_PATH = os.path.join('data', 'user_db.csv')

def get_client_ip():
    # Get the real client IP if behind proxy, else fallback
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.remote_addr
    return ip

def load_credentials():
    return pd.read_csv(CRED_PATH)

def load_user_db():
    return pd.read_csv(USER_DB_PATH)

def save_user_db(df):
    df.to_csv(USER_DB_PATH, index=False)

def save_credentials(df):
    df.to_csv(CRED_PATH, index=False)

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        ip = get_client_ip()

        creds = load_credentials()
        user_db = load_user_db()

        user_cred = creds[(creds['username'] == username) & (creds['password'] == password)]
        if not user_cred.empty:
            user_info = user_db[user_db['username'] == username]
            if not user_info.empty:
                expected_ip = user_info.iloc[0]['ip']
                email = user_info.iloc[0]['email']
                if ip == expected_ip:
                    session['username'] = username
                    flash('Login successful!', 'success')
                    return render_template('welcome.html', username=username)
                else:
                    token = serializer.dumps({'username': username, 'ip': ip})
                    subject = "Alert: Unrecognized Login Attempt"
                    confirm_url = url_for('confirm_ip', token=token, _external=True)
                    message = (
                        f"Dear {username},\n\n"
                        f"A login attempt was made from an unrecognized IP address: {ip}.\n"
                        f"If this was you, click the link below to confirm and update your records:\n"
                        f"{confirm_url}\n\n"
                        f"If this wasn't you, please secure your account."
)
                    send_alert_email(email, subject, message, SENDER_EMAIL, SENDER_PASSWORD)
            else:
                error = "User not found in user database."
        else:
            error = "Invalid username or password."
    return render_template('login.html', error=error)

@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('welcome.html', username=session['username'])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        ip = get_client_ip()

        creds = load_credentials()
        user_db = load_user_db()

        if username in creds['username'].values:
            error = "Username already exists."
        elif email in user_db['email'].values:
            error = "Email already registered."
        else:
            new_cred = pd.DataFrame([{'username': username, 'password': password}])
            creds = pd.concat([creds, new_cred], ignore_index=True)
            save_credentials(creds)

            new_user = pd.DataFrame([{'username': username, 'email': email, 'ip': ip}])
            user_db = pd.concat([user_db, new_user], ignore_index=True)
            save_user_db(user_db)

            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', error=error)
@app.route('/confirm_ip/<token>')
def confirm_ip(token):
    try:
        data = serializer.loads(token)
        username = data['username']
        ip = data['ip']

        # Update user_db.csv
        user_db = load_user_db()
        user_db.loc[user_db['username'] == username, 'ip'] = ip
        save_user_db(user_db)

        # Optionally, update user_credential.csv or log the event

        flash('Your IP address has been updated successfully!', 'success')
    except Exception as e:
        flash('Invalid or expired confirmation link.', 'error')
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True)