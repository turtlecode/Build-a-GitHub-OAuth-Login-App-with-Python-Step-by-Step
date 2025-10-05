import os
from flask import Flask, redirect, url_for, session, request, render_template
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2.rfc6749.errors import AccessDeniedError
from dotenv import load_dotenv

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load environment variables
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
AUTHORIZATION_BASE_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
USER_API_URL = 'https://api.github.com/user'


@app.route('/')
def index():
    user = session.get('user')
    return render_template('index.html', user=user)


@app.route('/login')
def login():
    github = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=["read:user", "user:email"])
    authorization_url, state = github.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    github = OAuth2Session(CLIENT_ID, state=session.get('oauth_state'), redirect_uri=REDIRECT_URI)
    try:
        token = github.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )
    except AccessDeniedError:
        return render_template('access_denied.html'), 403

    session['oauth_token'] = token

    # Fetch only username
    user_info = github.get(USER_API_URL).json()
    session['user'] = {
        'username': user_info.get('login', 'User')
    }

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
