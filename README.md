<h2>Environment configuration</h2>
<p>Create a <code>.env</code> file at the project root with at least:</p>
<pre>
FLASK_SECRET_KEY=change_me
DB_HOST=sql12.freesqldatabase.com
DB_USER=
DB_PASSWORD=
DB_NAME=
SESSION_COOKIE_SECURE=false
VIEW_DATA_PASSWORD=
DEFAULT_RATE_LIMIT=200 per hour
LOGIN_RATE_LIMIT=5 per minute
WRITE_RATE_LIMIT=30 per minute
PORT=5000
</pre>

<h2>Install and run</h2>
<pre>
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
</pre>

<h2>Security notes</h2>
<ul>
  <li>Session cookies are HttpOnly and SameSite=Lax; set <code>SESSION_COOKIE_SECURE=true</code> in production over HTTPS.</li>
  <li>CSP is enabled with per-request nonce. Inline scripts must include the <code>csp_nonce</code> provided to templates.</li>
  <li>Rate limits applied to login and write endpoints; adjust via env.</li>
</ul>
