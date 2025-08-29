from flask import Flask, render_template, request, redirect, session, flash, url_for, make_response, send_file, g
import pymysql
import pytz
import json
import os
from functools import wraps
from datetime import datetime, timedelta, timezone
from openpyxl import Workbook
import io
import secrets
from flask import after_this_request
from flask import jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv


def get_bool_env(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in {"1", "true", "yes", "on"}


load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(32))
app.permanent_session_lifetime = timedelta(minutes=30)

# Secure session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=get_bool_env("SESSION_COOKIE_SECURE", False),
    SESSION_PERMANENT=False,
)

# Rate limiter (user-friendly messages on limit exceeded)
limiter = Limiter(get_remote_address, app=app, default_limits=[os.getenv("DEFAULT_RATE_LIMIT", "200 per hour")])


@app.before_request
def enforce_idle_timeout():
    ep = (request.endpoint or "")
    PUBLIC_ENDPOINTS = {
        "static", "login", "logout", "home", "select_role",
        "help_center", "view_data", "view_data_menu",
        "view_table", "export_table",
    }
    if ep in PUBLIC_ENDPOINTS or ep.startswith("static"):
        return

    if "username" not in session:
        return

    now = datetime.now(timezone.utc)
    last_seen = session.get("last_seen")

    try:
        if last_seen:
            dt = datetime.fromisoformat(last_seen)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if now - dt > timedelta(minutes=25):
                session.clear()
                return redirect(url_for("login"))
        else:
            session["last_seen"] = now.isoformat()
    except Exception:
        session.clear()
        return redirect(url_for("login"))

    session["last_seen"] = now.isoformat()
    session.modified = True


SESSION_MAX_AGE = timedelta(minutes=25)


def session_expired() -> bool:
    ts = session.get("last_seen")
    if not ts:
        return True
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        return True

    return (datetime.now(timezone.utc) - dt) > SESSION_MAX_AGE


def refresh_last_seen():
    session["last_seen"] = datetime.now(timezone.utc).isoformat()


def get_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "sql12.freesqldatabase.com"),
        user=os.getenv("DB_USER", "sql12796135"),
        password=os.getenv("DB_PASSWORD", "iyIbKmEzHA"),
        database=os.getenv("DB_NAME", "sql12796135"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )


def add_service_engineer(employee_id, username, plain_password):
    conn = None
    cursor = None
    try:
        password_hash = generate_password_hash(plain_password)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO service_engineers (employee_id, username, password_hash, is_active)
            VALUES (%s, %s, %s, %s)
        """, (employee_id, username, password_hash, 1))
        conn.commit()
        print("Engineer added successfully")

    except Exception as e:
        print("Error:", e)
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.before_request
def add_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def inject_csp_nonce():
    return {"csp_nonce": getattr(g, "csp_nonce", "")}


def nocache(view):
    @wraps(view)
    def _no_cache(*args, **kwargs):
        resp = make_response(view(*args, **kwargs))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
    return _no_cache


def one_time_access(name):
    def decorator(view):
        @wraps(view)
        def _wrapped(*args, **kwargs):
            arg_part = ""
            if "method" in kwargs:
                arg_part = f":{kwargs['method']}"
            key = f"_visited_once_{name}{arg_part}"

            if session.get(key):
                flash("This page has expired. Please start again.", "warning")
                return redirect(url_for("home"))

            @after_this_request
            def mark_visited(response):
                session[key] = True
                session.modified = True
                return response

            return view(*args, **kwargs)
        return _wrapped
    return decorator


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if "username" not in session:
            flash("Session expired. Please log in.", "warning")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


@app.errorhandler(405)
def method_not_allowed(e):
    return redirect(url_for("service_module"))


@app.route("/")
@nocache
def home():
    session.pop("view_data_authenticated", None)
    return redirect("/select-role")


@app.route("/help-center")
@nocache
def help_center():
    session.pop("view_data_authenticated", None)
    return render_template("help_center.html")


@app.route("/select-role", methods=["GET", "POST"])
@nocache
def select_role():

    if "username" in session:
        return redirect("/service-module")
        
    session.pop("view_data_authenticated", None)
    if request.method == "POST":
        role = request.form.get("role")
        if role:
            session["role"] = role
            return redirect(url_for("login"))
    return render_template("select_role.html")


@app.route("/view-data", methods=["GET", "POST"])
@login_required
@nocache
def view_data():
    VIEW_DATA_PASSWORD = os.getenv("VIEW_DATA_PASSWORD", "")

    if request.method == "POST":
        password = request.form.get("password", "").strip()
        if not VIEW_DATA_PASSWORD or password != VIEW_DATA_PASSWORD:
            flash("Incorrect password", "danger")
            return redirect("/view-data")

        session["view_data_authenticated"] = True
        return redirect("/view-data-menu")

    return render_template("view_data_password.html")


@app.route("/view-data-menu")
@login_required
@nocache
def view_data_menu():
    if not session.get("view_data_authenticated"):
        flash("Please enter password first", "warning")
        return redirect("/view-data")
    return render_template("view_data_menu.html")


@app.route("/view-table/<table_name>")
@login_required
@nocache
def view_table(table_name):
    if not session.get("view_data_authenticated"):
        flash("Please enter password first", "warning")
        return redirect("/view-data")

    if table_name not in ["firmware_updates", "logs", "errors", "users", "action_taken"]:
        flash("Invalid table name", "danger")
        return redirect("/view-data")

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        data = cursor.fetchall()
    except pymysql.MySQLError as e:
        flash(f"Database Error: {e}", "danger")
        data = []
    finally:
        try:
            if cursor: cursor.close()
        except: pass
        try:
            if conn: conn.close()
        except: pass

    return render_template("view_table.html", table_name=table_name, data=data)


@app.route("/export-table/<table_name>")
@login_required
@nocache
def export_table(table_name):
    if not session.get("view_data_authenticated"):
        flash("Please enter password first", "warning")
        return redirect("/view-data")

    if table_name not in ["firmware_updates", "logs", "errors", "users", "action_taken"]:
        flash("Invalid table name", "danger")
        return redirect("/view-data")

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        data = cursor.fetchall()
    except pymysql.MySQLError as e:
        flash(f"Database Error: {e}", "danger")
        return redirect("/view-table/" + table_name)
    finally:
        try:
            if cursor: cursor.close()
        except: pass
        try:
            if conn: conn.close()
        except: pass

    if not data:
        flash("No data found to export", "warning")
        return redirect("/view-table/" + table_name)

    # Build workbook without pandas for portability
    wb = Workbook()
    ws = wb.active
    ws.title = table_name
    if data:
        # Write header
        headers = list(data[0].keys())
        ws.append(headers)
        # Write rows
        for row in data:
            ws.append([row.get(h) for h in headers])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name=f"{table_name}.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    # Security headers
    csp = " ".join([
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline'",
        f"script-src 'self' 'nonce-{getattr(g, 'csp_nonce', '')}'",
        "object-src 'none'",
        "frame-ancestors 'none'",
    ])
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
    return response


@app.route("/login", methods=["GET", "POST"])
@nocache
@limiter.limit(os.getenv("LOGIN_RATE_LIMIT", "5 per minute"))
def login():
    if "username" in session:
        return redirect("/service-module")

    if request.method == "POST":
        role          = (session.get("role", "Service Engineer") or "").upper()
        charger_model = (request.form.get("charger_model") or "").strip()
        password      = (request.form.get("password") or "").strip()

        if role == "SERVICE ENGINEER":
            identifier = (request.form.get("employee_id") or "").strip()
        elif role == "CUSTOMER":
            identifier = (request.form.get("customer_id") or "").strip()
        else:
            identifier = ""

        if not identifier or not password or not charger_model:
            flash("All fields are required.", "warning")
            return redirect("/login")

        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            if role == "SERVICE ENGINEER":
                cursor.execute(
                    """
                    SELECT username, password_hash, is_active
                    FROM service_engineers
                    WHERE employee_id = %s
                    LIMIT 1
                    """,
                    (identifier,)
                )
                row = cursor.fetchone()
                if not row or not row.get("is_active"):
                    flash("Invalid Employee ID or Password.", "danger")
                    return redirect("/login")
                if not check_password_hash(row["password_hash"], password):
                    flash("Incorrect password.", "danger")
                    return redirect("/login")
                username = row["username"]

            elif role == "CUSTOMER":
                cursor.execute(
                    """
                    SELECT username, password_hash, is_active
                    FROM customers
                    WHERE customer_id = %s
                    LIMIT 1
                    """,
                    (identifier,)
                )
                row = cursor.fetchone()
                if not row or not row.get("is_active"):
                    flash("Invalid Customer ID or inactive account.", "danger")
                    return redirect("/login")

                if not check_password_hash(row["password_hash"], password):
                    flash("Incorrect password. Please try again.", "danger")
                    return redirect("/login")
                username = row["username"]

            else:
                flash("Unknown role.", "danger")
                return redirect("/login")

            india_time  = datetime.now(pytz.timezone("Asia/Kolkata"))
            action_time = india_time.strftime("%H:%M:%S")
            action_date = india_time.strftime("%Y-%m-%d")

            cursor.execute(
                """
                INSERT INTO users (username, employee_id, charger_model, role, action_time, action_date)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (username, identifier, charger_model, role, action_time, action_date)
            )
            conn.commit()

            session["username"]       = username
            session["role"]           = role
            session["charger_model"]  = charger_model
            session["employee_id"]    = identifier
            if role == "CUSTOMER":
                session["customer_id"] = identifier

            if role == "CUSTOMER" and charger_model == "Harmony Upper Pilot":
                session["allowed_errors"] = [
                    "E220: E-LOCK FAIL", "E308: ERROR NOTICED BY EV", "E308-4-4: ERROR", "E308-4-5: ERROR", "E308-5-4: ERROR",
                    "E308-5-5: ERROR", "E211: COMMA WITH EV FAILED", "E212: PLUGGED GUN TIMEOUT",
                    "E311: GUN NOT INSERTED COMPLETELY", "E404: REBOOT", "E405: ID TAG REJECTED BY SERVER"
                ]
            elif role == "SERVICE ENGINEER":
                session["allowed_errors"] = [
                    "E201: PARAM CONFIG FAILED", "E203: ABNORMAL VOLT OUTSIDE BUS", "E205: INSULATION INSPECT ABNORMALLY",
                    "E211: COMMA WITH EV FAILED", "E212: PLUGGED GUN TIMEOUT", "E213: PRE CHARGING FAULT",
                    "E214: DOOR OPEN", "E215: EMERGENCY PRESSED", "E216: SPD FAIL OR WIRING LOSE", "E217: ALL RECTIFIER FAIL",
                    "E220: E-LOCK FAIL", "E221: GUN OVER TEMP", "E225: GROUP RECT COMM FAIL", "E226: GROUP RECTFAIL",
                    "E251: POWER METER FAILURE", "E252: CCU COMM FAIL", "ALARM: INSULATION BOARD COMMUNICATION FAIL",
                    "E308: ERROR NOTICED BY EV", "E308-4-4: ERROR", "E308-4-5: ERROR", "E308-5-4: ERROR",
                    "E308-5-5: ERROR", "E309: PLC LOW LEVEL COMM FAIL", "E310: PLC HIGH LEVEL COMM FAIL",
                    "E311: GUN NOT INSERTED COMPLETELY", "E404: REBOOT", "E405: ID TAG REJECTED BY SERVER", "E514: NO CURRENT INCHARGING",
                    "E901: EV Protocol Error", "E902: EV Sequencer Error on Display", "E913: EV Wrong Charge Parameter", "E919: Wrong Energy Transfer Mode",
                    "E921: EV No Negotiation", "E922: EV Timeout Communication Setup", "E923: EV Timeout Sequence", "E924: EV Timeout Notification Max Delay",
                    "E926: EV Disconnected", "E928: HLC Error", "E954: EV EVERSS Malfunction", "E957: EV Charging System Incompatibility", "E958: EV No Data",
                    "E981: Error at Charging Stage", "E982: Error at Pre charge Stage", "E983: Error at Authenticate stage", "E984: Error at High level comm fail",
                    "E985: Error at Low level comm fail", "E986: Error at Cable check Stage"
                ]
            else:
                session["allowed_errors"] = []

            session.pop("diag_flow_complete", None)
            session.permanent    = True
            session["last_seen"] = datetime.now(timezone.utc).isoformat()

            return redirect("/service-module")

        except pymysql.MySQLError as e:
            flash("Database error: " + str(e), "danger")
            return redirect("/login")

        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    return render_template("login.html", role=session.get("role", "Service Engineer"))


@app.route("/service-module")
@login_required
@nocache
def service_module():

    if "username" not in session:
        return redirect("/login")

    role = session["role"]
    charger_model = session["charger_model"]

    available_services = {
        "Harmony Upper Pilot": [
            "Fault Diagnosis and Troubleshooting",
            "Firmware and Software Management",
            "Diagnostic Log Collection"
        ]
    }

    if role == "CUSTOMER":
        services = ["Fault Diagnosis and Troubleshooting"]
    else:
        services = available_services.get(charger_model, [])

    return render_template(
        "service-module.html",
        username=session["username"],
        role=role,
        charger_model=charger_model,
        services=services
    )

 
@app.route("/fault-diagnosis", methods=["GET", "POST"])
@login_required
@nocache
def fault_diagnosis():

    if session.get("diag_flow_complete"):
        return redirect(url_for("service_module"))

    if "username" not in session:
        return redirect("/login")

    username = session.get("username")
    employee_id = session.get("employee_id")
    charger_model = session.get("charger_model", "Harmony Upper Pilot")
    error_codes = session.get("allowed_errors", [ ])  

    json_path = os.path.join(app.root_path, 'static', 'data', 'harmony_upper_pilot_errors.json')
    with open(json_path) as f:
        troubleshooting_data = json.load(f)

    if request.method == "POST":
        selected_code = request.form.get("error_code", "").strip()
        session["error_code"] = selected_code

        steps = troubleshooting_data.get(selected_code, {}).get("steps", [])
        images = []
        for step in steps:
            if "image" in step:
                images.append(step["image"])
            elif "images" in step:
                images.extend(step["images"])

        return render_template(
            "troubleshoot_guide.html",
            error_code=selected_code,
            images=images,
            steps=steps
        )

    error_codes = list(dict.fromkeys(session.get("allowed_errors", [])))

    return render_template("fault_diagnosis.html", error_codes=error_codes, username=username)


@app.route("/log-back-action", methods=["POST"])
@login_required
@nocache
@one_time_access("log-back-action")
@limiter.limit(os.getenv("WRITE_RATE_LIMIT", "30 per minute"))
def log_back_action():
    if "username" not in session:
        return ("", 204)

    username      = session.get("username")
    employee_id   = session.get("employee_id")
    charger_model = session.get("charger_model", "N/A")
    error_code    = session.get("error_code", "N/A")

    issue_solved     = "NOT_MARKED"
    hardware_changed = "N/A"
    hardware_name    = "N/A"

    india_time  = datetime.now(pytz.timezone("Asia/Kolkata"))
    action_time = india_time.strftime("%H:%M:%S")
    action_date = india_time.strftime("%Y-%m-%d")

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO action_taken (
                username, employee_id, charger_model,
                error_type, issue_solved, hardware_name,
                hardware_changed, action_time, action_date
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                username, employee_id, charger_model,
                error_code, issue_solved, hardware_name,
                hardware_changed, action_time, action_date
            )
        )
        conn.commit()
    except Exception as e:
        print("DB insert error in /log-back-action:", e)
    finally:
        if cursor:
            try: cursor.close()
            except Exception: pass
        if conn:
            try: conn.close()
            except Exception: pass

    return jsonify(status="logged"), 200


@app.route("/submit-resolution", methods=["POST"])
@login_required
@nocache
def submit_resolution():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    employee_id = session["employee_id"]
    charger_model = session.get("charger_model", "Harmony Upper Pilot")
    selected_code = session.get("error_code")
    issue_solved = request.form.get("issue_solved") or "Not Marked"

    session["issue_solved"] = issue_solved

    india_time = datetime.now(pytz.timezone('Asia/Kolkata'))
    action_time = india_time.strftime('%H:%M:%S')
    action_date = india_time.strftime('%Y-%m-%d')

    if issue_solved == "no":
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO errors (
                    username, employee_id, charger_model,
                    error_type, issue_solved, Hardware_changed, hardware_name,
                    action_time, action_date
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                username, employee_id, charger_model,
                selected_code, issue_solved, "N/A", "No",
                action_time, action_date
            ))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        session["diag_flow_complete"] = True
        return redirect("/service-module")
    
    return redirect("/hardware-status")


@app.route("/hardware-status", methods=["GET", "POST"])
@login_required
@nocache
def hardware_status():

    if session.get("diag_flow_complete"):
        return redirect(url_for("service_module"))

    if "username" not in session:
        return redirect("/login")

    role = session.get("role", "SERVICE ENGINEER").upper()

    if role == "CUSTOMER":
        username = session.get("username")
        employee_id = session.get("employee_id")
        charger_model = session.get("charger_model")
        error_code = session.get("error_code")
        issue_solved = session.get("issue_solved")

        india_time = datetime.now(pytz.timezone('Asia/Kolkata'))
        action_time = india_time.strftime('%H:%M:%S')
        action_date = india_time.strftime('%Y-%m-%d')

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO errors (
                    username, employee_id, charger_model,
                    error_type, issue_solved, hardware_name,
                    Hardware_changed, action_time, action_date
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                username, employee_id, charger_model,
                error_code, issue_solved, "N/A",
                "N/A", action_time, action_date
            ))
            conn.commit()
        except pymysql.MySQLError as e:
            flash(f"DB error: {str(e)}", "danger")
        finally:
            if conn:
                conn.close()


        return redirect("/service-module")

    if request.method == "POST":
        username = session.get("username")
        employee_id = session.get("employee_id")
        charger_model = session.get("charger_model")
        error_code = session.get("error_code")
        issue_solved = session.get("issue_solved")

        india_time = datetime.now(pytz.timezone('Asia/Kolkata'))
        action_time = india_time.strftime('%H:%M:%S')
        action_date = india_time.strftime('%Y-%m-%d')

        hardware_changed = request.form.get("hardware_changed", "N/A")
        hardware_name = request.form.get("hardware_name", "N/A")

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO errors (
                    username, employee_id, charger_model,
                    error_type, issue_solved, hardware_name,
                    Hardware_changed, action_time, action_date
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                username, employee_id, charger_model,
                error_code, issue_solved, hardware_name,
                hardware_changed, action_time, action_date
            ))
            conn.commit()
        except pymysql.MySQLError as e:
            flash(f"DB error: {str(e)}", "danger")
        finally:
            if conn:
                conn.close()

        session["diag_flow_complete"] = True
        return redirect("/service-module")

    return render_template("hardware_status.html")


@app.route("/start-service", methods=["GET", "POST"])
@login_required
@nocache
def start_service():
    if request.method == "GET":
        return redirect(url_for("service_module"))

    session.pop("diag_flow_complete", None)

    raw_service = request.form.get("service_name", "")

    def normalize(s: str) -> str:
        s = (s or "").strip().lower()
        s = "".join(ch if (ch.isalnum() or ch.isspace()) else " " for ch in s)
        s = " ".join(s.split())
        return s

    service = normalize(raw_service)

    if "fault" in service or "troubleshoot" in service:
        return redirect(url_for("fault_diagnosis"))

    if "firmware" in service or "software" in service:
        return redirect(url_for("firmware_management"))

    if "log" in service or "diagnostic" in service:
        return render_template("diagnostic_log_collection.html")

    flash(f"Invalid service selected: {raw_service}", "danger")
    return redirect(url_for("service_module"))


# Fixed troubleshoot route and loader
def load_json_data(filepath=None):
    if filepath is None:
        filepath = os.path.join(app.root_path, 'static', 'data', 'harmony_upper_pilot_errors.json')
    with open(filepath, 'r') as f:
        return json.load(f)


@app.route("/troubleshoot/<code>")
@login_required
@nocache
def troubleshoot(code):
    troubleshooting_data = load_json_data()
    node = troubleshooting_data.get(code, {})
    steps = node.get("steps", []) if isinstance(node, dict) else node
    images = []
    for step in steps:
        imgs = step.get("images", []) or step.get("image", "")
        if isinstance(imgs, str):
            images.append(imgs)
        elif isinstance(imgs, list):
            images.extend(imgs)
    return render_template("troubleshoot_guide.html", code=code, images=images, steps=steps)


@app.route("/firmware-management")
@login_required
@nocache
def firmware_management():
    username = session.get("username")
    return render_template("firmware_management.html")


@app.route("/firmware-action", methods=["POST"])
@login_required
@nocache
def firmware_action():
    firmware_type = request.form.get("firmware_type")
    return f"You selected: {firmware_type} (You can redirect or render a page for this type)"


@app.route("/show_firmware/<method>")
@login_required
@nocache
def show_firmware_steps(method):
    if session.get("diag_flow_complete"):
        return redirect(url_for("service_module"))
    images = []

    images_folder = os.path.join(app.static_folder, 'images')
    prefix = f"{method}_step"
    index = 1
    while True:
        image_filename = f"{prefix}{index}.webp"
        image_path = os.path.join(images_folder, image_filename)

        if os.path.exists(image_path):
            images.append(image_filename)
            index += 1
        else:
            break    
    return render_template("firmware_guide.html", method=method, images=images)


@app.route("/firmware/upper-controller-tools")
@login_required
@nocache
def select_upper_controller_tool():
    if session.get("diag_flow_complete"):
        return redirect(url_for("service_module"))

    if "username" not in session:
        return redirect("/login")
    
    return render_template("select_tool.html", username=session["username"])


@app.route("/show_logs/<method>")
@login_required
@nocache
def show_log_steps(method):

    if session.get("diag_flow_complete"):
        return redirect(url_for("service_module"))

    images = []
    images_folder = os.path.join(app.static_folder, "images")
    prefix = f"{method}_step"
    index = 1

    while True:
        image_filename = f"{prefix}{index}.webp"
        image_path = os.path.join(images_folder, image_filename)

        if os.path.exists(image_path):
            images.append(image_filename)
            index += 1
        else:
            break

    return render_template("log_guide.html", method=method, images=images)


@app.route("/submit-log-update", methods=["POST"])
@login_required
@nocache
@limiter.limit(os.getenv("WRITE_RATE_LIMIT", "30 per minute"))
def submit_log_update():
    if "username" not in session:
        return redirect("/login")

    username = session.get("username")
    employee_id = session.get("employee_id")
    charger_model = session.get("charger_model")
    section_selected = request.form.get("section_selected")
    log_collected = request.form.get("log_collected")

    india_time = datetime.now(pytz.timezone('Asia/Kolkata'))
    action_time = india_time.strftime('%H:%M:%S')
    action_date = india_time.strftime('%Y-%m-%d')

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO logs (
                username, employee_id, charger_model,
                section_selected, log_collected,
                action_date, action_time
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            username, employee_id, charger_model,
            section_selected, log_collected,
            action_date, action_time
        ))
        conn.commit()
        flash("Log collected successfully", "success")
    except pymysql.MySQLError as e:
        flash(f"DB error: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    
    session["diag_flow_complete"] = True

    return redirect("/service-module")


@app.route("/submit-firmware-update", methods=["POST"])
@login_required
@nocache
@limiter.limit(os.getenv("WRITE_RATE_LIMIT", "30 per minute"))
def submit_firmware_update():
    if "username" not in session:
        return redirect("/login")

    username = session.get("username")
    employee_id = session.get("employee_id")
    charger_model = session.get("charger_model")
    section_selected = request.form.get("section_selected")
    firmware_update_completed = request.form.get("firmware_complete")

    india_time = datetime.now(pytz.timezone('Asia/Kolkata'))
    action_time = india_time.strftime('%H:%M:%S')
    action_date = india_time.strftime('%Y-%m-%d')

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO firmware_updates (
                username, employee_id, charger_model,
                section_selected, firmware_update_completed,
                action_date, action_time
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            username, employee_id, charger_model,
            section_selected, firmware_update_completed,
            action_date, action_time
        ))
        conn.commit()
        flash("Firmware update status logged successfully", "success")
    except pymysql.MySQLError as e:
        flash(f"DB error: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()

    session["diag_flow_complete"] = True

    return redirect("/service-module")


@app.route("/logout", methods=["GET"])
@nocache
def logout():
    session.clear()
    resp = redirect(url_for("login"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))

