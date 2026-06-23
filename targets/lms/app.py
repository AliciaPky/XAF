"""
XAF — Deliberately Vulnerable LMS (test target)
================================================
A minimal Learning Management System used as the WAF test target.

!!! INTENTIONALLY VULNERABLE TO SQL INJECTION !!!
This app exists ONLY to evaluate the XAF adaptive WAF. Do NOT deploy it on a
public network without the WAF in front and inbound restricted to your own IP.

Primary SQLi sink: the login authentication function (Objective 1 of the FYP).
A secondary sink lives in the course search box.
"""
import os
import time

import pymysql
from flask import (
    Flask,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "fyp-xaf-demo-not-secret"

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", "rootpass"),
    "database": os.environ.get("DB_NAME", "lms"),
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True,
}


def get_db():
    """Open a fresh connection. MySQL may not be ready at boot, so retry."""
    last_err = None
    for _ in range(30):
        try:
            return pymysql.connect(**DB_CONFIG)
        except pymysql.err.OperationalError as exc:  # DB still starting
            last_err = exc
            time.sleep(2)
    raise last_err


# --------------------------------------------------------------------------- #
# Templates (kept inline to keep the target self-contained)
# --------------------------------------------------------------------------- #
PAGE = """
<!doctype html>
<title>APU LearnHub</title>
<style>
  body{font-family:system-ui,Arial,sans-serif;max-width:760px;margin:40px auto;color:#1d2433}
  header{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #2557d6;padding-bottom:8px}
  h1{color:#2557d6;margin:0;font-size:22px}
  input,button{padding:8px;font-size:14px;margin:4px 0}
  button{background:#2557d6;color:#fff;border:0;border-radius:4px;cursor:pointer}
  table{border-collapse:collapse;width:100%;margin-top:12px}
  th,td{border:1px solid #d6dae3;padding:8px;text-align:left}
  th{background:#eef2fb}
  .card{border:1px solid #d6dae3;border-radius:8px;padding:20px;margin-top:16px}
  .err{color:#c0392b}
</style>
<header>
  <h1>📚 APU LearnHub <small style="color:#888;font-weight:400">(LMS)</small></h1>
  <div>{% if user %}{{ user }} · <a href="{{ url_for('logout') }}">Logout</a>{% endif %}</div>
</header>
{{ body|safe }}
"""

LOGIN_BODY = """
<div class="card">
  <h2>Sign in</h2>
  {% if error %}<p class="err">{{ error }}</p>{% endif %}
  <form method="post" action="{{ url_for('login') }}">
    <input name="username" placeholder="Username" autocomplete="off"><br>
    <input name="password" type="password" placeholder="Password"><br>
    <button type="submit">Login</button>
  </form>
  <p style="color:#888;font-size:13px">Try: <code>student1 / pass123</code></p>
</div>
"""

DASH_BODY = """
<div class="card">
  <h2>Welcome, {{ fullname }}</h2>
  <p>Role: {{ role }}</p>
  <h3>Your grades</h3>
  <table>
    <tr><th>Course</th><th>Code</th><th>Grade</th></tr>
    {% for g in grades %}
    <tr><td>{{ g.title }}</td><td>{{ g.code }}</td><td>{{ g.grade }}</td></tr>
    {% endfor %}
  </table>
</div>
<div class="card">
  <h3>Course catalogue</h3>
  <form method="get" action="{{ url_for('courses') }}">
    <input name="q" placeholder="Search courses" value="{{ q }}">
    <button type="submit">Search</button>
  </form>
  <table>
    <tr><th>Code</th><th>Title</th><th>Instructor</th></tr>
    {% for c in catalogue %}
    <tr><td>{{ c.code }}</td><td>{{ c.title }}</td><td>{{ c.instructor }}</td></tr>
    {% endfor %}
  </table>
</div>
"""


def render(body, **ctx):
    inner = render_template_string(body, **ctx)
    return render_template_string(PAGE, body=inner, user=session.get("username"), **ctx)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # !!! VULNERABLE: user input concatenated straight into SQL.
        # This is the primary SQL injection sink the WAF must protect.
        query = (
            "SELECT id, username, full_name, role FROM users "
            "WHERE username = '%s' AND password = '%s'" % (username, password)
        )
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()
        except Exception as exc:  # surface SQL errors (error-based SQLi)
            return render(LOGIN_BODY, error="DB error: %s" % exc)
        finally:
            conn.close()

        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["full_name"] = row["full_name"]
            session["role"] = row["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render(LOGIN_BODY, error=error)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT c.title, c.code, e.grade FROM enrollments e "
                "JOIN courses c ON c.id = e.course_id WHERE e.student_id = %s",
                (session["user_id"],),
            )
            grades = cur.fetchall()
            cur.execute("SELECT code, title, instructor FROM courses")
            catalogue = cur.fetchall()
    finally:
        conn.close()
    return render(
        DASH_BODY,
        fullname=session["full_name"],
        role=session["role"],
        grades=grades,
        catalogue=catalogue,
        q="",
    )


@app.route("/courses")
def courses():
    if "username" not in session:
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT c.title, c.code, e.grade FROM enrollments e "
                "JOIN courses c ON c.id = e.course_id WHERE e.student_id = %s",
                (session["user_id"],),
            )
            grades = cur.fetchall()
            # !!! VULNERABLE: secondary SQLi sink in the search filter.
            cur.execute(
                "SELECT code, title, instructor FROM courses "
                "WHERE title LIKE '%%%s%%'" % q
            )
            catalogue = cur.fetchall()
    except Exception as exc:
        catalogue = []
        grades = []
        return render(
            DASH_BODY,
            fullname=session.get("full_name", ""),
            role=session.get("role", ""),
            grades=grades,
            catalogue=[{"code": "ERROR", "title": str(exc), "instructor": ""}],
            q=q,
        )
    finally:
        conn.close()
    return render(
        DASH_BODY,
        fullname=session["full_name"],
        role=session["role"],
        grades=grades,
        catalogue=catalogue,
        q=q,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
