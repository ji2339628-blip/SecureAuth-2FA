
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import random
import time

app = Flask(__name__)
app.secret_key = "my_2fa_secret_key_123"

users = {}

wrong_attempts = {}
locked_until = {}


@app.route("/")
def home():
    username = session.get("login_username", "")
    remaining = max(
        0,
        int(locked_until.get(username, 0) - time.time() + 0.99)
    )

    return render_template(
        "index.html",
        message="",
        remaining=remaining,
        otp_pending=session.get("otp_pending", False),
        logged_in=session.get("logged_in", False),
        show_signup=False
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template(
            "index.html",
            message="",
            remaining=0,
            otp_pending=False,
            logged_in=False,
            show_signup=True
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not username or not password:
        message = "Please fill in all fields."

    elif len(username) < 3:
        message = "Username must contain at least 3 characters."

    elif len(password) < 8:
        message = "Password must contain at least 8 characters."

    elif password != confirm_password:
        message = "Passwords do not match."

    elif username in users:
        message = "This username is already registered."

    else:
        password_hash = generate_password_hash(password)

        users[username] = [password_hash]
        wrong_attempts[username] = 0
        locked_until[username] = 0

        return render_template(
            "index.html",
            message="Account created successfully! You can now log in.",
            remaining=0,
            otp_pending=False,
            logged_in=False,
            show_signup=False
        )

    return render_template(
        "index.html",
        message=message,
        remaining=0,
        otp_pending=False,
        logged_in=False,
        show_signup=True
    )


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if username not in users:
        return render_template(
            "index.html",
            message="Account not found. Please sign up first.",
            remaining=0,
            otp_pending=False,
            logged_in=False,
            show_signup=False
        )

    remaining = max(
        0,
        int(locked_until.get(username, 0) - time.time() + 0.99)
    )

    if remaining > 0:
        return render_template(
            "index.html",
            message="Your account is temporarily locked.",
            remaining=remaining,
            otp_pending=False,
            logged_in=False,
            show_signup=False
        )

    locked_until[username] = 0

    if check_password_hash(users[username][0], password):
        wrong_attempts[username] = 0

        otp = random.randint(100000, 999999)

        session["login_username"] = username
        session["otp"] = str(otp)
        session["otp_pending"] = True
        session["otp_expiry"] = time.time() + 120

        print("Your OTP is:", otp, flush=True)

        return render_template(
            "index.html",
            message="OTP generated! Check your VS Code terminal.",
            remaining=0,
            otp_pending=True,
            logged_in=False,
            show_signup=False
        )

    wrong_attempts[username] = wrong_attempts.get(username, 0) + 1

    attempts_left = 3 - wrong_attempts[username]

    if wrong_attempts[username] >= 3:
        locked_until[username] = time.time() + 120
        wrong_attempts[username] = 0

        return render_template(
            "index.html",
            message="Too many incorrect attempts. Account locked for 2 minutes.",
            remaining=120,
            otp_pending=False,
            logged_in=False,
            show_signup=False
        )

    return render_template(
        "index.html",
        message=f"Incorrect password. {attempts_left} attempt(s) left.",
        remaining=0,
        otp_pending=False,
        logged_in=False,
        show_signup=False
    )

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    if not session.get("otp_pending"):
        return redirect(url_for("home"))

    entered_otp = request.form.get("otp", "")

    if time.time() > session.get("otp_expiry", 0):
        session.pop("otp", None)
        session.pop("otp_pending", None)
        session.pop("otp_expiry", None)

        return render_template(
            "index.html",
            message="OTP expired. Please log in again.",
            remaining=0,
            otp_pending=False,
            logged_in=False,
            show_signup=False
        )

    if entered_otp == session.get("otp"):
        session.pop("otp", None)
        session.pop("otp_pending", None)
        session.pop("otp_expiry", None)

        session["logged_in"] = True

        return render_template(
            "index.html",
            message="",
            remaining=0,
            otp_pending=False,
            logged_in=True,
            show_signup=False
        )

    return render_template(
        "index.html",
        message="Incorrect OTP. Please try again.",
        remaining=0,
        otp_pending=True,
        logged_in=False,
        show_signup=False
    )


@app.route("/forgot")
def forgot_password():
    return render_template("reset.html", message="")


@app.route("/reset-password", methods=["POST"])
def reset_password():
    username = request.form.get("username", "").strip()
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if username not in users:
        return render_template(
            "reset.html",
            message="Account not found."
        )

    old_password_valid = any(
        check_password_hash(old_hash, old_password)
        for old_hash in users[username]
    )

    if not old_password_valid:
        return render_template(
            "reset.html",
            message="Previous password is incorrect."
        )

    if len(new_password) < 8:
        return render_template(
            "reset.html",
            message="New password must contain at least 8 characters."
        )

    if new_password != confirm_password:
        return render_template(
            "reset.html",
            message="New passwords do not match."
        )

    for old_hash in users[username]:
        if check_password_hash(old_hash, new_password):
            return render_template(
                "reset.html",
                message="You cannot reuse your last 3 passwords."
            )

    new_hash = generate_password_hash(new_password)
    users[username].insert(0, new_hash)

    users[username] = users[username][:3]

    return render_template(
        "reset.html",
        message="Password changed successfully! You can now log in."
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)