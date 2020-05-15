import os
import requests

from flask import Flask, session, render_template, flash, redirect, url_for, request, session
from flask_session import Session
from functools import wraps
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

# Config
app = Flask(__name__)
KEY = "tiLqLcHydCeDdGYnDQN3ig"
app.secret_key = b'="O??U:-??0u?S'

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

def error(message="Sorry", code=400):
    return render_template("error.html", code=code, text=escape(message)), code


def escape(s):
    """
    Escape special characters.
 
    https://github.com/jacebrowning/memegen#special-characters
    """
    for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
        ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
        s = s.replace(old, new)
    return s


def login_required(f):
    # as presented on http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@app.route("/index")
@login_required
def index():
    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": KEY, "isbns": "9781632168146"}).json()
    user = {"username": "Marcus"}
    content = "Project 1: TODO"
    return render_template("index.html", user=user, content=content, res=res) 


@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    # POST request (form submit)
    if request.method == "POST":

        # check if username
        if not request.form.get("username"):
            return error("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return error("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username" :request.form.get("username")}).fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password_hash"], request.form.get("password")):
            return error("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        flash("Successfully logged in!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    
    # Forget any user_id
    session.clear()

    # POST method
    if request.method == "POST":

        # check if username
        if not request.form.get("username"):
            return error("must provide username", 403)

        # check if password
        elif not request.form.get("password"):
            return error("must provide password", 403)

        # check if 2nd password
        elif not request.form.get("password-2"):
            return error("must confirm password", 403)

        # assign variables
        username = request.form.get("username")
        pw = request.form.get("password")
        pw2 = request.form.get("password-2")

        # check if passwords equal
        if pw != pw2:
            return error("password does not equal confirm password", 403)

        hashed = generate_password_hash(pw)

        db.execute("INSERT INTO users (username, password_hash) VALUES (:username, :hashed);", {"username": username, "hashed": hashed})
        db.commit()
        flash("Register succesful!")

        return redirect("/login")

    # GET method
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():

    # Forget any user_id
    session.clear()

    # Redirect to login
    flash("Successfully logged out.")
    return redirect("/login")