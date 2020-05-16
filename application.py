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


@app.route("/", methods=["GET", "POST"])
@app.route("/index", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        q = request.form.get("q")
        return search(q)
    else:
        user = db.execute("SELECT * FROM users WHERE id=:id", {"id": session.get("user_id")}).fetchone()["username"]
        id = session.get("user_id")
        content = "Project 1: TODO"
        return render_template("index.html", user=user, content=content) 


@app.route("/search/<string:q>")
@login_required
def search(q):
    res = db.execute("SELECT * FROM books WHERE LOWER(isbn) LIKE :q OR LOWER(title) LIKE :q OR LOWER(author) LIKE :q", {"q": "%" + q.lower() + "%"}).fetchall()
    if len(res) == 0:
        return error(f"No results for {q}", 400)
    else:
        return render_template("search.html", q=q, res=res)


@app.route("/book/<string:isbn>")
@app.route("/book/<string:isbn>/<string:q>")
@login_required
def book(isbn, q=None):
    details = db.execute("SELECT title, author, year FROM books WHERE LOWER(isbn) = :isbn", {"isbn": isbn.lower()}).fetchone()
    
    if details == None:
        return error(f"No book for ISBN {isbn}", 400)
    reviews = db.execute("SELECT reviews.stars, reviews.text, users.username FROM reviews INNER JOIN users ON reviews.user_id=users.id WHERE LOWER(reviews.isbn) = :isbn", {"isbn": isbn.lower()}).fetchall()
    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": KEY, "isbns": isbn}).json()
    grRev = res["books"][0]

    if db.execute("SELECT isbn, user_id FROM reviews WHERE LOWER(isbn)=:isbn AND user_id=:user_id", {"isbn": isbn.lower(), "user_id": session.get("user_id")}).rowcount != 0:
        hasreviewed = True
    else:
        hasreviewed = False
    return render_template("book.html", isbn=isbn, details=details, reviews=reviews, hasreviewed=hasreviewed, q=q, grRev = grRev)


@app.route("/submitreview", methods=["POST"])
def submitReview():
    isbn = request.form.get("isbn")
    user_id = session.get("user_id")
    stars = request.form.get("stars")
    text = request.form.get("reviewText")
    db.execute("INSERT INTO reviews (isbn, user_id, stars, text) VALUES (:isbn, :user_id, :stars, :text)", {"isbn": isbn, "user_id": user_id, "stars": stars, "text": text})
    db.commit()
    return redirect("/book/" + isbn)


@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    # POST request (form submit)
    if request.method == "POST":

        if not request.form.get("username"):
            return error("must provide username", 403)
        elif not request.form.get("password"):
            return error("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username": request.form.get("username")}).fetchall()

        if len(rows) != 1 or not check_password_hash(rows[0]["password_hash"], request.form.get("password")):
            return error("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        flash("Successfully logged in!")

        return redirect("/")

    # GET request
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    
    session.clear()

    # POST method
    if request.method == "POST":

        if not request.form.get("username"):
            return error("must provide username", 403)

        elif not request.form.get("password"):
            return error("must provide password", 403)

        elif not request.form.get("password-2"):
            return error("must confirm password", 403)

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