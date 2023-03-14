import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    # get available cash for user
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    if len(cash) != 1:
        return apology("query did not return exactly one user")
    cash = cash[0]['cash']

    # get holdings data
    holdings = db.execute("SELECT * FROM holdings WHERE user_id = ? ORDER BY name", user_id)

    # get current price
    total_holdings = 0
    for holding in holdings:
        symbol = holding["symbol"]
        stockinfo = lookup(symbol)
        holding["price"] = stockinfo["price"]
        total_holdings = total_holdings + (holding["price"] * holding["shares"])

    # TODO: create an index for the database

    return render_template("index.html", cash=cash, holdings=holdings, total_holdings=total_holdings)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # Input validation
        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide a ticker")
        stock = lookup(symbol)
        if not stock:
            return apology("must provide valid ticker")

        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except:
            return apology("must provide number of shares")
        if shares < 1:
            return apology("must provide a positive integer")

        # get available cash for user
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        if len(cash) != 1:
            return apology("query did not return exactly one user")
        cash = cash[0]['cash']

        # check if user can afford
        if (stock['price'] * shares) > cash:
            return apology("insufficient funds")

        # get datetime
        datetime = db.execute("SELECT datetime('now', 'localtime')")
        datetime = datetime[0]["datetime('now', 'localtime')"]

        # commit to transactions
        db.execute("INSERT INTO transactions (user_id, type, name, symbol, price, shares, datetime) VALUES (?, ?, ?, ?, ?, ?, ?)", user_id, "buy", stock["name"], stock["symbol"], stock["price"], shares, datetime)
        cash_left = cash - (stock["price"] * shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_left, user_id)

        # update holdings table
        holdings = db.execute("SELECT * FROM holdings WHERE user_id = ?", user_id)
        check_symbols = []
        for holding in holdings:
            check_symbols.append(holding["symbol"])
        if symbol.upper() in check_symbols:
            db.execute("UPDATE holdings SET shares = (shares + ?) WHERE symbol = ? AND user_id = ?", shares, stock["symbol"], user_id)
        else:
            db.execute("INSERT INTO holdings (user_id, name, symbol, shares) VALUES (?, ?, ?, ?)", user_id, stock["name"], stock["symbol"], shares)

        flash("Bought successfully!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide a ticker")
        stock = lookup(symbol)
        if not stock:
            return apology("must provide valid ticker")

        return render_template("quoted.html", stock=stock)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Input validation
        username = request.form.get("username")
        if not username:
            return apology("must provide username")

        # TODO: dynamically check if username is not already in database
        check_username = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(check_username) != 0:
            return apology("username already taken")

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation or password != confirmation:
            return apology("must enter two matching passwords")

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    holdings = db.execute("SELECT name, symbol FROM holdings WHERE user_id = ? ORDER BY name", user_id)
    if request.method == "POST":

        # Input validation
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must select a stock")
        # check if you own the stock
        symbols = []
        for holding in holdings:
            symbols.append(holding["symbol"])
        if symbol not in symbols:
            return apology("must select a stock you own")

        # get stock data
        stock = lookup(symbol)
        if not stock:
            return apology("must provide valid ticker")

        # check input for shares
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except:
            return apology("must provide number of shares")
        if shares < 1:
            return apology("must provide a positive integer")

        # check if user has enough shares
        shares_owned = db.execute("SELECT shares FROM holdings WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if shares_owned[0]["shares"] < shares:
            return apology("insufficient shares")

        # get datetime
        datetime = db.execute("SELECT datetime('now', 'localtime')")
        datetime = datetime[0]["datetime('now', 'localtime')"]

        # commit to transactions and update cash
        db.execute("INSERT INTO transactions (user_id, type, name, symbol, price, shares, datetime) VALUES (?, ?, ?, ?, ?, ?, ?)", user_id, "sell", stock["name"], stock["symbol"], stock["price"], shares, datetime)
        cash_earned = (stock["price"] * shares)
        db.execute("UPDATE users SET cash = (cash + ?) WHERE id = ?", cash_earned, user_id)

        # update holdings table
        db.execute("UPDATE holdings SET shares = (shares - ?) WHERE symbol = ? AND user_id = ?", shares, stock["symbol"], user_id)
        db.execute("DELETE FROM holdings WHERE shares = 0")

        flash("Sold successfully!")
        return redirect("/")
    else:
        # get holdings to show for select menu
        return render_template("sell.html", holdings=holdings)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        user_id = session["user_id"]
        password_old = request.form.get("password_old")
        password_new = request.form.get("password_new")
        confirmation = request.form.get("confirmation")
        if not password_old or not password_new or not confirmation:
            return apology("please fill out the entire form")

        # check if new passwords match
        if password_new != confirmation:
            return apology("new passwords don't match")

        # check if old password is correct
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        if not check_password_hash(user[0]["hash"], password_old):
            return apology("incorrect password")

        # update database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(password_new), user_id)

        flash("Updated Password!")
        return redirect("/")
    else:
        return render_template("account.html")


@app.route("/money", methods=["POST"])
@login_required
def money():
    user_id = session["user_id"]

    # input validation for the option
    options = ["deposit", "withdraw"]
    type = request.form.get("type")
    if type not in options:
        return apology("please choose a valid option")

    # validation for the amount
    amount = request.form.get("amount")
    if not amount:
        return apology("please enter an amount")
    try:
        amount = int(amount)
    except:
        return apology("amount must be a positive integer")
    if amount < 1:
        return apology("amount must be a positive integer")

    # execute
    if type == "deposit":
        # deposit money
        db.execute("UPDATE users SET cash = (cash + ?) WHERE id = ?", amount, user_id)
        flash("Deposited successfully!")
    elif type == "withdraw":
        # withdraw money
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        if user[0]["cash"] < amount:
            return apology("insufficient funds")
        db.execute("UPDATE users SET cash = (cash - ?) WHERE id = ?", amount, user_id)
        flash("Withdrew successfully!")
    return redirect("/")
