import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
# app.jinja_env.filters["usd"] = usd
app.jinja_env.globals.update(usd=usd)

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
    result = db.execute(
        "SELECT cash FROM users WHERE id=:id", id=session["user_id"])
    cash = result[0]['cash']

    stocks_owned = db.execute("SELECT stock, SUM(quantity) as quantity FROM transactions WHERE user_id == :id GROUP BY stock",id=session["user_id"])

    print(stocks_owned)

    grand_total = cash

    for stock in stocks_owned:
        price = lookup(stock['stock'])['price']
        total = stock['quantity'] * price
        stock.update({'price':price, 'total':total})
        grand_total += total

    print(usd(grand_total))
    # return apology("NOT")
    return render_template("index.html", stocks=stocks_owned, cash=usd(cash), total=usd(grand_total))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        if (not request.form.get("symbol")) or (not request.form.get("shares")):
            return apology("must provide stock symbol and number of shares")

        if int(request.form.get("shares")) <= 0:
            return apology("must provide valid number of shares (integer)")

        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("Stock symbol not valid, please try again")

        cost = int(request.form.get("shares")) *quote['price']

        result = db.execute(
            "SELECT cash FROM users WHERE id=:id", id=session['user_id'])

        if cost > result[0]['cash']:
            return apology("you do not have enough cash for this transaction")

        db.execute("UPDATE users SET cash=cash-:cost WHERE id=:id",cost=cost, id=session['user_id'])

        add_transaction = db.execute("INSERT INTO transactions (user_id, stock, quantity, price, date) VALUES(:user_id, :stock, :quantity, :price, :date)",
        user_id=session['user_id'], stock=quote['symbol'], quantity=int(request.form.get("shares")), price=quote['price'],date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        curr_portfolio = db.execute("SELECT quantity FROM portfolio WHERE stock=:stock", stock=quote['symbol'])

        if not curr_portfolio:
            db.execute("INSERT INTO portfolio (stock, quantity) VALUES (:stock, :quantity)",stock=quote['symbol'], quantity=int(request.form.get("shares")))
        else:
            db.execute("UPDATE portfolio SET quantity=quantity+:quantity WHERE stock=:stock",quantity=int(request.form.get("shares")), stock=quote['price'])

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    portfolio = db.execute("SELECT stock, quantity, price, date FROM transactions WHERE user_id=:id", id=session["user_id"])

    if not portfolio:
        return apology("sorry you have no transactions on record")
    return render_template("history.html", stocks=portfolio)

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

        if not request.form.get("symbol"):
            return apology("must provide stock symbol")
        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("Stock symbol not valid, please try again")
        else:
            return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # validation checks
        if not request.form.get("username"):
            return apology("must provide username")

        elif  not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide password")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and password confirmation must match")
        # hash password
        hash = generate_password_hash(request.form.get("password"))
        name = db.execute("SELECT username from users")

        for users in name:
            if request.form.get("username") == users['username']:
                return apology("username is already registered")

        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=request.form.get("username"), hash=hash)

        session["user_id"] = result

        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        if ( not request.form.get("symbol")):
            return apology("must provide stock symbol and")
        if (not request.form.get("shares")):
            return apology("must provide number of shares")

        if int(request.form.get("shares")) <= 0:
            return apology("must provide valid number of shares (integers)")
        available = db.execute("SELECT quantity FROM portfolio WHERE :stock=stock", stock=request.form.get("stock"))

        if int(request.form.get("shares")) > available[0]['quantity']:
            return apology("You may not sell more shares than you currently hold")

        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("Stock symbol not valid, please try again")

        cost = int(request.form.get("shares") )* quote['price']

        db.execute("UPDATE users SET cash=cash+:cost WHERE id=:id", cost=cost, id=session["user_id"])

        add_transaction = db.execute("INSERT INTO transactions(user_id, stock, quantity, price, date) VALUES (:user_id, :stock, :quantity, :price, :date)",user_id=session["user_id"], stock=quote["symbol"], quantity=-int(request.form.get("shares")), price=quote['price'], date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        db.execute("UPDATE portfolio SET quantity=quantity-:quantity WHERE stock=:stock", quantity=int(request.form.get("shares")), stock=quote["symbol"])

        return redirect("/")
    else:
        portfolio = db.execute("SELECT stock from portfolio")
        return render_template("sell.html", stocks=portfolio)
