import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use Postgres database
db = SQL(os.environ.get("DATABASE_URL").replace("://", "ql://", 1))


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    """ Requests total cash from current user """
    total = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
    if not total:
        return apology("Error retrieving total cash", 400)

    # Variable for user total cash
    totalCash = total[0]['cash']

    # Variable for user total stock value
    totalStock = 0

    """ Requests all shares from current user """
    portfolio = db.execute(
        "SELECT symbol, price, SUM(quantity) AS quantity FROM portfolio WHERE username=:username::varchar GROUP BY symbol HAVING SUM(quantity) > 0", username=session["user_id"])
    if not portfolio:
        return render_template("index.html", totalCash=usd(totalCash), grandTotal=usd(totalCash))

    """ Interates over portfolio dictionary and adds current price, name and stock total value """
    for count, stock in enumerate(portfolio):
        quote = lookup(stock["symbol"])
        portfolio[count]['currentPrice'] = usd(quote['price'])
        portfolio[count]['name'] = quote['name']
        portfolio[count]['total'] = usd(quote['price'] * stock['quantity'])
        totalStock += quote['price'] * stock['quantity']

    grandTotal = totalCash + totalStock

    return render_template("index.html", totalCash=usd(totalCash), portfolio=portfolio, totalStock=usd(totalStock), grandTotal=usd(grandTotal))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Get stock quote
        quote = lookup(request.form.get("symbol"))

        # if invalid stock name is provided, return apology
        if not quote:
            return apology("incorrect stock name", 400)

        # Checks if provided quantity is an integer and positive
        try:
            quantity = int(request.form.get("shares"))
            assert quantity > 0, "Number must be positive"
        except:
            return apology("must be a valid number", 400)

        # Variable for total purchase value
        total = quote["price"] * quantity

        # Returns user's total cash
        rows = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])

        # Returns apology if total purchase is greater than available cash
        if not rows[0]["cash"] >= total:
            return apology("insufficient funds", 403)

        # Current time and date
        now = datetime.datetime.now()

        # Insert to portfolio table data about purchase
        purchase = db.execute("INSERT INTO portfolio(username, symbol, price, quantity, date) VALUES(:username, :symbol, :price, :quantity, :date)",
                              username=session["user_id"], symbol=quote["symbol"], price=quote["price"], quantity=quantity, date=now)

        # Updates user's cash after purchase
        update = db.execute("UPDATE users SET cash = cash - :total WHERE id=:id", total=total, id=session["user_id"])
        flash("Stock Bought!")
        return redirect('/')
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    if request.method == 'GET':
        username = request.args.get('username')
        # Query database for username
        query = db.execute('SELECT username FROM users WHERE username = :username', username=username)

        # If username is lenght > 1 and does not contain in users database, return true; otherwise, false
        if len(username) > 1 and not query:
            return jsonify(True)
        else:
            return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute(
        'SELECT symbol, price, quantity, date, CASE WHEN quantity > 0 THEN "BUY" WHEN quantity < 0 THEN "SELL" END as "status" FROM portfolio WHERE username= :username', username=session["user_id"])

    """ Interates over history dictionary and adds name """
    for count, stock in enumerate(history):
        quote = lookup(stock["symbol"])
        history[count]['name'] = quote['name']

    return render_template("history.html", history=history)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        print(session["user_id"])

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
        quote = lookup(request.form.get("symbol"))

        if quote:
            return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=usd(quote["price"]))
        else:
            return apology("incorrect stock name", 400)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        user = db.execute('SELECT username FROM users WHERE username=:username', username=request.form.get("username"))
        if user:
            return apology('user already exists', 400)

        hash = generate_password_hash(request.form.get("password"))

        # Query database for username
        result = db.execute("INSERT INTO users(username, hash) VALUES(:username, :hash)",
                            username=request.form.get("username"), hash=hash)
        if not result:
            return apology("user already exists", 200)

        # Stores id returned by INSERT
        session["user_id"] = result

        # Redirect user to home page
        flash("Registration successful")
        return redirect(url_for('index'))

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'POST':
        # Checks if stock name is not blank
        if not request.form.get('symbol'):
            return apology("Must select a stock", 400)

        # Stores symbol in a variable
        symbol = request.form.get('symbol').upper()

        # Checks if quantity is positive and it is an integer
        try:
            quantity = int(request.form.get("shares"))
            assert quantity > 0
        except:
            # flash("Quantity must be a valid number")
            # return redirect("/sell")
            return apology("Quantity must be a valid number", 400)

        # Returns total number of shares of selected stock
        available = db.execute('SELECT SUM(quantity) AS quantity FROM portfolio WHERE username = :username AND symbol = :symbol',
                               username=session['user_id'], symbol=symbol)
        # Checks if stock exists in portfolio and in sufficient qty
        if not available:
            # flash("No stocks available")
            # return redirect("/sell")
            return apology("No stocks available", 400)

        # Checks if quantity of shares to be sold does not exceed quantity in possession
        if quantity > available[0]['quantity']:
            # flash('Insuficient stock quantity')
            # return redirect("/sell")
            return apology("Insuficient stock quantity", 400)

        # Quote for updated stock price
        quote = lookup(symbol)

        # Current time and date
        now = datetime.datetime.now()

        # Insert to portfolio table data about the selling
        sell = db.execute("INSERT INTO portfolio(username, symbol, price, quantity, date) VALUES(:username, :symbol, :price, :quantity, :date)",
                          username=session["user_id"], symbol=quote["symbol"], price=quote["price"], quantity=-quantity, date=now)

        soldTotal = quote['price'] * quantity

        # Updates user's wallet
        update = db.execute("UPDATE users SET cash = cash + :soldTotal WHERE id=:id", soldTotal=soldTotal, id=session["user_id"])

        # Message to user
        flash("Stock sold")
        return redirect(url_for('index'))
    else:
        # Users get by a GET request

        # Query to search for all stock symbols from given user that have qty > 0
        options = db.execute(
            'SELECT symbol, SUM(quantity) AS sum_total FROM portfolio WHERE username = :username GROUP BY symbol HAVING sum_total > 0', username=session["user_id"])
        return render_template("sell.html", options=options)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    '''Manages users settings'''
    if request.method == 'POST':
        password = request.form.get("password")
        if not password:
            flash('You must provide the current password')
            return redirect("/settings")

        password_new = request.form.get("password_new")
        if not password_new:
            flash('You must provide the new password')
            return redirect("/settings")

        # Query database
        rows = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])
        print(rows)
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid password", 403)

        # Hash new password
        hash = generate_password_hash(request.form.get("password_new"))

        # Update password
        update = db.execute('UPDATE users SET hash = :hash WHERE id = :id', hash=hash, id=session["user_id"])
        if update:
            # Redirect user to home page
            flash("Password have successfully changed")
            return redirect(url_for('index.html'))
        else:
            flash("Error updating password")
            return redirect(url_for('index.html'))
    else:
        return render_template('settings.html')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
