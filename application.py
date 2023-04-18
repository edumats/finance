import decimal

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

from helpers import apology, login_required, lookup, usd
import datetime

from env import DATABASE_URL

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

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
# Using pool_recycle to avoid using closed connections
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_recycle' : 280}

db = SQLAlchemy(app)

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Requests total cash from current user
    total = db.session.execute(
        "SELECT cash FROM users WHERE id=:id",
        {"id": session["user_id"]}
    )
    cash = total.fetchone()

    # If no user was found, return error
    if cash is None:
        return apology("Error retrieving total cash", 400)
    

    # User total cash returned as Decimal type
    totalCash = cash['cash']

    # User total stock value
    totalStock = 0

    """ Requests all shares from current user """
    portfolio = db.session.execute(
        "SELECT symbol, CAST(SUM(quantity) AS SIGNED INTEGER) AS quantity "
        "FROM portfolio "
        "WHERE user_id=:username "
        "GROUP BY symbol "
        "HAVING SUM(quantity) > 0",
        {"username": session["user_id"]}
    )

    portfolio = portfolio.fetchall()

    if not portfolio:
        return render_template(
            "index.html",
            totalCash=usd(totalCash),
            grandTotal=usd(totalCash)
        )

    """
    Iterates over portfolio list of dicts
    Adds current price, name and stock total value
    """
    result = []
    for stock in portfolio:
        quote = lookup(stock["symbol"])
        result.append(
            {
                "currentPrice": usd(quote['price']),
                "name": quote['name'],
                "total": usd(quote['price'] * stock['quantity']),
            }
        )
        totalStock += quote['price'] * stock['quantity']

    grandTotal = totalCash + totalStock

    return render_template(
        "index.html",
        totalCash=usd(totalCash),
        portfolio=result,
        totalStock=usd(totalStock),
        grandTotal=usd(grandTotal)
    )


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

        # Check if quantity of stocks requested by user is integer
        try:
            quantity = int(request.form.get("shares"))
        except (ValueError, TypeError):
            return apology("must be a valid number", 400)

        # Checks if provided quantity is not positive or zero
        if quantity <= 0:
            return apology("must be a positive number", 400)

        # Variable for total purchase value
        total = quote["price"] * quantity

        # Returns user's total cash
        rows = db.session.execute(
            "SELECT cash FROM users WHERE id=:id",
            {"id": session["user_id"]}
        )

        rows = rows.fetchone()

        # Returns apology if total purchase is greater than available cash
        if not rows["cash"] >= total:
            return apology("insufficient funds", 403)

        # Current time and date
        now = datetime.datetime.now()

        # Insert to portfolio table data about purchase
        db.session.execute(
            "INSERT INTO portfolio(user_id, symbol, price, quantity, date) "
            "VALUES(:username, :symbol, :price, :quantity, :date)",
            {
                "username": session["user_id"],
                "symbol": quote["symbol"],
                "price": quote["price"],
                "quantity": quantity,
                "date": now,
            }
        )

        # Updates user's cash after purchase
        db.session.execute(
            "UPDATE users "
            "SET cash = cash - :total "
            "WHERE id=:id",
            {"total": total, "id": session["user_id"]}
        )
        flash(
            f"{quote['name']} bought for the unit price of {usd(quote['price'])}. Paid {usd(total)}"
        )
        return redirect('/')
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    if request.method == 'GET':
        username = request.args.get('username')
        # Query database for username
        query = db.session.execute(
            'SELECT username FROM users WHERE username = :username',
            {"username": username}
        )

        query = list(query)

        # If username is lenght > 1 and does not contain in users database, return true; otherwise, false
        if len(username) > 1 and not query:
            return jsonify(True)
        else:
            return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.session.execute(
        "SELECT symbol, price, quantity, date, "
        "CASE WHEN quantity > 0 "
        "THEN 'BUY' "
        "WHEN quantity < 0 "
        "THEN 'SELL' "
        "END status "
        "FROM portfolio "
        "WHERE user_id=:username ",
        {"username": session["user_id"]}
    )

    result = []
    """ Interates over history list of dicts """
    for stock in history:
        result.append(
            {
                "name": stock["symbol"],
                "price": usd(stock["price"]),
                "date": stock["date"].strftime("%d/%m/%Y"),
            }
        )

    return render_template("history.html", history=result)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Query database for username
        rows = db.session.execute(
            "SELECT * FROM users WHERE username = :username",
            {"username": username}
        )

        rows = rows.fetchone()

        # Ensure username exists and password is correct
        if rows is None or not check_password_hash(rows["hash"], password):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows["id"]

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
            return render_template(
                "quoted.html",
                name=quote["name"],
                symbol=quote["symbol"],
                price=usd(quote["price"])
            )
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
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not password:
            return apology("must provide password", 400)

        if password != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Check if user already exists
        user = db.session.execute(
            'SELECT username FROM users WHERE username=:username',
            {"username": username}
        )
        row = user.fetchone()

        if row is not None:
            return apology('user already exists', 400)

        hash = generate_password_hash(password)

        # Query database for username
        result = db.session.execute(
            "INSERT INTO users(username, hash) VALUES(:username, :hash)",
            {
                "username": username,
                "hash": hash,
            }
        )
        db.session.commit()

        # Stores id returned by INSERT
        session["user_id"] = result.lastrowid
        print(f'Session id: {session["user_id"]}')

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

        # Quantity of stocks requested by user
        try:
            quantity = int(request.form.get("shares"))
        except (ValueError, TypeError):
            return apology("must be a valid number", 400)

        # Checks if provided quantity is positive
        if quantity <= 0:
            return apology("must be a positive number", 400)

        # Returns total number of shares of selected stock
        available = db.session.execute(
            "SELECT CAST(SUM(quantity) AS SIGNED INTEGER) AS quantity "
            "FROM portfolio "
            "WHERE user_id=:username AND symbol=:symbol",
            {"username": session['user_id'], "symbol": symbol}
        )
        available = list(available)
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
        db.session.execute(
            "INSERT INTO portfolio(user_id, symbol, price, quantity, date) "
            "VALUES(:username, :symbol, :price, :quantity, :date)",
            {
                "username": session["user_id"],
                "symbol": quote["symbol"],
                "price": quote["price"],
                "quantity": -quantity,
                "date": now,
            }
        )

        soldTotal = quote['price'] * quantity

        # Updates user's wallet
        db.session.execute(
            "UPDATE users SET cash = cash + :soldTotal WHERE id=:id",
            {
                "soldTotal": soldTotal,
                "id": session["user_id"],
            }
        )

        # Message to user
        flash(f"{quote['name']} sold for the unit price of ${quote['price']}. Received ${soldTotal}")
        return redirect(url_for('index'))
    else:
        # Users get by a GET request

        # Query to search for all stock symbols from given user that have qty > 0
        options = db.session.execute(
            "SELECT symbol, CAST(SUM(quantity) AS SIGNED INTEGER) AS sum_total "
            "FROM portfolio "
            "WHERE user_id=:username "
            "GROUP BY symbol "
            "HAVING SUM(quantity) > 0",
            {"username": session["user_id"]}
        )
        return render_template("sell.html", options=list(options))


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
            flash('You must provide a new password')
            return redirect("/settings")

        # Query database
        rows = db.session.execute(
            "SELECT * FROM users WHERE id = :id",
            {"id": session["user_id"]}
        )

        rows = rows.fetchone()

        # Ensure username exists and password is correct
        if rows is None or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid password", 403)

        # Hash new password
        hash = generate_password_hash(request.form.get("password_new"))

        # Update password
        try:
            db.session.execute(
                'UPDATE users SET hash = :hash WHERE id = :id',
                {"hash": hash, "id": session["user_id"]}
            )
            db.session.commit()
            
        except IntegrityError:
            db.session.rollback()
            flash("Error updating password")
            return redirect(url_for('index.html'))

        # Update was successful
        flash("Password update successful")
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


if __name__ == '__main__':
    app.run()