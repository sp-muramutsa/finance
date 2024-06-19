import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime
from collections import namedtuple


from helpers import apology, login_required, lookup, usd, validate_password

# Configure application
app = Flask(__name__)
app.debug = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    """Allow user to change thier password"""
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        new_password_confirmation = request.form.get("new_password_confirmation")
        user_id = session["user_id"]

        # Validate passwords
        if not old_password:
            return apology("Please enter valid password")

        hash = db.execute(
            "SELECT hash FROM users WHERE id = :user_id", user_id=user_id
        )[0]["hash"]
        if not check_password_hash(hash, old_password):
            return apology("Please make sure your password is correct")

        if not new_password:
            return apology("Please enter new password")

        if not new_password_confirmation or new_password_confirmation != new_password:
            return apology(
                "Please make sure your confirmation matches your new password"
            )

        if check_password_hash(hash, new_password):
            return apology("Please use a password never used before")

        if not validate_password(new_password):
            return apology(
                "Password must me at least 6 characters long and must contain at least a lowercase letter, an uppercase letter, and a symbol"
            )

        # Register new passoword
        new_hash = generate_password_hash(new_password)

        # add the user and their details to the database
        db.execute("UPDATE users SET hash=:new_hash", new_hash=new_hash)

        return redirect("/login")

    else:
        return render_template("edit.html")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    cash_balance = db.execute(
        "SELECT cash FROM users WHERE id = :user_id", user_id=user_id
    )[0]["cash"]

    # Get total shares for each stock
    transactions = db.execute(
        """SELECT symbol, SUM(CASE WHEN transaction_type = "Buy" THEN shares ELSE -shares END) as total_shares
                                 FROM transactions
                                 WHERE user_id = :user_id
                                 GROUP BY symbol""",
        user_id=user_id,
    )

    # Calculate total worth for each stock
    Stock = namedtuple("Stock", ["total_shares", "stock_total_worth"])

    stocks = {}

    for transaction in transactions:
        symbol = transaction["symbol"]
        total_shares = transaction["total_shares"]
        stock_unit_price = lookup(symbol)["price"]
        stock_total_worth = total_shares * stock_unit_price
        stocks[symbol] = Stock(total_shares, stock_total_worth)

    # Calculate total current worth
    total_current_worth = sum([stocks[stock].stock_total_worth for stock in stocks])

    return render_template(
        "index.html",
        cash_balance=cash_balance,
        total_current_worth=total_current_worth,
        stocks=stocks,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]

        # Check input price validity and get the current price of the stock
        symbol = request.form.get("symbol")
        price_symbol = lookup(symbol)
        if not price_symbol:
            return apology("Stock Symbol Not Found")
        price = price_symbol["price"]

        # Check shares validity
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Please enter valid number of shares")
        if shares <= 0:
            return apology("Please enter a positive integer number of shares")

        # Lookup the user's worth and buy the stock if feasible
        current_worth = db.execute(
            "SELECT cash FROM users WHERE id = :user_id", user_id=user_id
        )[0]["cash"]
        total_stock_price = price * shares

        if total_stock_price > current_worth:
            return apology("Sorry you cannot afford this")

        # Buy the stock by creating a table for the user to track their history
        new_cash = current_worth - total_stock_price
        time_of_transaction = datetime.now()

        # Add the transaction and its details in the transactions database
        db.execute(
            """
            INSERT INTO transactions (user_id, symbol, unit_price, shares, total_stock_price, transaction_type, time_of_transaction)
            VALUES (:user_id, :symbol, :unit_price, :shares, :total_stock_price,
                    :transaction_type, :time_of_transaction)
        """,
            user_id=user_id,
            symbol=symbol.upper(),
            unit_price=price,
            shares=shares,
            total_stock_price=total_stock_price,
            transaction_type="Buy",
            time_of_transaction=time_of_transaction,
        )

        # Credit the user's account in the users database

        db.execute(
            "UPDATE users SET cash = :new_cash WHERE id = :user_id",
            new_cash=new_cash,
            user_id=user_id,
        )

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute(
        """
                              SELECT symbol, transaction_type, unit_price, shares, time_of_transaction FROM transactions
                              WHERE user_id = :user_id
                              ORDER BY time_of_transaction""",
        user_id=user_id,
    )
    print(transactions)
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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
        price_symbol = lookup(symbol)
        if price_symbol:
            price = price_symbol["price"]
            return render_template("quoted.html", symbol=symbol.upper(), price=price)
        else:
            return apology("Price not available for this stock")
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check if username already exists
        existing_user = db.execute(
            "SELECT username FROM users WHERE username = :username", username=username
        )
        if existing_user:
            return apology("Username already exists")

        # Validate password
        if not password:
            return apology("Please enter valid password")
        if not confirmation:
            return apology("Please confirm your password")
        if password != confirmation:
            return apology("Please make sure your confirmation matches your password")

        if not validate_password(password):
            return apology(
                "Password must me at least 6 characters long and must contain at least a lowercase letter, an uppercase letter, and a symbol"
            )

        # Hash the password
        hash = generate_password_hash(password)

        # add the user and their details to the database
        db.execute(
            "INSERT INTO users(username, hash) VALUES(:username, :hash)",
            username=username,
            hash=hash,
        )
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session["user_id"]
    cash_data = db.execute(
        "SELECT cash FROM users WHERE id = :user_id", user_id=user_id
    )
    cash = round(cash_data[0]["cash"], 3) if cash_data else None

    if request.method == "POST":
        return redirect("/edit")

    return render_template("profile.html", cash=cash)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]
        symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :user_id", user_id=user_id
        )
        symbols = list(set(symbol["symbol"] for symbol in symbols))

        # Validate symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Symbol not found")
        symbol = symbol

        # Validate shares and check if the user has that much value in stock they want to sell
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except ValueError:
            return apology("Shares must be a positive integer")

        if shares <= 0:
            return apology("Shares must be a positive integer")


        owned_shares_query = db.execute(
            """SELECT symbol, SUM(CASE WHEN transaction_type = "Buy" THEN shares ELSE -shares END) as total_shares
                                     FROM transactions WHERE user_id = :user_id AND symbol=:symbol
                                     GROUP BY symbol""",
            user_id=user_id,
            symbol=symbol.upper(),
        )

        try:
            owned_shares = owned_shares_query[0]["total_shares"]
        except IndexError:
            owned_shares = 0

        if shares > owned_shares:
            return apology(f"Your don't have enough {symbol.upper()} stocks")

        # Debit the user in users database
        current_stock_price = lookup(symbol)["price"]
        total_stock_price = current_stock_price * shares
        current_worth = db.execute(
            "SELECT cash FROM users WHERE id = :user_id", user_id=user_id
        )[0]["cash"]
        new_cash = current_worth + total_stock_price

        db.execute(
            "UPDATE users SET cash = :new_cash WHERE id = :user_id",
            user_id=user_id,
            new_cash=new_cash,
        )

        # Register the transaction in transactions
        time_of_transaction = datetime.now()
        db.execute(
            """
            INSERT INTO transactions (user_id, symbol, unit_price, shares, total_stock_price, transaction_type, time_of_transaction)
            VALUES (:user_id, :symbol, :unit_price, :shares, :total_stock_price,
                    :transaction_type, :time_of_transaction)
        """,
            user_id=user_id,
            symbol=symbol,
            unit_price=current_stock_price,
            shares=shares,
            total_stock_price=total_stock_price,
            transaction_type="Sell",
            time_of_transaction=time_of_transaction,
        )

        return redirect("/")

    else:
        user_id = session["user_id"]
        symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :user_id", user_id=user_id
        )
        symbols = list(set(symbol["symbol"] for symbol in symbols))
        return render_template("sell.html", symbols=symbols)


@app.route("/top", methods=["GET", "POST"])
@login_required
def top():
    if request.method == "POST":
        top_amount = request.form.get("top_amount")
        if not top_amount:
            return apology("Please enter top amount")

        try:
            top_amount = int(top_amount)
        except ValueError:
            return apology("Account should be topped with a positive amount")

        if top_amount <= 0:
            return apology("Account should be topped with a positive amount")

        user_id = session["user_id"]

        # Top account
        db.execute(
            "UPDATE users SET cash = cash + :top_amount WHERE id = :user_id",
            top_amount=top_amount,
            user_id=user_id,
        )

        return redirect("/")

    else:
        return render_template("top.html")
