import requests
import urllib.parse

from flask import redirect, render_template, session, flash
from functools import wraps

from env import API_KEY

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template(
        "apology.html",
        top=code,
        bottom=escape(message)
    ), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Contact API
    try:
        api_key = API_KEY
        response = requests.get(f"https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={urllib.parse.quote_plus(symbol)}&apikey={api_key}")
        response.raise_for_status()
    except requests.RequestException as e:
        flash(f"Error getting data from API: {e}", "error")
        print(f"Error getting data from API: {e}")
        return None

    # Parse response
    try:
        quote = response.json()
        return {
            "name": quote["Global Quote"]["01. symbol"],
            "price": float(quote["Global Quote"]["05. price"]),
            "symbol": quote["Global Quote"]["01. symbol"]
        }
    except (KeyError, TypeError, ValueError) as e:
        flash(f"Error parsing data from API: {e}", "error")
        print(f"Error parsing data from API: {e}")
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"
