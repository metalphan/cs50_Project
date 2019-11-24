import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import json, requests
from datetime import datetime

# leveraging Fernet to encrypt pass to save in DB, and decrypt to show on site after user logs in
# https://cryptography.io/en/latest/fernet/
from cryptography.fernet import Fernet

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

service_id='password_vault'

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///pword-vault.db")


@app.route("/", methods=["GET","POST"])
@login_required
def index():
    userid = session["user_id"]
    key = session["key"]
    user = db.execute("SELECT * FROM users WHERE id = :userid", userid=userid)
    categories = db.execute("SELECT NULL as categoryid, '' as categoryname, 1 AS SortOrder UNION SELECT *, 2 as SortOrder FROM categories ORDER BY SortOrder, categoryname")
    username = user[0]['username']
    if request.method=="POST":
        url = request.form.get('url')
        if not url:
            sitename=request.form.get('sitename')
            return redirect(url_for('addnew', sitename=sitename, categories=categories))
        else:
            siteid=request.form.get('siteid')
            sitename=request.form.get('sitename')
            site_categoryid=request.form.get('category_id')
            site_url=request.form.get('url')
            site_username=request.form.get('site_username')
            comment=request.form.get('comment')
            modified_date = datetime.now()

            # update site record in sites table
            # unsure why but terminal didn't show all correct data when updating so broke this out into multiple statements
            # seems working
            upd_sitename = db.execute("UPDATE sites SET site_name = :sitename WHERE siteid=:siteid"
                                , siteid=siteid, sitename=sitename)
            upd_category = db.execute("UPDATE sites SET category_id = :site_categoryid WHERE siteid=:siteid"
                                , siteid=siteid, site_categoryid=site_categoryid)
            upd_url = db.execute("UPDATE sites SET url = :site_url WHERE siteid=:siteid"
                                            , siteid=siteid, site_url=site_url)
            upd_username = db.execute("UPDATE sites SET username = :site_username WHERE siteid=:siteid"
                                            , siteid=siteid, site_username=site_username)
            upd_comment = db.execute("UPDATE sites SET comment = :comment WHERE siteid=:siteid"
                                            , siteid=siteid, comment=comment)
            upd_moddate = db.execute("UPDATE sites SET modified_date = :modified_date WHERE siteid=:siteid"
                                            , siteid=siteid, modified_date=modified_date)

            f = Fernet(key)
            site_password = f.encrypt(request.form.get('site_password').encode()).decode()

            # update site_passwords table
            result2 = db.execute("UPDATE site_passwords SET password = :site_password, modified_date = :modified_date WHERE siteid=:siteid", siteid=siteid, site_password=site_password, modified_date=modified_date)

            sites = db.execute("SELECT * FROM vsites WHERE userid=:userid",userid=userid)

            for site in sites:
                site['password'] = f.decrypt(site['password'].encode()).decode()
            return render_template("index.html",username=username, sites=sites, categories=categories)
    elif request.method=="GET":
        sites = db.execute("SELECT * FROM vsites WHERE userid=:userid",userid=userid)
        f = Fernet(key)
        for site in sites:
            site['password'] = f.decrypt(site['password'].encode()).decode()
        return render_template("index.html",username=username, sites=sites, categories=categories)
    return render_template("index.html", username=username)


@app.route("/check", methods=["GET"])
def check():
    username = request.args.get("username")
    check_username = db.execute("SELECT * FROM users WHERE username = :username", username = username)

    if len(username) > 1 and not check_username:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/addnew", methods=["GET","POST"])
@login_required
def addnew():
    userid=session["user_id"]
    key = session["key"]
    if request.method=="GET":
        sitename=request.args.get("sitename")
        categories = db.execute("SELECT NULL as categoryid, '' as categoryname, 1 AS SortOrder UNION SELECT *, 2 as SortOrder FROM categories ORDER BY SortOrder, categoryname")
        return render_template("add_new_site.html", sitename=sitename, categories=categories)
    else:
        sitename = request.form.get('sitename')
        category_id = request.form.get('category_id')
        url = request.form.get('url')
        site_username = request.form.get('site_username')
        comment=request.form.get('comment')
        created_date=datetime.now()
        modified_date=datetime.now()
        f = Fernet(key)
        site_password = f.encrypt(request.form.get('site_password').encode()).decode()
        siteid=db.execute("INSERT INTO sites (userid, site_name, category_id, username, url, comment, created_date, modified_date) VALUES (:userid, :sitename, :category_id, :site_username, :url, :comment, :created_date, :modified_date)",
                            userid=userid, sitename=sitename, category_id=category_id, site_username=site_username, url=url, comment=comment,created_date=created_date, modified_date=modified_date)
        db.execute("INSERT INTO site_passwords (siteid, password, created_date, modified_date) VALUES (:siteid, :site_password, :created_date, :modified_date)"
                    ,siteid=siteid, site_password=site_password, created_date=created_date, modified_date=modified_date)
        # return render_template("add_new_site.html", site_password=site_password)
        return redirect(url_for('index'))

@app.route("/edit", methods=["GET","POST"])
@login_required
def edit():
    if request.method=="POST":
        userid=session["user_id"]
        sitename = request.form.get('sitename')
        category_id = request.form.get('category_id')
        url = request.form.get('url')
        site_username = request.form.get('site_username')
        f = Fernet(key)
        site_password = f.encrypt(request.form.get('site_password').encode()).decode()
        comment=request.form.get('comment')
        created_date=datetime.now()
        modified_date=datetime.now()
        siteid=db.execute("INSERT INTO sites (userid, site_name, category_id, username, url, comment, created_date, modified_date) VALUES (:userid, :sitename, :category_id, :site_username, :url, :comment, :created_date, :modified_date)",
                            userid=userid, sitename=sitename, category_id=category_id, site_username=site_username, url=url, comment=comment,created_date=created_date, modified_date=modified_date)
        db.execute("INSERT INTO site_passwords (siteid, password, created_date, modified_date) VALUES (:siteid, :site_password, :created_date, :modified_date)"
                    ,siteid=siteid, site_password=site_password, created_date=created_date, modified_date=modified_date)
        return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))


@app.route("/notes", methods=["GET","POST"])
@login_required
def notes():
    userid=session["user_id"]
    key=session["key"]
    f = Fernet(key)
    if request.method=="POST":
        noteid=request.form.get("noteid")
        notename = request.form.get("notename")
        if not noteid:
            return redirect(url_for('addnewnote', notename=notename))
        else:
            noteid=request.form.get("noteid")
            print(request.form.get("note"))
            note=f.encrypt(request.form.get("note").encode()).decode()
            result=db.execute("UPDATE notes SET note=:note, notename=:notename WHERE noteid=:noteid", note=note, notename=notename, noteid=noteid)
            notes=db.execute("SELECT * FROM notes WHERE userid=:userid", userid=userid)
            for note in notes:
                note['note']= f.decrypt(note['note'].encode()).decode()
                if note['notename']:
                    note['notename'] = ""
            return render_template("notes.html", notes=notes)
    elif request.method=="GET":
        notes=db.execute("SELECT * FROM notes WHERE userid=:userid",userid=userid)
        for note in notes:
            note['note']= f.decrypt(note['note'].encode()).decode()
            if not note['notename']:
                note['notename'] = ""
        return render_template("notes.html", notes=notes)
    return render_template("notes.html")

@app.route("/delete", methods=["POST"])
@login_required
def delete():
    userid=session["user_id"]
    if request.form.get("deletesite"):
        siteid=request.form.get("deletesite")
        delete_pw=db.execute("DELETE FROM site_passwords WHERE siteid=:siteid", siteid=siteid)
        delete_site=db.execute("DELETE FROM sites WHERE siteid = :siteid", siteid=siteid)
        return redirect(url_for('index'))
    elif request.form.get("deletecard"):
        cardid=request.form.get("deletecard")
        delete_card=db.execute("DELETE FROM cards WHERE cardid=:cardid", cardid=cardid)
        return redirect(url_for('cards'))
    elif request.form.get("deletenote"):
        noteid=request.form.get("deletenote")
        delete_note=db.execute("DELETE FROM notes WHERE noteid=:noteid", noteid=noteid)
        return redirect(url_for('notes'))

@app.route("/cards", methods=["GET","POST"])
@login_required
def cards():
    userid=session["user_id"]
    key=session["key"]
    cardtypes = db.execute("SELECT NULL as cardtypeid, '' as cardtype, 1 AS SortOrder UNION SELECT cardtypeid, cardtype, 2 as SortOrder FROM cardtypes ORDER BY SortOrder, cardtype")
    print(cardtypes)
    if request.method=="POST":
        cardid = request.form.get('cardid')
        if not cardid:
            cardname=request.form.get('cardname')
            return redirect(url_for('addnewcard', cardname=cardname, cardtypes=cardtypes))
        else:
            cardid=request.form.get("cardid")
            cardname=request.form.get("cardname")
            cardtype=request.form.get("cardtypeid")
            cardholder=request.form.get("cardholder")
            f = Fernet(key)
            if request.form.get("cardnumber"):
                cardnumber = f.encrypt(request.form.get("cardnumber").encode()).decode()
            else:
                cardnumber=""
            if request.form.get("expire_date"):
                expire_month = request.form.get("expire_date")[5:]
                expire_year= request.form.get("expire_date")[:-3]
            else:
                expire_month=""
                expire_year=""
            if request.form.get("cvv"):
                cvv=f.encrypt(request.form.get("cvv").encode()).decode()
            else:
                cvv=""
            comment=request.form.get("comment")
            created_date=datetime.now()
            modified_date=datetime.now()
            update_statement="update cards set cardname = :cardname, cardtypeid = :cardtype, cardholder = :cardholder, cardnumber = :cardnumber,"
            update_statement+=" expirationmonth = :expire_month, expirationyear = :expire_year, cvv = :cvv, comment = :comment, created_date = :created_date, modified_date = :modified_date where cardid=:cardid "
            results=db.execute(update_statement, cardname=cardname, cardtype=cardtype, cardholder=cardholder, cardnumber=cardnumber, expire_month=expire_month, expire_year=expire_year, cvv=cvv
                                , comment=comment, created_date=created_date, modified_date=modified_date, cardid=cardid)

            cards = db.execute("SELECT * FROM vcards where userid=:userid", userid=userid)
            for card in cards:
                card['cardnumber'] = f.decrypt(card['cardnumber'].encode()).decode()
                card['cvv'] = f.decrypt(card['cvv'].encode()).decode()
            return render_template("cards.html", cards=cards, cardtypes=cardtypes)
    elif request.method=="GET":
        cards = db.execute("SELECT * FROM vcards WHERE userid=:userid",userid=userid)
        f = Fernet(key)
        for card in cards:
            card['cardnumber'] = f.decrypt(card['cardnumber'].encode()).decode()
            card['cvv'] = f.decrypt(card['cvv'].encode()).decode()
        return render_template("cards.html", cards=cards, cardtypes=cardtypes)
    return render_template("cards.html")

@app.route("/addnewnote", methods=["GET","POST"])
@login_required
def addnewnote():
    userid=session["user_id"]
    key=session["key"]
    if request.method=="GET":
        notename=request.args.get("notename")
        return render_template("add_new_note.html", notename=notename)
    else:
        notename=request.form.get("notename")
        if request.form.get("note"):
            f = Fernet(key)
            note=f.encrypt(request.form.get("note").encode()).decode()
        else:
            note=""
        created_date=datetime.now()
        modified_date=datetime.now()
        insert=db.execute("INSERT INTO notes (notename, note, userid, created_date, modified_date) VALUES (:notename, :note, :userid, :created_date, :modified_date)",
                            notename=notename, note=note, userid=userid, created_date=created_date, modified_date=modified_date)
        print(insert)
    return redirect(url_for('notes'))

@app.route("/addnewcard", methods=["GET","POST"])
@login_required
def addnewcard():
    userid=session["user_id"]
    key=session["key"]
    if request.method=="GET":
        cardname=request.args.get("cardname")
        cardtypes = db.execute("SELECT NULL as cardtypeid, '' as cardtype, 1 AS SortOrder UNION SELECT cardtypeid, cardtype, 2 as SortOrder FROM cardtypes ORDER BY SortOrder, cardtype")
        return render_template("add_new_card.html", cardname=cardname, cardtypes=cardtypes)
    else:
        cardname=request.form.get("cardname")
        cardtype=request.form.get("cardtype")
        cardholder=request.form.get("cardholder")
        if request.form.get("cardnumber"):
            f = Fernet(key)
            cardnumber = f.encrypt(request.form.get("cardnumber").encode()).decode()
        else:
            cardnumber = None
        if request.form.get("expire_date"):
            expire_month = request.form.get("expire_date")[5:]
            expire_year= request.form.get("expire_date")[:-3]
        else:
            expire_month = None
            expire_year = None
        if request.form.get("cvv"):
            cvv=f.encrypt(request.form.get("cvv").encode()).decode()
        else:
            cvv=None
        comment=request.form.get("comment")
        created_date=datetime.now()
        modified_date=datetime.now()
        insert_statement="INSERT INTO cards (cardname, cardtypeid, cardholder, cardnumber, expirationmonth, expirationyear, cvv, userid, comment, created_date, modified_date) "
        insert_statement+="values (:cardname, :cardtype, :cardholder, :cardnumber, :expire_month, :expire_year, :cvv, :userid, :comment, :created_date, :modified_date)"
        results=db.execute(insert_statement, cardname=cardname, cardtype=cardtype, cardholder=cardholder, cardnumber=cardnumber, expire_month=expire_month, expire_year=expire_year, cvv=cvv, userid=userid, comment=comment, created_date=created_date, modified_date=modified_date)
    return redirect(url_for('cards'))


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method=="POST":

        if not request.form.get("username"):
            return apology("you must provide a username")

        if not request.form.get("password") or not request.form.get("confirmation"):
            return apology("you must provide a password")

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must match")

        key = Fernet.generate_key()
        print(key)
        key=key.decode()
        print(key)
        current_time = datetime.now()
        print(current_time)
        hash = generate_password_hash(request.form.get("password"))
        print(hash)
        username=request.form.get("username")
        print(username)
        result = db.execute("INSERT INTO users (username, hash, key, created_date, modified_date) VALUES (:username, :hash, :key, :created_date, :modified_date)",
                            username=username, hash=hash, key=key, created_date = current_time, modified_date = current_time)

        session["user_id"] = result

        rows=db.execute("SELECT * FROM users WHERE id=:result",result=result)
        session["key"] = rows[0]["key"]

        if not result:
            return apology("username already exists")
        else:
            return redirect(url_for('index'))

    else:
        return render_template('register.html')

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
        session["key"] = rows[0]["key"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
