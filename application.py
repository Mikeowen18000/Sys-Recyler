from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify, send_from_directory
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from tempfile import gettempdir
import sqlite3
from flask_mail import Mail, Message


from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps
#JINJA FIXING #
#pip install jinja2==3.0.3 --force-reinstall
#To be DELETED#
from markupsafe import Markup

from flask_jsglue import JSGlue
import re
import datetime
import time

from helpers import *
import os
from werkzeug.utils import secure_filename



# Import smtplib for the actual sending function
import smtplib

# configure application pip
app = Flask(__name__)

JSGlue(app)


# custom filter
app.jinja_env.filters["usd"] = usd
        
# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = gettempdir()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "secret111"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
#database renaming from myflaskapp to storage
app.config['MYSQL_DB'] = 'myflask'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = "munakuimba@gmail.com"
app.config['MAIL_PASSWORD'] = "kushatakwakoiwe"
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


mail = Mail(app)

UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = ['jpg']


# ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response
        
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

        

#Session(app)

# configure CS50 Library to use SQLite database

#remove comments on code --db = SQL ("sqlite:///yauction.db")
db = SQL("sqlite:///yauction.db")


# Config MySQL

#intialise
mysql = MySQL(app)



###########################################

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedin' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login','danger')
            return redirect(url_for('login'))
    return wrap

def is_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return f(*args, *kwargs)
        else:
            return redirect(url_for('admin_login'))

    return wrap


def not_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return redirect(url_for('admin'))
        else:
            return f(*args, *kwargs)

    return wrap


@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/recyclingfirm')
def recyclingfirm():
    cur = mysql.connection.cursor()

    #result = cur.execute("SELECT * FROM materialcollected WHERE addedby = username")
    #result = cur.execute('SELECT * FROM materialcollected WHERE addedby = %s', (session['username'],))
    result = cur.execute("SELECT * FROM recyclerfirm")
    
    recyclerfirm = cur.fetchall()

    if result > 0:
        return render_template('recyclingfirm.html', recyclerfirm=recyclerfirm)
    else:
        msg = 'Nothing here'
        return render_template('recyclingfirm.html',msg=msg)

    #close connection
    cur.close()



    return render_template('recyclingfirm.html')


@app.route('/admin_login', methods=['GET', 'POST'])
@not_admin_logged_in
def admin_login():
    if request.method == 'POST':
        # GEt user form
        username = request.form['email']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM admin WHERE email=%s", [username])

        if result > 0:
            # Get stored value
            data = cur.fetchone()
            password = data['password']
            uid = data['id']
            name = data['firstName']

            # Compare password
            if sha256_crypt.verify(password_candidate, password):
                # passed
                session['admin_logged_in'] = True
                session['admin_uid'] = uid
                session['admin_name'] = name

                
                return redirect(url_for('admin'))

            else:
                flash('Incorrect password', 'danger')
                return render_template('pages/login.html')

        else:
            flash('Username not found', 'danger')
            # Close connection
            cur.close()
            return render_template('pages/login.html')
    return render_template('pages/login.html')


@app.route('/admin_out')
def admin_logout():
    if 'admin_logged_in' in session:
        session.clear()
        return redirect(url_for('admin_login'))
    return redirect(url_for('admin'))

@app.route('/admin')
@is_admin_logged_in
def admin():
    cur = mysql.connection.cursor()
    num_rows = cur.execute("SELECT * FROM materialcollected ORDER BY address DESC")
    result = cur.fetchall()
    order_rows = cur.execute("SELECT * FROM materialcollected WHERE status = 'pending'")
    users_rows = cur.execute("SELECT * FROM users")

    countRequest = cur.execute("SELECT * FROM materialcollected WHERE disposalmethod = 'Request Collection' AND status = 'pending' GROUP BY address ")
    countMax = cur.execute("SELECT * FROM materialcollected WHERE disposalmethod = 'Request Collection' AND status = 'pending' AND address = 'Waterfalls'")
    #countMax = cur.execute("SELECT MAX(Total) FROM (SELECT COUNT(*) AS Total FROM materialcollected GROUP BY address) AS Results")
    
    #if countRequest > 10:
    #   flash('Please Contact Local Authority quota has been reached')
    #  return redirect(url_for(admin))

    return render_template('pages/index.html', result=result, row=num_rows, order_rows=order_rows,
                           users_rows=users_rows,countRequest=countRequest,countMax=countMax)

    

    flash('Incorrect password', 'danger')


@app.route('/users')
@is_admin_logged_in
def users():
    cur = mysql.connection.cursor()
    num_rows = cur.execute("SELECT * FROM materialcollected")
    order_rows = cur.execute("SELECT * FROM materialcollected WHERE status = 'pending'")
    users_rows = cur.execute("SELECT * FROM users")
    result = cur.fetchall()
    return render_template('pages/all_users.html', result=result, row=num_rows, order_rows=order_rows,
                           users_rows=users_rows)


@app.route('/orders')
@is_admin_logged_in
def orders():
    curso = mysql.connection.cursor()
    num_rows = curso.execute("SELECT * FROM materialcollected")
    order_rows = curso.execute("SELECT * FROM materialcollected WHERE status = 'pending'")
    result = curso.fetchall()
    users_rows = curso.execute("SELECT * FROM users")
    return render_template('pages/all_orders.html', result=result, row=num_rows, order_rows=order_rows,
                           users_rows=users_rows)


@app.route('/profile')
@is_logged_in
def profile():
    if 'user' in request.args:
        q = request.args['user']
        curso = mysql.connection.cursor()
        curso.execute("SELECT * FROM users WHERE id=%s", (q,))
        result = curso.fetchone()
        if result:
            if result['id'] == session['uid']:
                curso.execute("SELECT * FROM orders WHERE uid=%s ORDER BY id ASC", (session['uid'],))
                res = curso.fetchall()
                return render_template('profile.html', result=res)
            else:
                flash('Unauthorised', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Unauthorised! Please login', 'danger')
            return redirect(url_for('login'))
    else:
        flash('Unauthorised', 'danger')
        return redirect(url_for('login'))




@app.route('/recyclerportal')
@is_logged_in
def recyclerportal():
    #CReate cursor
    cur = mysql.connection.cursor()

    #result = cur.execute("SELECT * FROM materialcollected WHERE addedby = username")
    #result = cur.execute('SELECT * FROM materialcollected WHERE addedby = %s', (session['username'],))
    result = cur.execute("SELECT * FROM materialcollected WHERE disposalmethod = 'Sell' AND status = 'pending'")
    
    materialcollected = cur.fetchall()

    if result > 0:
        return render_template('recyclerportal.html', materialcollected=materialcollected)
    else:
        msg = 'Nothing here'
        return render_template('recyclerportal.html',msg=msg)

    #close connection
    cur.close()


@app.route('/dashboard')
@is_logged_in
def dashboard():
    #CReate cursor
    cur = mysql.connection.cursor()

    #result = cur.execute("SELECT * FROM materialcollected WHERE addedby = username")
    result = cur.execute('SELECT * FROM materialcollected WHERE addedby = %s', (session['username'],))
    #result = cur.execute("SELECT * FROM materialcollected")
    
    materialcollected = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', materialcollected=materialcollected)
    else:
        msg = 'Nothing here'
        return render_template('dashboard.html',msg=msg)

    #close connection
    cur.close()
#########################

class PurchaseRequestForm(Form):
    transportationtype = [('delivery', 'delivery'),
                   ('request collection', 'request collection'),
                    ]

    
    payingamount= StringField('Amount to be paid',[validators.Length(min=1, max=50)])
    
    transportation = SelectField('Transportation', choices=transportationtype)

    address= StringField('Location',[validators.Length(min=1, max=50)])

    email = StringField('Email', [validators.DataRequired(), validators.length(min=4, max=25)],
                       render_kw={'placeholder': 'Email'})
    subject = StringField('Subject', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Subject'})
    message = StringField('Message', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Message'})
    
 
@app.route('/purchaserequest',methods=['GET','POST'])
def purchaserequest():
    form = PurchaseRequestForm(request.form)
    if request.method == 'POST' and form.validate():
        
        payingamount = form.payingamount.data
        transportation = form.transportation.data
        address = form.address.data
        email = form.email.data
        subject = form.subject.data
        message = form.message.data

        msg = Message('Hello ' + transportation + 'from'+ address + 'we will pay' + payingamount + 'for your material, confirm by responding to this email or message 0777 893 211',sender="munakuimba@gmail.com",recipients=[email])

        msg.body = message

        mail.send(msg)
        success = 'delivered'

        
        return redirect (url_for('recyclerportal'))

        #return render_template('register.html')
    return render_template('purchaserequest.html', form=form)


@app.route('/closesale',methods=['GET','POST'])
@is_logged_in
def closesale():
    cur = mysql.connection.cursor()

    cur.execute('UPDATE materialcollected SET status = "Sold" WHERE addedby = %s AND disposalmethod = "Sell"' , (session['username'],))

        #commit
    mysql.connection.commit()

        #close connection
    cur.close

    flash('Closed', 'success')

    return redirect(url_for('dashboard'))

    return render_template('dashboard.html', form=form)

@app.route('/closerequest',methods=['GET','POST'])
@is_logged_in
def closerequest():
    cur = mysql.connection.cursor()

    cur.execute('UPDATE materialcollected SET status = "Log Issued" WHERE addedby = %s AND disposalmethod = "Request Collection"' , (session['username'],))

        #commit
    mysql.connection.commit()

        #close connection
    cur.close

    flash('Closed', 'success')

    return redirect(url_for('dashboard'))

    return render_template('dashboard.html', form=form)


#####################

class RequestCollectionForm(Form):
    email = StringField('Email', [validators.DataRequired(), validators.length(min=4, max=25)],
                       render_kw={'placeholder': 'Email'})
    subject = StringField('Subject', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Subject'})
    message = StringField('Message', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Message'})
    
    


@app.route('/requestcollection',methods=['GET','POST'])
def requestcollection():
    form = RequestCollectionForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        subject = form.subject.data
        message = form.message.data

        msg = Message(subject,sender="munakuimba@gmail.com",recipients=[email])

        msg.body = message

        mail.send(msg)
        success = 'delivered'

        cur = mysql.connection.cursor()

        cur.execute("UPDATE materialcollected SET status = 'Log Issued' WHERE status = 'Pending' AND disposalmethod='Request Collection'")

        #commit
        mysql.connection.commit()

        #close connection
        cur.close

        flash('Request Logged With Council', 'success')

        return redirect (url_for('admin'))

        #return render_template('register.html')
    return render_template('requestcollection.html', form=form)


class MaterialCollectedForm(Form):
    materialtypes = [('Plastic', 'Plastic'),
                   ('Glass', 'Glass'),
                   ('Paper', 'Paper'),                
                   ('General Trash','General Trash')
                ]

    disposaltypes = [('Sell', 'Sell'),
                   ('Request Collection', 'Request Collection')
                   
                ]
                
    statustypes = [('Pending', 'Pending'),
                   ('Sold', 'Sold'),
                   ('Log Issued', 'Log Issued')
                ]

    typeofmaterial = SelectField('Type of material', choices=materialtypes)
    
    amount= StringField('Amount',[validators.Length(min=1, max=50)])
    address= StringField('Address',[validators.Length(min=4, max=50)])
    disposalmethod = SelectField('Disposal Method', choices=disposaltypes)
    status = SelectField('Status', choices=statustypes)

    #addedby = StringField('Added By',[validators.Length(min=4, max=50)])

@app.route('/add_material',methods=['GET','POST'])
@is_logged_in
def add_material():
    form = MaterialCollectedForm(request.form)
    if request.method == 'POST' and form.validate():
        typeofmaterial = form.typeofmaterial.data
        amount = form.amount.data
        address = form.address.data        
        disposalmethod = form.disposalmethod.data
        status = form.status.data
        #addedby = form.addedby.data

        #create cursor 
        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO materialcollected(typeofmaterial, amount, address, disposalmethod, status, addedby) VALUES(%s, %s, %s, %s,%s, %s)", (typeofmaterial, amount, address,  disposalmethod, status, session['username']))

        #commit
        mysql.connection.commit()

        #close connection
        cur.close

        flash('Saved', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_material.html', form=form)


#edit
@app.route('/edit_material/<string:id>',methods=['GET','POST'])
@is_logged_in
def edit_material(id):
    #cursor
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM materialcollected where id = %s", [id])

    material = cur.fetchone()

    
    form = MaterialCollectedForm(request.form)


    form.typeofmaterial.data = material['typeofmaterial']
    form.amount.data = material['amount']
    form.address.data = material['address']
    form.disposalmethod.data = material['disposalmethod']
    form.status.data = material['status']


    if request.method == 'POST' and form.validate():
        typeofmaterial = form.typeofmaterial.data
        amount = form.amount.data
        address = form.address.data        
        disposalmethod = form.disposalmethod.data
        status = form.status.data
        #addedby = form.addedby.data

        #create cursor 
        cur = mysql.connection.cursor()

        cur.execute("UPDATE materialcollected SET typeofmaterial=%s, amount=%s, address=%s, disposalmethod = %s, status=%s, addedby WHERE id = %s", (typeofmaterial, amount, address,  disposalmethod, status, session['username']))

        #commit
        mysql.connection.commit()

        #close connection
        cur.close

        flash('Saved', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_material.html', form=form)


class RegisterForm(Form):
    usertypes = [('Waste Collector', 'Waste Collector'),
                   ('recycler', 'recycler'),
                   ('household', 'household')
                ]
    name = StringField('Full Name', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Full Name'})
    username = StringField('Username', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Username'})
    email = StringField('Email', [validators.DataRequired(), validators.length(min=4, max=25)],
                       render_kw={'placeholder': 'Email'})
    usertype = SelectField('User Type', choices=usertypes,  render_kw={'placeholder': 'User Type'})
    password= PasswordField('Password',[
        validators.DataRequired(),
        validators.EqualTo('confirm', message="passwords do not match")
    ],  render_kw={'placeholder': 'Password'})
    confirm=PasswordField("Confirm password")



@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        usertype = form.usertype.data
        email = form.email.data        
        username = form.username.data
        password = sha256_crypt.hash(str(form.password.data))
        
        #create cursor 
        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO users(name, usertype, email, username, password) VALUES(%s, %s, %s, %s, %s)", (name, usertype, email,  username, password))

        #commit
        mysql.connection.commit()

        #close connection
        cur.close

        flash('you are registered', 'success')

        return redirect (url_for('login'))

        #return render_template('register.html')
    return render_template('register.html', form=form)


@app.route('/loginrecycler',methods=['GET','POST'])
def loginrecycler():
    if request.method == 'POST':
        #get from fields
        username = request.form['username']
        password_candidate = request.form['password']

        #create cursor
        cur = mysql.connection.cursor()

        #get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s",[username])

        if result > 0:
            data = cur.fetchone()
            password = data ['password']

            #compare
            if sha256_crypt.verify(password_candidate,password):
                
                session ['loggedin']= True
                session['username'] = username
                

                flash('you are now logged in','success')
                
                return redirect(url_for('recyclerportal'))
            else:
                app.logger.info('no match')
        else:
            error = "invalid login"
            return render_template('loginrecycler.html', error=error)
        cur.close()

    return render_template('loginrecycler.html')


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        #get from fields
        username = request.form['username']
        password_candidate = request.form['password']

        #create cursor
        cur = mysql.connection.cursor()

        #get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s",[username])

        if result > 0:
            data = cur.fetchone()
            password = data ['password']

            #compare
            if sha256_crypt.verify(password_candidate,password):
                
                session ['loggedin']= True
                session['username'] = username
                

                flash('you are now logged in','success')
                
                return redirect(url_for('dashboard'))
            else:
                app.logger.info('no match')
        else:
            error = "invalid login"
            return render_template('login.html', error=error)
        cur.close()

    return render_template('login.html')





@app.route('/logout')
def logout():
    session.clear()
    flash('logged out','success')
    return redirect(url_for('login'))
    

class AdminRegisterForm(Form):
    firstName = StringField('', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'First Name'})
    lastName = StringField('', [validators.length(min=3, max=25)], render_kw={'placeholder': 'Last Name'})
    email = StringField('', [validators.DataRequired(), validators.length(min=4, max=25)],
                       render_kw={'placeholder': 'Email'})
    
    mobile = StringField('', [validators.length(min=1, max=15)], render_kw={'placeholder': 'Mobile'})                   
    address= StringField('', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Address'})
    
    password = PasswordField('', [validators.length(min=3)],
                             render_kw={'placeholder': 'Password'})

    admintype = StringField('', [validators.length(min=1, max=15)], render_kw={'placeholder': 'Title'})
    confirmCode = StringField('', [validators.length(min=3, max=25)], render_kw={'placeholder': 'code'})


@app.route('/adminregister', methods=['GET', 'POST'])
#@not_logged_in
def adminregister():
    form = AdminRegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        firstName = form.firstName.data
        lastName = form.lastName.data
        email = form.email.data
        mobile = form.mobile.data
        address = form.address.data
        password = sha256_crypt.encrypt(str(form.password.data))
        admintype = form.admintype.data
        confirmCode = form.confirmCode.data
        

        # Create Cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO admin(firstName,lastName , email, mobile, address, password,admintype,confirmCode) VALUES(%s, %s, %s, %s, %s,%s, %s, %s)",
                    (firstName,lastName , email, mobile, address, password,admintype,confirmCode))

        # Commit cursor
        mysql.connection.commit()

        # Close Connection
        cur.close()

        flash('You are now registered and can login', 'success')

        return redirect(url_for('admin_login'))
    return render_template('adminregister.html', form=form)







##########################################


#@app.route("/")
#@login_required
#def homeauction():
#return redirect(url_for("indexauction"))

@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    # if user reached route via POST (as by submitting a form via POST)
    # Displays items that the user has won in auction
        
    # select all of the user's bids 
    user = session["user_id"]
    bids = db.execute("SELECT * FROM bids WHERE bidder_id = :user", user = user)

    #  return apology("You don't have any open bids!")
    item_ids = []
    for bid in bids:
        item_ids.append(bid["item_id"])
        
    # ensure each item id only appears once 
    items = list(set(item_ids))
    won_items = []
    
    # iterate through items that the user has bid on
    for item_id in items:
        tempDict = dict()
        seller = db.execute("SELECT seller_id FROM items WHERE item_id = :item_id", item_id=item_id)[0]["seller_id"]
        item_status = db.execute("SELECT status FROM items WHERE item_id = :item_id", item_id = item_id)[0]["status"]
        auction_winner = db.execute("SELECT bidder_id FROM bids WHERE item_id = :item_id ORDER BY timestamp DESC LIMIT 1", item_id=item_id)[0]["bidder_id"]
        # if auction is expired and user was the highest bidder, display the item
        if item_status == 0 and auction_winner == user:
            tempDict["charge"] = db.execute("SELECT bid_amount FROM bids WHERE item_id = :item_id ORDER BY timestamp DESC LIMIT 1", item_id=item_id)[0]["bid_amount"]
            tempDict["item_name"] = db.execute("SELECT item_name FROM items WHERE item_id = :item_id", item_id = item_id)[0]["item_name"]
            tempDict["item_id"] = item_id
            tempDict["phoneno"] = db.execute("SELECT * FROM users WHERE user_id=:seller", seller=seller)[0]["phoneno"]
            tempDict["seller_email"] = db.execute("SELECT email from users WHERE user_id = :seller_id", seller_id=seller)[0]["email"]
            won_items.append(tempDict)
            
    # check if user has ever won an auction
    if len(won_items) < 1:
        return apology("You haven't won any items yet!")
        
    # display history of auctions won, and provide link to the seller's phoneno account for payment
    return render_template("history.html", won_items=won_items)
    

@app.route("/indexauction")
@login_required
def indexauction(): 
     # get user id    
    user = session["user_id"]
    
    # query database for 10 items that are currently live
    random_rows = db.execute("SELECT * FROM items WHERE status=:live LIMIT 9", live=1)
    return render_template("indexauction.html", random_rows=random_rows)
    
@app.route("/itm/<int:item_id>", methods=["GET", "POST"])
@login_required
def itm_page(item_id):
    # get user id
    user = session["user_id"]

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # if user clicks bid
        if request.form['btn'] == 'bid':

            if not request.form.get("place_bid"):
                return apology("missing bid")
            
            # convert user input to a float
            try:
                user_bid = float(request.form.get("place_bid"))
            
            # unless they provide invalid input
            except ValueError:
                return apology("invalid bid")
            
            # prevent user from bidding in their own auction
            seller_id = db.execute("SELECT seller_id FROM 'items' WHERE item_id = :itm_id", itm_id=item_id)[0]["seller_id"]
            if user == seller_id:
                return apology("you cannot bid on your own item")
                
            # ensure user provides positive number of shares
            if user_bid <= 0:
                return apology("invalid bid")
            
            # get current winning bid
            row = db.execute("SELECT current_bid FROM 'items' WHERE item_id = :itm_id", itm_id=item_id)
            current_bid = row[0]["current_bid"]
            
            # check if user bid actually tops current winning bid
            if user_bid <= current_bid:
                return apology("invalid bid")
            
            # add bid to database
            db.execute("INSERT INTO 'bids' (bidder_id, item_id, bid_amount) VALUES(:userid, :itm_id, :bid)", userid=user, itm_id=item_id, bid=user_bid)
            
            # update current_bid 
            db.execute("UPDATE 'items' SET current_bid=:bid WHERE item_id=:item_id", bid=user_bid, item_id=item_id)
            
            
            # update total_bids
            total_bids = db.execute("SELECT * FROM items WHERE item_id=:item_id", item_id=item_id)[0]["total_bids"]
            total_bids += 1
            db.execute("UPDATE items SET total_bids = :total_bids WHERE item_id=:item_id", total_bids=total_bids, item_id=item_id)
            
            # flash
            flash("Success")
            
            return redirect(url_for("itm_page", item_id=item_id))
            
        # if user clicked 
        if request.form['btn'] == 'watchlist':
            
            # check if the item is already in the user's watchlist
            row = db.execute("SELECT * FROM watchlist WHERE item_id = :item_id AND user_id = :user_id", item_id=item_id, user_id=user)
            
            # if yes, delete from watchlist
            if len(row) != 0:
                db.execute("DELETE FROM watchlist WHERE item_id = :item_id AND user_id = :user_id", item_id=item_id, user_id=user)
            
            # if not, insert into watchlist
            else:
                db.execute("INSERT INTO watchlist (item_id, user_id) VALUES (:item_id, :user_id)", item_id = item_id, user_id = user) 
        
            return redirect(url_for("watchlist"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        
        item_row = db.execute("SELECT * FROM 'items' WHERE item_id = :itm_id", itm_id=item_id)
        
        item_status = db.execute("SELECT status FROM items WHERE item_id=:itm_id", itm_id=item_id)[0]['status']
        if item_status == 1:
            # get current time
            time_now = datetime.datetime.utcnow()
            
            # get the timestamp of creation from the auction and format
            # in a way that is readable to python's datetime
            f = '%Y-%m-%d %H:%M:%S'
            time_start = datetime.datetime.strptime(item_row[0]["timestamp"], f)

            # delta of time
            elapsed = time_now - time_start

            # if more than established time
            if elapsed > datetime.timedelta(days=item_row[0]['duration']):
                db.execute("UPDATE 'items' SET status=:expired WHERE item_id=:itm_id", expired=0, itm_id=item_id)
        
        # check if user already has the item in his watchlist   
        row = db.execute("SELECT * FROM watchlist WHERE item_id = :item_id AND user_id = :user_id", item_id=item_id, user_id=user)
        
        # if there is a row, it means item is already in watchlist 
        if len(row) != 0:
            watchlist_status = 1
        
        # else, it is not in watchlist
        else: 
            watchlist_status = 0
        
        seller_id=item_row[0]["seller_id"]
        seller_name = db.execute("SELECT username FROM users WHERE user_id = :seller_id", seller_id=seller_id)[0]["username"]
        return render_template("itm.html", item_row=item_row, watchlist_status=watchlist_status, seller_name=seller_name, item_status=item_status)

@app.route("/loginauction", methods=["GET", "POST"])
def loginauction():
    """Log user in."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # ensure username exists and password is correct
        if len(rows) != 1 or not pwd_context.verify(request.form.get("password"), rows[0]["hash"]):
            return apology("invalid username and/or password")

        # remember which user has logged in
        session["user_id"] = rows[0]["user_id"]
        
        flash("Welcome!")
        
        # redirect user to home page
        return redirect(url_for("indexauction"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("loginauction.html")

@app.route("/logoutauction")
def logoutauction():
    """Log user out."""

    # forget any user_id
    session.clear()

    # redirect user to login form
    return redirect(url_for("loginauction"))
    
@app.route("/my_auctions")
@login_required
def my_auctions():
    "Displays items that the user is currently selling."
        
    # select all of the user's auctions 
    user = session["user_id"]
    auctions = db.execute("SELECT * FROM items WHERE seller_id = :user", user = user)
   
    # create list of the items the user is selling
    item_ids = []
    for auction in auctions:
        item_ids.append(auction["item_id"])
        
    # ensure each item id only appears once 
    items = list(set(item_ids))
    current_auctions = []
    for item in items:
        auction_status = db.execute("SELECT status FROM items WHERE item_id=:item_id", item_id=item)[0]["status"]
        if auction_status == 1:
            tempDict = dict()
            tempDict["current_bid"] = db.execute("SELECT current_bid FROM items WHERE item_id = :item_id", item_id=item)[0]["current_bid"]
            tempDict["item_name"] = db.execute("SELECT item_name FROM items WHERE item_id = :item_id", item_id = item)[0]["item_name"]
            tempDict["item_id"] = item
            current_auctions.append(tempDict)

    # render html page with table of currently held stocks
    return render_template("auctions.html", current_auctions=current_auctions)


@app.route("/my_bids")
@login_required

def my_bids():
    "Displays items that the user is currently bidding on."
    user = session["user_id"]
    
    # select all of the user's bids 
    bids = db.execute("SELECT * FROM bids WHERE bidder_id = :user", user = user)

    item_ids = []
    for bid in bids:
        item_ids.append(bid["item_id"])
        
    # ensure each item id only appears once 
    items = list(set(item_ids))
    current_bids = []
    
    # iterate through items, creating a dictionary for each to store relevant data
    for item_id in items:
        tempDict = dict()
        item_status = db.execute("SELECT status FROM items WHERE item_id = :item_id", item_id = item_id)[0]["status"]
        if item_status == 1:
            tempDict["user_last_bid_amount"] = db.execute("SELECT bid_amount FROM bids WHERE item_id = :item_id AND bidder_id = :user ORDER BY timestamp DESC LIMIT 1", item_id = item_id, user = user)[0]["bid_amount"]
            tempDict["current_bid"] = db.execute("SELECT bid_amount FROM bids WHERE item_id = :item_id ORDER BY timestamp DESC LIMIT 1", item_id=item_id)[0]["bid_amount"]
            tempDict["item_name"] = db.execute("SELECT item_name FROM items WHERE item_id = :item_id", item_id = item_id)[0]["item_name"]
            tempDict["item_id"] = item_id
            current_bids.append(tempDict)
    if len(current_bids) == 0:
        return apology("You don't have any open bids!")

    # display user's current bids 
    return render_template("bids.html", current_bids=current_bids)
    
@app.route("/registerauction", methods=["GET", "POST"])
def registerauction():
    """Register user."""
    
    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")
        
        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")
        
        if not request.form.get("email"):
            return apology("must provide email address")
        
        # get user email
        user_email = request.form.get("email")
        
        # ensure he has email
        if '@gmail.com' not in user_email:
            return apology("You Must have email!")
        
        
        # ensure user insert phoneno
        if not request.form.get("phoneno"):
           return apology("must provide phoneno username")
            
        # get phoneno
        phoneno_username = request.form.get("phoneno")
        
        # remove "-" characters from input
        phoneno_username = phoneno_username.replace('@', '');
        
        # query database for username
        rows = db.execute("SELECT * FROM users WHERE user_id = :username OR email = :email", username=request.form.get("username"), email=user_email)
    
        # ensure username or email are already not being used
        if len(rows) == 1:
            return apology("username or email are already being used!")
        
        # ensure user input a password and the same password again
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords are not matching :(")
    
        # if everything is ok, register username and hashed password in our database
        user_id = db.execute("INSERT INTO users (username, hash, email, phoneno) VALUES(:users, :hash, :email, :phoneno)", users=request.form.get("username"), hash=pwd_context.encrypt(request.form.get("password")), email=user_email, phoneno=phoneno_username)
        
        # remember which user has logged in
        session["user_id"] = user_id
        
        # flash success message!
        flash("Registered!")
        
        # redirect user to home page
        return redirect(url_for("indexauction"))
        
    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("registerauction.html")
        

@app.route("/sales")
@login_required
def sales():
    
    # get user session
    user = session["user_id"]
    
    # get user's auctions that are already over
    past_sales = db.execute("SELECT * FROM items WHERE status = :expired AND seller_id = :user", expired=0, user=user)

    
    # if user has not sold anything before, return apology
    if len(past_sales) == 0:
        return apology("You have never sold an item before")
        
  
    
    for sale in past_sales:
        temp = db.execute("SELECT bidder_id from bids WHERE bid_amount = :bid AND item_id = :item_id", bid=sale["current_bid"], item_id=sale["item_id"])[0]["bidder_id"]
        sale["buyer_email"] = db.execute("SELECT email from users WHERE user_id = :user_id", user_id=temp)[0]["email"]
        
    return render_template("sales.html", past_sales=past_sales)

@app.route("/search")
def search():
    """Search for places that match query."""
    
    # check if valid query
    if not request.args.get("q"):
        raise RuntimeError("missing query")
     
    # get q argument passed into search as a get paramenter  
    q = request.args.get("q") + "%"
        
    # select places with postal code or name similar to that passed by argument q
    rows = db.execute("SELECT * FROM items WHERE item_name LIKE :q AND status=:live", q=q, live=1)
    
    # outputs resulting rows as JSON
    return jsonify(rows)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route("/sell",  methods=["GET", "POST"])
@login_required
def sell():
    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # get user session 
        user = session["user_id"]

        # ensure user provides all needed info
        if not request.form.get("name"):
            return apology("must have name")
            
        # ensure user provides stock symbol
        if not request.form.get("description"):
            return apology("must have description")
        
        # ensure user provides start_price
        if not request.form.get("start_bid"):
            return apology("must have starting bid")
            
        # get the form info after checking
        auction_length = int(request.form.get("auction_length"))
        name = request.form.get("name")
        description = request.form.get("description")
        try: 
            start_bid = float(request.form.get("start_bid"))
        except ValueError:
            return apology("start bid must be numeric")
        # prepare to calculate timestamp_end
        difference = datetime.timedelta(days=auction_length)
        time_temp = datetime.datetime.utcnow() + difference
        time_now = time_temp.strftime('%Y-%m-%d %H:%M:%S')
        
        # insert into items database
        db.execute("INSERT INTO items (item_name, seller_id, start_bid, description, current_bid, timestamp_end, duration) VALUES(:name, :seller, :start_bid, :description, :start_bid, :time, :duration)", name=name, seller=user, start_bid=start_bid, description=description, time=time_now, duration=auction_length)

        # get created auction's id
        temp = db.execute("SELECT item_id FROM items WHERE seller_id = :user_id ORDER BY item_id DESC LIMIT 1", user_id=user)
        item_id = temp[0]["item_id"]
        
        item_row = db.execute("SELECT * FROM items WHERE item_id = :itm_id", itm_id=item_id)
        
        '''image file upload'''
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(str(item_id) + '.' + file.filename.rsplit('.', 1)[1])
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        flash("Created Auction Successfully!")
        return redirect(url_for("itm_page", item_id=item_id))
    
    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("sell.html")

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)
 

@app.route("/watchlist", methods=["GET", "POST"])
@login_required
def watchlist():
    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        user = session["user_id"]
        
    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        # get user session
        user = session["user_id"]
        
        # get user's watchlist
        watchlist_entries = db.execute("SELECT * FROM watchlist WHERE user_id = :user", user = user)
        
        # if user has no items in the watchlist return apology
        if len(watchlist_entries) == 0:
            return apology("Your watchlist is empty!")
        
        # else proceed to create his watchlist page
        watchlist_items = []
        for entry in watchlist_entries:
            item_id = entry["item_id"]
            item = db.execute("SELECT * from items WHERE item_id = :item_id", item_id=item_id)
            watchlist_items.append(item)
        return render_template("watchlist.html", watchlist_items=watchlist_items)
        

###### code yeku u-cycle

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True) 
