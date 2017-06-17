#pylint: disable=C0103,C0111
import re
from flask import Flask, render_template, redirect, request, flash, session
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector

def clearsession():
    print "===8=== Clear Session just ran"
    session['id'] = 0
    session['user_first_name'] = 'Anonymous'
    session['logged_in'] = False

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'thewall')
app.secret_key = 'lkjas0llkdj123dlkja089'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        error = 0
        #get the user data from the db based on the email address the user typed
        #There are two fields coming in, username(email), and password
        #doing three checks on the login info... Is blank, or email bad...
        if not request.form['login_email']:
            flash("Username is blank")
            error += 1
        if not request.form['login_password']:
            flash("Password is blank")
            error += 1
        if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",\
                        request.form['login_email']):
            flash("Invalid Email Address detected.")
            error += 1
        if error > 0:
            clearsession()
            return redirect('/login')
        #get info from db
        query = "SELECT * from users where email = :email LIMIT 1"
        data = {
            'email': request.form['login_email']
        }
        get_user = mysql.query_db(query, data)
        #Check the user info and password
        if get_user:
            session['id'] = get_user[0]['id']
            session['user_first_name'] = get_user[0]['first_name']
            hashed_password = get_user[0]['password']
            if bcrypt.check_password_hash(hashed_password, request.form['login_password']):
                session['logged_in'] = True
                return redirect('/')
            else:
                clearsession()
                flash("Login failed... Try again, or register.")
                return redirect('/login')
        else:
            flash("Your username (email) was not found, please try again or register")
            clearsession()
            return redirect('/login')
    else:
        #exit on fail to main login page with flash error
        if request.method == 'GET':
            return render_template('login.html')

@app.route('/logout')
def logout():
    clearsession()
    session['logged_in'] = False
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = 0
    if request.method == 'POST':
#check first name (2 chars, submitted, and letters only)
        first_name = request.form['first_name']
        if not first_name:
            error += 1
            flash("You must supply a First Name")
        elif not first_name.isalpha():
            error += 1
            flash("First Name must contain letters only.")
        elif len(first_name) < 3:
            error += 1
            flash("First Name must contain more than 2 characters.")
#check last name (2 chars, submitted, and letters only)
        last_name = request.form['last_name']
        if not last_name:
            error += 1
            flash("You must supply a Last Name")
        elif not last_name.isalpha():
            error += 1
            flash("Last Name must contain letters only.")
        elif len(last_name) < 3:
            error += 1
            flash("Last Name must contain more than 2 characters.")
#Check the email (present, looks like an email (regex))
        email = request.form['register_email']
        if not email:
            error += 1
            flash("You must supply an email")
        if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
            error += 1
            flash("Invalid Email Address detected.")
#Check the password (both are present, must match, greater than 7 chars. )
        user_password = request.form['user_password']
        confirm_password = request.form['confirm_password']
        if not user_password:
            error += 1
            flash("You must supply a password.")
        elif not confirm_password:
            error += 1
            flash("You must supply a confirm password")
        if user_password != confirm_password:
            error += 1
            flash("Passwords do not match.")
        elif len(user_password) < 8:
            error += 1
            flash("Password must be at least 8 characters long.")
#get info from db
        query = "SELECT * from users where email = :email LIMIT 1"
        data = {
            'email': request.form['register_email']
        }
        get_user_reg = mysql.query_db(query, data)
#check the email if it already exists
        if get_user_reg:
            flash("Email already exists, please login or use a different email.")
            error += 1
#prior to the insert, return any errors.
        if error > 0:
            return redirect('/register')
        else:
            print "==123== Passed user email check"
#Generate password hash with BCrypt
            pw_hash = bcrypt.generate_password_hash(user_password)
#Insert Query Build
            query = "INSERT INTO users (first_name, last_name, email, password, \
                    created_at, updated_at) values (:first_name, :last_name, \
                    :email, :password, now(), now())"
            data = {
                'first_name': first_name, 'last_name': last_name, \
                'email': email, 'password': pw_hash}
#Run insert Query, set session logged in = True, go to wall page
            mysql.query_db(query, data)
            session['logged_in'] = True
            return redirect('/')
    else:
        #exit on fail to main login page with flash error
        if request.method == 'GET':
            return render_template('register.html')

app.run(debug=True)