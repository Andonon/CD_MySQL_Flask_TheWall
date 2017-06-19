'''==================================================================================
This is "The Wall" project, a coding dojo assignment
by: Troy Center, troycenter1@gmail.com, Coding Dojo Python fundamentals, June 2017
=================================================================================='''
#pylint: disable=C0103,C0111

import re
from flask import Flask, render_template, redirect, request, flash, session
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'thewall')
app.secret_key = 'lkjas0llkdj123dlkja089'

def clearsession():
    '''=========================================
    My method to reset session data
    ========================================='''
    print "===8=== Clear Session just ran"
    session['id'] = 0
    session['user_first_name'] = 'Anonymous'
    session['logged_in'] = False


@app.route('/')
def index():
    '''=========================================
    This is the home page of the wall loading,
    with refreshed messages and comments
    ========================================='''
    ##############################################
    #   get info from db
    ##############################################
    messagequery = (
        "select m.message, DATE_FORMAT(m.created_at,'%M %D %Y') as datecreated, u.first_name, "
        "u.last_name,m.id from messages m join users u on m.user_id = u.id order by id desc")
    get_messages = mysql.query_db(messagequery)
    commentsquery = (
        "select c.comment, DATE_FORMAT(c.created_at,'%M %D %Y') as datecreated, u.first_name, "
        "u.last_name,c.message_id from comments c join users u on c.user_id = u.id")
    get_comments = mysql.query_db(commentsquery)
    ##############################################
    # send that query data back to Jinja to render on the page
    ##############################################
    return render_template('index.html', user_messages=get_messages, user_comments=get_comments)

@app.route('/logout')
def logout():
    '''=========================================
    This is the logout route, which resets session data
    and refreshes a false login state.
    ========================================='''
    clearsession()
    session['logged_in'] = False
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''=========================================
    This is the login route, which resets session data
    and refreshes a true login state after validating the user exists.
    ========================================='''
    if request.method == 'POST':
        # set error checking
        error = 0
        # get info from db
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
        #####################################################
        # Check the user info and password
        #####################################################
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
        #####################################################
        # exit on fail to main login page with flash error
        #####################################################
        if request.method == 'GET':
            return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    '''=========================================
    This is the registration page route, which validates user input
    and refreshes a true login state after creating the user and then
    running another db query to call the user ID back into Session Data
    ========================================='''
    #reset error checking
    error = 0
    #if user is just landing on this page, get request to load page.
    if request.method == 'GET':
        return render_template('register.html')
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
        ##############################################
        #  Here we start checking if the user already exists
        ##############################################
        query = "SELECT * from users where email = :email LIMIT 1"
        data = {
            'email': request.form['register_email']
        }
        get_user_reg = mysql.query_db(query, data)
        if get_user_reg:
            flash("Email already exists, please login or use a different email.")
            error += 1
        #prior to the insert, return any errors.
        if error > 0:
            return redirect('/register')
        ##############################################
        #   BCRYPT Hashing
        ##############################################
        pw_hash = bcrypt.generate_password_hash(user_password)
        #  DATABASE INSERT
        query = "INSERT INTO users (first_name, last_name, email, password, \
                 created_at, updated_at) values (:first_name, :last_name, \
                 :email, :password, now(), now())"
        data = {
            'first_name': first_name, 'last_name': last_name, \
            'email': email, 'password': pw_hash}
        #Run insert Query, set session logged in = True, go to wall page
        mysql.query_db(query, data)
        ##############################################
        #   All checks are done, no errors, set some session data here.
        ##############################################
        query = "SELECT * from users where email = :email LIMIT 1"
        data = {
            'email': request.form['register_email']
        }
        get_user_reg = mysql.query_db(query, data)
        #check the email, which should be in the db now, get session data.
        if get_user_reg:
            session['id'] = get_user_reg[0]['id']
            session['user_first_name'] = get_user_reg[0]['first_name']
            session['logged_in'] = True
        else:
            #catchall error, in case the insert failed for some reason.
            flash("Unknown error, db insert failed, could not find user account...")
            return redirect('/login')
        ##############################################
        #  all processing is complete, redirect to "The Wall" as a logged in user!
        ##############################################
        return redirect('/')

@app.route('/postmessage', methods=['GET', 'POST'])
def postmessage():
    '''=========================================
    This is the postmessage route, wich pushes new messages,
    assuming the user is logged in, to the DB, and returns a
    refreshed page with the comments.
    ========================================='''
    ##############################################
    #  set session if not present, which can happen if someone lands
    # on the app for the first time, and tries to post a message.
    #note self: i could make the buttons hidden unless loggedin.
    ##############################################
    try:
        session['logged_in']
    except KeyError:
        session['logged_in'] = False
    
    if session['logged_in']:
        print request.form
        #Insert Query Build
        query = "INSERT INTO messages (message, created_at, updated_at, user_id) \
                                       values (:message, now(), now(), :user_id)"
        data = {
            'message': request.form['message'], 'user_id': session['id']
        }
        #Run insert Query, set session logged in = True, go to wall page
        mysql.query_db(query, data)
        print "Message Added"
        return redirect('/')
    else:
        flash("You can only post messages if you are logged in.")
        flash("Please login, or register before posting. You can register in the login screen.")
        return redirect('/')

@app.route('/postcomment', methods=['GET', 'POST'])
def postcomment():
    '''=========================================
    Same as the message route, but for comments. Assuming user is logged in,
    pushed comments to the DB.
    ========================================='''
    if session['logged_in']:
        print request.form
        #Insert Query Build
        query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) \
                                       values (:comment, now(), now(), :user_id, :message_id)"
        data = {
            'comment': request.form['comment'], 'message_id': request.form['messageid'], \
            'user_id': session['id']
        }
        #Run insert Query, set session logged in = True, go to wall page
        mysql.query_db(query, data)
        print "Comment Added"
        return redirect('/')
    else:
        flash("You can only post comments if you are logged in.")
        flash("Please login, or register before posting. You can register in the login screen.")
        return redirect('/')

app.run(debug=True)
