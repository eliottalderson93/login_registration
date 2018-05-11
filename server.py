from flask import Flask, render_template, redirect, request, session, flash
import re
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
# create a regular expression object that we can use run operations on

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
app.secret_key = 'KeepItSecretKeepItSafe'
bcrypt = Bcrypt(app)
mysql = connectToMySQL('login_user')

@app.route('/')
def index():
    if 'initial' in session:
        session['initial'] = False
        session['user_id'] = -1
        if session['user_id'] != -1: #user is here
            flash('You are logged in')
            return redirect('/success')
        #print(session)
    else:
        session['initial'] = True #initialize
        session['user_id'] = -1
        session['valid'] =True
        session['first_name'] = 'you little orc' #someone has hacked in if they read this
    if session['initial'] == False:
        pass
    return render_template('code.html')

@app.route("/register", methods=['POST'])
def reserve():     
    if len(request.form['first_name']) < 2:
        flash("First name too short", 'first_name')
        session['valid'] =False
    elif request.form['first_name'].isalpha() == False:
        flash("First name invalid", 'first_name')
        session['valid'] =False
    if len(request.form['last_name']) < 2:
        flash("Last name too short", 'last_name')
        session['valid'] =False
    elif request.form['last_name'].isalpha() == False:
        flash("Last name invalid", 'last_name')
        session['valid'] =False
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!",'email')
        session['valid'] = False
    else: #check if in DB 
        if not (checkDB('email','users',request.form['email'])):
            flash("Invalid Email Address!",'email')
            session['valid'] = False
    if request.form['password'] != request.form['confirm']:
        flash("Passwords must match",'confirm')
        session['valid'] =False
    if len(request.form['password']) < 8:
        flash("Password too short",'password')
        session['valid'] =False
    #end verification
    print(session['valid'])    
    if session['valid'] == True:
        first = request.form['first_name']
        last = request.form['last_name']
        email = request.form['email']
        pw_hash = hashPassword(request.form['password'])
        session['user_id'] = createUser(first,last,email,pw_hash)
        session['first_name'] = first 
        return redirect('/success')
    else:
        return redirect('/')

@app.route("/login_page")
def display():
    return render_template('login.html')

@app.route("/login", methods=['POST'])
def mainframe():
    if not EMAIL_REGEX.match(request.form['email']):
        flash("We don't recognize your email")
        return redirect('/login_page')
    attempt = request.form['email']
    attempt1 = request.form['password']
    correct_email = checkDB('email','users',attempt)
    correct_password = hashPassword(attempt1)
    correct_password = checkDB('password','users',correct_password)
    if correct_password and correct_email:
        user = getDataFromBase(info1 = attempt)
        session['first_name'] = user['first_name']
        return redirect('/success')
    else:
        flash("Invalid Login")
        return redirect('/login_page')

    
@app.route("/success")
def success():
    return render_template('user.html')

@app.route('/clear')
def clear():
    session.clear()
    return redirect('/')

def getDataFromBase(id = -1,info1='default',info2='default',info3='default'):
    query = "SELECT * FROM users WHERE email = %(info1)s;"
    data = {"email" : request.form["email"]}
    result = mysql.query_db(query, data)
    return result
def createUser(fname,lname,email,pw_hash):
    query = "INSERT INTO users (first_name,last_name,email) VALUES (%(fname)s,%(lname)s,%(email)s,%(pw_hash)s);" 
    data = { "first_name" : fname,"last_name" : lname, "email" : email, "password" : pw_hash}
    user_id = mysql.query_db(query, data)
    return user_id
def hashPassword(pw):
    pw_hash = bcrypt.generate_password_hash(pw)
    return pw_hash
def checkDB(col,table,check_var):
    q_string = "SELECT "+str(col)+" FROM "+str(table)+';'
    print(q_string)
    col_check = mysql.query_db(q_string)
    print(col_check)
    for col_var in col_check:
        if col_var == check_var:
            return False
    return True

def debugHelp(message = ""):
    print("\n\n-----------------------", message, "--------------------")
    print('REQUEST.FORM:', request.form)
    print('SESSION:', session)

if __name__ == "__main__":
    app.run(debug=True)




















@app.route('/process', methods=['Post'])
def process():
    if len(request.form['name']) < 1:
       flash("Name cannot be empty!") # just pass a string to the flash function
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
    else:
        flash(f"Success! Your name is {request.form['name']}.") # just pass a string to the flash function
    return redirect('/')

@app.route('/createUser', methods=['POST'])
def create():
    # include some logic to validate user input before adding them to the database!
    # create the hash
    pw_hash = bcrypt.generate_password_hash(request.form['password'])  
    print(pw_hash)  
    # prints something like b'$2b$12$sqjyok5RQccl9S6eFLhEPuaRaJCcH3Esl2RWLm/cimMIEnhnLb7iC'
    # be sure you set up your database so it can store password hashes this long (60 characters)
    query = "INSERT INTO users (username, password) VALUES (%(username)s, %(password_hash)s);"
    # put the pw_hash in our data dictionary, NOT the password the user provided
    data = { "username" : request.form['username'],
             "password_hash" : pw_hash }
    mysql.query_db(query, data)
    # never render on a post, always redirect!
    return redirect("/")

@app.route('/login', methods=['POST'])
def login():
    # see if the username provided exists in the database
    query = "SELECT * FROM users WHERE username = %(username)s;"
    data = {"username" : request.form["username"]}
    result = mysql.query_db(query, data)
    if result:
        # assuming we only have one user with this username, the user would be first in the list we get back
        # of course, for this approach, we should have some logic to prevent duplicates of usernames when we create users
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            session['userid'] = result[0]['id']
            # never render on a post, always redirect!
            return redirect('/success')
    # if we didn't find anything in the database by searching by username or if the passwords don't match,
    # flash an error message and redirect back to a safe route
    flash("You could not be logged in")
    return redirect("/")

if __name__=="__main__":
    app.run(debug=True)

