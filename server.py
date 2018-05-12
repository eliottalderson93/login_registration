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
        session['valid'] =True
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
        print('REGEX')
        flash("Invalid Email Address!",'email')
        session['valid'] = False
    else: #check if in DB 
        print('is the email in DB?')
        if (checkDB('email','users',request.form['email'])==True):
            print('email in DB, user cannot use same email')
            flash("Invalid Email Address!",'email')
            session['valid'] = False
        else:
            print('email is not in DB')
    if request.form['password'] != request.form['confirm']:
        flash("Passwords must match",'confirm')
        session['valid'] =False
    if len(request.form['password']) < 8:
        flash("Password too short",'password')
        session['valid'] =False
    #end verification
    print('is this session valid? :',session['valid'])
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
    debugHelp(message='LOGINPOST')
    attempt = request.form['email']
    if not EMAIL_REGEX.match(attempt):
        flash("We don't recognize your email")
        return redirect('/login_page')
    correct_email = checkDB('email','users',attempt)
    print('Check email::',correct_email)
    debugHelp(message='LOGINPOST')
    correct_passwordDB = getDataFromBase('password','email',attempt)
    print('DB_OBJ::',correct_passwordDB)
    print('SUBMIT_PASSWORD::',request.form['password'])
    if (correct_passwordDB == False):   #check if we misqueried the DB
        correct_password = False        #will fail below and redirect
    else:
        print('DB_PASS::', correct_passwordDB[0]['password'])
        correct_password = bcrypt.check_password_hash(correct_passwordDB[0]['password'],request.form['password'])
    debugHelp(message='LOGINPOST')
    print('let me in?',correct_password,correct_email)
    if correct_password and correct_email:
        print('this password matches an email')
        user = getDataFromBase('first_name','email',attempt) #returns a size 1 tuple of dict, access user[0]['key']
        debugHelp(message='BACK_LOGINPOST')
        print('USER_DICT::',user)
        session['first_name'] = user[0]['first_name']
        print('SESSION_FIRST::',session['first_name'])
        return redirect('/success')
    else:
        flash("Invalid Login")
        return redirect('/login_page')
    
@app.route("/success")
def success():
    return render_template('user.html')

@app.route('/clear')
def clear():
    debugHelp(message='LOGOUT')
    session.clear()
    debugHelp(message ='SESSION_EMPTY')
    return redirect('/')

def getDataFromBase(category,identifier,request):
    debugHelp(message ='GETDATAFROMBASE')
    this_request = {'category':category,'identifier':identifier,'request':request}
    print("you are requesting::",this_request)
    query = "SELECT {} FROM users WHERE {}='{}';".format(category.strip("'"),identifier.strip("'"),request.strip("'"))
    print("you are querying::",query)
    result = mysql.query_db(query)
    if not(result):
        print('no such data')
        return False
    else:
        print("you get::", result)
        return result

def createUser(fname,lname,email,pw_hash):
    debugHelp(message ='CREATEUSER')
    print('HASH::',pw_hash)
    data = { "first_name" : fname,"last_name" : lname, "email" : email, "password" : pw_hash}
    query = "INSERT INTO users (first_name,last_name,email,password) VALUES ('{first_name}','{last_name}','{email}','{password}');".format(**data) 
    print('DATA OBJECT::',data)
    print('QUERY STRING::',query)
    user_id = mysql.query_db(query, data)
    return user_id

def hashPassword(pw):
    pw_hash = bcrypt.generate_password_hash(pw)
    pw_hash = str(pw_hash).strip('b').replace("'","")
    return pw_hash
def checkDB(col,table,check_var):
    col = str(col)
    table = str(table)
    check_var = str(check_var)
    data = {'col':col,'table':table,'check_var':check_var}
    q_string = "SELECT "+col+" FROM "+table+';'
    debugHelp(message = 'CHECKDB')
    print('QUERY::',q_string)
    print('DATA::',data)
    col_check = mysql.query_db(q_string) #should return dictionary
    print('DICT_ARRAY::',col_check)
    for i in range(len(col_check)): #elements in dictionary
        print('CHECKING DICT_ARRAY')
        print('ELEMENT::',col_check[i]['{}'.format(col)])
        print('checked against::',check_var)
        if col_check[i]['{}'.format(col)] == data['check_var']:
            print('ELEMENT FOUND')
            return True
    print('ELEMENT NOT FOUND')
    return False

def debugHelp(message = ""):
    print("\n\n-----------------------", message, "--------------------")
    print('REQUEST.FORM:', request.form)
    print('SESSION:', session)

if __name__ == "__main__":
    app.run(debug=True)