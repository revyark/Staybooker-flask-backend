from flask import Flask,request,render_template,redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
db=SQLAlchemy(app)
app.secret_key='secret_key'
class User(db.Model):
    index=db.Column(db.Integer,primary_key=True)
    firstname=db.Column(db.String(100),nullable=False)
    lastname=db.Column(db.String(100),nullable=False)
    email=db.Column(db.String(100),nullable=False)
    password=db.Column(db.String(100))
    phone=db.Column(db.String(10),nullable=False)

    def __init__(self,email,password,firstname,lastname,phone):
        self.firstname=firstname
        self.lastname=lastname
        self.phone=phone
        self.email=email
        self.password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt()).decode('utf-8')
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()
@app.route('/')
def index():
    return 'hi'
@app.route('/register',methods=['GET','POST'])

def register():
    if request.method=='POST':
        firstname=request.form['firstname']
        lastname=request.form['lastname']
        email=request.form['email']
        password=request.form['password']
        phone=request.form['phone']
        new_user=User(email=email,password=password,firstname=firstname,lastname=lastname,phone=phone)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])

def login():
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']
        user=User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['firstname']=user.firstname
            session['email']=user.email
            session['password']=user.password
            return redirect('/dashboard')
        else:
            return render_template('login.html',error='Invalid user')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session['firstname']:
        user=User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html',user=user)
    return redirect('/login')
@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')
if  __name__=='__main__':
    app.run(debug=True)
    