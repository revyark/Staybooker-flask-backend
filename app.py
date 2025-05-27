from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_cors import CORS
app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "http://localhost:3000"}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    index = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100))
    phone = db.Column(db.String(10), nullable=False)
    userType=db.Column(db.String(10), default='guest')

    def __init__(self, email, password, firstname, lastname, phone):
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    email = data.get('email')
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400
    user = User(
        email=email,
        password=data.get('password'),
        firstname=data.get('firstName'),
        lastname=data.get('lastName'),
        phone=data.get('phone')
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = user.email
        session['firstname'] = user.firstname
        return jsonify({'message': 'Login successful', 'firstname': user.firstname}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'firstname': user.firstname,
        'lastname': user.lastname,
        'email': user.email,
        'phone': user.phone,
        'message': 'Welcome to your dashboard'
    }), 200

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('email', None)
    session.pop('firstname', None)
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)
