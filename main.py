from flask import Flask,request,jsonify, session,redirect,render_template,flash,current_app,url_for
from flask_restful import Api,Resource,reqparse,abort,fields,marshal_with
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey,text,or_
from itsdangerous import URLSafeTimedSerializer
from flask_jwt_extended import create_access_token,jwt_required,JWTManager,get_jwt_identity
from flask_cors import CORS
import bcrypt
import uuid
import os
import requests
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from flask_mail import Mail,Message
from datetime import datetime,date,timedelta
import random
from sqlalchemy.ext.mutable import MutableList
from app import db
from Helper import set_service_fee
import geocoder
import stripe
app=Flask(__name__)
CORS(app, supports_credentials=True, resources={r"*": {"origins": "http://localhost:3000"}},allow_headers=["Content-Type", "Authorization"])
jwt=JWTManager(app)
UPLOAD_FOLDER='static/uploads'
ALLOWED_EXTENSIONS={'png','jpg','jpeg'}
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER
load_dotenv()
key=os.getenv("OPENCAGE_API_KEY")
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS
api=Api(app)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///app-database.db'
app.secret_key='secret key'
db=SQLAlchemy(app)
app.config['JWT_SECRET_KEY'] = 'your-secret'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=587
app.config['MAIL_USE_TLS']=True
app.config['MAIL_USERNAME']='bookishservices953@gmail.com'
app.config['MAIL_PASSWORD']='xaph hqjj lzyg iljy'
mail=Mail(app)

def generate_uuid():
    return str(uuid.uuid4())
def generate_reset_token(email):
    serializer=URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email,salt='password-reset-salt')
def verify_reset_token(token,max_age=1800):
    serializer=URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email=serializer.loads(token,salt='password-reset-salt',max_age=max_age)
    except Exception:
        return None
    return email
def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body, sender=app.config['MAIL_USERNAME'])
    mail.send(msg)

class User(db.Model):
    User_id = db.Column(db.String(36), primary_key=True,default=generate_uuid)
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

class Host(db.Model):
    Host_id=db.Column(db.String(36), primary_key=True, default=generate_uuid)
    Review_id=db.Column(db.String(36),nullable=True)
    Member_since=db.Column(db.Date,nullable=False)
    Languages=db.Column(db.JSON,nullable=False)
    Listings=db.Column(db.Integer,nullable=True)
    Properties = db.Column(MutableList.as_mutable(db.JSON), nullable=True)
    User_id=db.Column(db.String(36),db.ForeignKey('user.User_id'),nullable=True)
    
    def __init__(self,Host_id,Review_of_host,Member_since,Languages,Listings,Properties,User_id):
        self.Host_id=Host_id
        self.Review_of_host=Review_of_host
        self.Member_since=Member_since
        self.Languages=Languages
        self.Listings=Listings
        self.Properties=Properties
        self.User_id=User_id

@app.route('/api/register', methods=['POST','GET'])
def register():
   if request.method=='POST':
       data=request.get_json()
       if not data:
           return jsonify({'error':'Invalid JSON'}),400
   
       firstname=data.get('firstName')
       lastname=data.get('lastName')
       email=data.get('email')
       password=data.get('password')
       phone=data.get('phone')

       if User.query.filter_by(email=email).first():
           return jsonify({'error':'User already exists'})
       
       otp=str(random.randint(100000,999999))
       session['registration_data']={
           'firstname':firstname,
           'lastname':lastname,
           'email':email,
           'password':password,
           'phone':phone,
           'otp':otp
       }
       send_email(email,"Verify your email",f"Your OTP is {otp}")
       return jsonify({'message':'OTP sent to your email'}),200
    # if request.method=='GET':
    #     try:
    #         email=session.get('email')
    #         return jsonify({'email':email}),200
    #     except Exception as e:
    #         return jsonify({'error':str(e)}),500

@app.route('/api/verify_otp',methods=['POST','GET'])
def verify_otp():
    if request.method=='POST':
        data=request.get_json()
        entered_otp=data.get('otp')
        reg_data=session.get('registration_data')
        print(reg_data.get('otp'))
        print(entered_otp)
        print("firstname:", reg_data.get('firstname'))
        print("Session data:", session.get('registration_data'))
        if not reg_data:
            return jsonify({'error':'Not data available'}),400
        
        if entered_otp==reg_data['otp']:
            new_user=User(
                firstname=reg_data['firstname'],
                lastname=reg_data['lastname'],
                email=reg_data['email'],
                password=reg_data['password'],
                phone=reg_data['phone']
            )
            db.session.add(new_user)
            db.session.commit()
            session.pop('registration_data',None)
            return jsonify({'message':'User created'}),201
        else:
            return jsonify({'message': 'Invalid OTP. Please try again.'}),401
@app.route('/api/login', methods=['OPTIONS'])
def login_preflight():
    response = current_app.make_default_options_response()
    headers = response.headers

    headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
    headers['Access-Control-Allow-Credentials'] = 'true'
    headers['Access-Control-Allow-Headers'] = 'Content-Type'
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'

    return response

@app.route('/api/login', methods=['POST','GET'])
def api_login():
    if request.method=='POST':
        data=request.get_json()
        email=data.get('email')
        password=data.get('password')
        user=User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['firstname']=user.firstname
            session['email']=user.email
            session['user_id']=user.User_id
            uid=session.get('user_id')
            print("User from DB:", uid)
            access_token=create_access_token(identity=str(user.User_id))
            host=Host.query.filter_by(User_id=uid).first()
            if host:
                session['host_id']=host.Host_id
                print(session['host_id'])
            return jsonify({'access_token':access_token, 'message':'Login successful'}),200
        else:
            return jsonify({'message':'Invalid email or password'}),401

@app.route('/api/reset_request',methods=['POST','GET'])
def reset_request():
    if request.method=='POST':
        data=request.get_json()
        email=data.get('email')
        user=User.query.filter_by(email=email).first()
        try:
            token=generate_reset_token(user.email)
            reset_url=url_for('reset_token',token=token,_external=True)
            send_email(user.email,"Reset your password",f"Click to reset: {reset_url}")
            return jsonify({'message':'sent'}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400

@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_token(token):
    email=verify_reset_token(token)
    if not email:
        flash("The reset link is invalid or has expired.",'danger')
        return redirect('/reset_request')
    if request.method=='POST':
        new_password=request.form['password']
        user=User.query.filter_by(email=email).first()
        user.password=bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.session.commit()
        flash("Your password has been updated. You can now log in.",'success')
        return redirect('http://localhost:3000/login')
    return render_template('reset_password.html')

@app.route('/api/logout', methods=['POST','GET'])
def api_logout():
    if request.method=='GET':
        try:
           session.pop('email', None)
           session.pop('firstname', None)
           return jsonify({'message': 'Logged out successfully'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400




@app.route('/api/dashboard/profile', methods=['POST','GET'])
@jwt_required()
def host_list():
    if request.method=='POST':
        User_id = get_jwt_identity()
        if not User_id:
            return jsonify({'message': 'User not logged in'}), 401
        data = request.get_json()
        Member_since_str = data.get('Member_since')
        Languages_str = data.get('Languages')

        if not Member_since_str or not Languages_str:
            return jsonify({'error': 'Missing required fields'}), 400

        Member_since = datetime.strptime(Member_since_str, '%Y-%m-%d').date()
        Languages = [lang.strip() for lang in Languages_str.split(',')]

        # Check if host already exists
        if Host.query.filter_by(User_id=User_id).first():
            return jsonify({'error': 'Host already there'}), 409

        new_host = Host(
            Host_id=str(uuid.uuid4()),
            Review_of_host=None,
            Member_since=Member_since,
            Languages=Languages,
            Listings=0,
            Properties=[],
            User_id=User_id
        )
        db.session.add(new_host)
        db.session.commit()
        session['Host_id'] = new_host.Host_id

        return jsonify({'status': 'success'})
    
#     except Exception as e:
#         print("ERROR:", str(e))
#         return jsonify({'error': str(e)}), 400
#   # or success page
class PropertyListed(db.Model):
    prop_id=db.Column(db.String(36), primary_key=True, default=generate_uuid)
    prop_type=db.Column(db.String(100),nullable=True)
    listing_name=db.Column(db.String(100),nullable=True)
    Summary=db.Column(db.String(800),nullable=True)
    Coastal_Area=db.Column(db.String(100),nullable=True)
    Accomodates=db.Column(db.Integer,nullable=True)
    Review_id=db.Column(db.String(36),nullable=True)
    photo_url = db.Column(db.String(500), nullable=True)
    latitude = db.Column(db.String(100),nullable=True)
    longitude = db.Column(db.String(100),nullable=True)
    date=db.Column(db.Date,nullable=True)
    status=db.Column(db.String(20),nullable=False,default="unavailable")
    Host_id=db.Column(db.String(56),db.ForeignKey('host.Host_id'),nullable=True)
    def __init__(self,prop_id,prop_type,listing_name,Summary,Coastal_Area,Accomodates,Reviews,photo_url,latitude,longitude,date,status,Host_id):
        self.prop_id=prop_id
        self.prop_type=prop_type
        self.listing_name=listing_name
        self.Summary=Summary
        self.Coastal_Area=Coastal_Area
        self.Accomodates=Accomodates
        self.Reviews=Reviews
        self.photo_url=photo_url
        self.latitude=latitude
        self.longitude=longitude
        self.date=date
        self.status=status
        self.Host_id=Host_id

class RoomsBeds(db.Model):
    rb_id=db.Column(db.String(36), primary_key=True, default=generate_uuid)
    bedrooms=db.Column(db.Integer,nullable=True)
    beds=db.Column(db.Integer,nullable=True)
    bed_type=db.Column(db.String(100),nullable=True)
    bathrooms=db.Column(db.Integer,nullable=True)
    prop_id=db.Column(db.String(36), db.ForeignKey('property_listed.prop_id'), nullable=True)
    kitchens=db.Column(db.Integer,nullable=True)
    def __init__(self,rb_id,bedrooms,beds,bed_type,bathrooms,prop_id,kitchens):
        self.rb_id=rb_id
        self.bedrooms=bedrooms
        self.beds=beds
        self.bed_type=bed_type
        self.bathrooms=bathrooms
        self.prop_id=prop_id
        self.kitchens=kitchens

@app.route('/api/dashboard/property',methods=['POST','GET'])
@jwt_required()
def prop_list():
    if request.method=='POST':
        try:
            data=request.get_json()
            prop_type=data.get('prop_type')
            Coastal_Area=data.get('Coastal_Area')
            Accomodates=data.get('Accomodates')
            listing_name=None
            Summary=None
            photo_url=None
            Reviews=None
            latitude=None
            longitude=None
            date=datetime.date.today()
            status="unavailable"
            prop_id=generate_uuid()
            uid=get_jwt_identity()
            host=Host.query.filter_by(User_id=uid).first()
            Host_id=host.Host_id
            session['host_id']=Host_id
            print(Host_id)
            new_property=PropertyListed(
                prop_id=prop_id,
                prop_type=prop_type,
                listing_name=listing_name,
                Summary=Summary,
                Coastal_Area=Coastal_Area,
                Accomodates=Accomodates,
                photo_url=photo_url,
                Reviews=Reviews,
                latitude=latitude,
                longitude=longitude,
                date=date,
                status=status,
                Host_id=Host_id
            )
            db.session.add(new_property)
            db.session.commit()
            session['prop_id']=prop_id
            rb_id=generate_uuid()
            bedrooms=data.get('bedrooms')
            beds=data.get('beds')
            bed_type=data.get('bed_type')
            bathrooms=data.get('bathrooms')
            kitchens=data.get('kitchens')
            prop_id=session['prop_id']
            new_room=RoomsBeds(
                rb_id=rb_id,
                bedrooms=bedrooms,
                beds=beds,
                bed_type=bed_type,
                bathrooms=bathrooms,
                kitchens=kitchens,
                prop_id=prop_id
            )
            db.session.add(new_room)
            db.session.commit()
            host.Listings=host.Listings+1
            host.Properties.append(prop_id)
            db.session.commit()
            return jsonify({'prop_id':prop_id}),200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.route('/api/dashboard/property/update',methods=['POST','GET'])
@jwt_required()
def prop_update():
    if request.method=='POST':
        try:
            data=request.get_json()
            print(data)
            prop_id=data.get('property_id')
            prop_type=data.get('prop_type')
            Coastal_Area=data.get('Coastal_Area')
            Accomodates=data.get('Accomodates')
            prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
            prop.prop_type=prop_type
            prop.Coastal_Area=Coastal_Area
            prop.Accomodates=Accomodates
            db.session.commit()
            rb=RoomsBeds.query.filter_by(prop_id=prop_id).first()
            bedrooms=data.get('bedrooms')
            beds=data.get('beds')
            bed_type=data.get('bed_type')
            bathrooms=data.get('bathrooms')
            kitchens=data.get('kitchens')
            rb.bedrooms=bedrooms
            rb.beds=beds
            rb.bed_type=bed_type
            rb.bathrooms=bathrooms
            rb.kitchens=kitchens
            db.session.commit()
            return jsonify({'message':'property updated'}),200
        except Exception as e:
            return jsonify({'error': str(e)}), 400



@app.route('/api/dashboard/description',methods=['POST','GET'])
@jwt_required()
def desc():
    if request.method=='POST':
        try:
            User_id=get_jwt_identity()
            data=request.get_json()
            prop_id=session['prop_id']
            listing_name=data.get('listing_name')
            Summary=data.get('Summary')
            result_prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
            result_prop.listing_name=listing_name
            result_prop.Summary=Summary
            db.session.commit()
            return jsonify({'message':'addded successfully'}),200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.route('/api/dashboard/description/update',methods=['POST','GET'])
@jwt_required()
def desc_update():
    if request.method=='POST':
        try:
            data=request.get_json()
            print(data)
            prop_id=data.get('property_id')
            print(prop_id)
            listing_name=data.get('listing_name')
            Summary=data.get('Summary')
            property=PropertyListed.query.filter_by(prop_id=prop_id).first()
            property.listing_name=listing_name
            property.Summary=Summary
            db.session.commit()
            return jsonify({'message':'updated successfully'}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400



class Address(db.Model):
    addr_id=db.Column(db.String(36), primary_key=True, default=generate_uuid)
    addr_line1=db.Column(db.String(100),nullable=True)
    addr_line2=db.Column(db.String(100),nullable=True)
    country=db.Column(db.String(100),nullable=True)
    city=db.Column(db.String(100),nullable=True)
    region=db.Column(db.String(100),nullable=True)
    zip=db.Column(db.String(6),nullable=True)
    prop_id=db.Column(db.String(36),db.ForeignKey('property_listed.prop_id'),nullable=True)

    def __init__(self,addr_id,addr_line1,addr_line2,country,city,region,zip,prop_id):
        self.addr_id=addr_id
        self.addr_line1=addr_line1
        self.addr_line2=addr_line2
        self.country=country
        self.city=city
        self.region=region
        self.zip=zip
        self.prop_id=prop_id

@app.route('/api/dashboard/address',methods=['POST','GET'])
def addr_list():
    if request.method=='POST':
        try:
            data=request.get_json()
            addr_line1=data.get('addr_line1')
            addr_line2=data.get('addr_line2')
            country=data.get('country')
            city=data.get('city')
            region=data.get('region')
            zip=data.get('zip')
            total_addr=addr_line1+" "+addr_line2+" "+city
            url = f"https://api.opencagedata.com/geocode/v1/json?q={total_addr}&key={key}"
            res=requests.get(url)
            map_data=res.json()
            latlng=map_data['results'][0]['geometry']
            lat=latlng['lat']
            lng=latlng['lng']
            lat_str=str(lat)
            lng_str=str(lng)
            print(lat_str)
            print(lng_str)
            prop_id=session['prop_id']
            prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
            prop.latitude=lat_str
            prop.longitude=lng_str
            db.session.commit()
            addr_id=generate_uuid()
            new_addr=Address(addr_id=addr_id,addr_line1=addr_line1,addr_line2=addr_line2,country=country,city=city,region=region,zip=zip,prop_id=prop_id)
            db.session.add(new_addr)
            db.session.commit()
            return jsonify({'message':'address added successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.route('/api/dashboard/address/update',methods=['POST','GET'])
def addr_update():
    if request.method=='POST':
        try:
           data=request.get_json()
           prop_id=data.get('property_id')
           addr=Address.query.filter_by(prop_id=prop_id).first()
           addr.addr_line1=data.get('addr_line1')
           addr.addr_line2=data.get('addr_line2')
           addr.country=data.get('country')
           addr.city=data.get('city')
           addr.region=data.get('region')
           addr.zip=data.get('zip')
           total_addr=data.get('addr_line1')+" "+data.get('addr_line2')+" "+data.get('city')
           url = f"https://api.opencagedata.com/geocode/v1/json?q={total_addr}&key={key}"
           res=requests.get(url)
           map_data=res.json()
           latlng=map_data['results'][0]['geometry']
           lat=latlng['lat']
           lng=latlng['lng']
           lat_str=str(lat)
           lng_str=str(lng)
           print(lat_str)
           print(lng_str)
           prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
           prop.latitude=lat_str
           prop.longitude=lng_str
           db.session.commit()
           return jsonify({'message':'address updated successfully'})
        except Exception as e:
            return jsonify({'error':str(e)}),400
        
class Amenities(db.Model):
    am_id=db.Column(db.String(36), primary_key=True, default=generate_uuid)
    amenities=db.Column(db.JSON,nullable=True)
    safety_features=db.Column(db.JSON,nullable=True)
    prop_id=db.Column(db.String(36),db.ForeignKey('property_listed.prop_id'),nullable=True)

    def __init__(self,am_id,amenities,safety_features,prop_id):
        self.am_id=am_id
        self.amenities=amenities
        self.safety_features=safety_features
        self.prop_id=prop_id

@app.route('/api/dashboard/amenities',methods=['POST','GET'])
@jwt_required()
def amen_list():
    if request.method=='POST':
        try:
            data=request.get_json()
            amenities=[amen.strip() for amen in data.get('amenities').split(',')] 
            safety_features=[safe.strip() for safe in data.get('safety_features').split(',')]
            prop_id=session.get('prop_id')
            print(prop_id)
            am_id=generate_uuid()
            new_am=Amenities(am_id=am_id,amenities=amenities,safety_features=safety_features,prop_id=prop_id)
            db.session.add(new_am)
            db.session.commit()
            return jsonify({'message':'Done and added'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.route('/api/dashboard/amenities/update',methods=['POST','GET'])
@jwt_required()
def amen_update():
    if request.method=='POST':
        try:
            data=request.get_json()
            prop_id=data.get('property_id')
            am=Amenities.query.filter_by(prop_id=prop_id).first()
            amenities=[amen.strip() for amen in data.get('amenities').split(',')] 
            safety_features=[safe.strip() for safe in data.get('safety_features').split(',')]
            am.amenities=amenities
            am.safety_features=safety_features
            db.session.commit()
            return jsonify({'message':'Updated'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.route('/api/dashboard/photo',methods=['POST','GET'])
@jwt_required()
def photo_list():
    if request.method=='POST':
        try:
            if 'photo' not in request.files:
                return jsonify({'error':'No file part'}),400
            file=request.files['photo']
            if file.filename=='':
                return jsonify({'error':'No selected file'}),400
            if file and allowed_file(file.filename):
                filename=secure_filename(file.filename)
                file_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
                file.save(file_path)
                prop_id=session['prop_id']
                property=PropertyListed.query.filter_by(prop_id=prop_id).first()
                property.photo_url=file_path
                db.session.commit()
                return jsonify({'photo_url': property.photo_url})
            else:
                return jsonify({'error':'File type not allowed'}),400
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.route('/api/dashboard/photo/update',methods=['POST','GET'])
@jwt_required()
def photo_update():
    if request.method=='POST':
        try:
            if 'photo' not in request.files:
                return jsonify({'error':'No file part'}),400
            file=request.files['photo']
            if file.filename=='':
                return jsonify({'error':'No selected file'}),400
            if file and allowed_file(file.filename):
                filename=secure_filename(file.filename)
                file_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
                file.save(file_path)
                prop_id=request.form.get('property_id')
                property=PropertyListed.query.filter_by(prop_id=prop_id).first()
                property.photo_url=file_path
                db.session.commit()
                return jsonify({'photo_url': property.photo_url}),200
            else:
                return jsonify({'error':'File type not allowed'}),400
        except Exception as e:
            return jsonify({'error': str(e)}), 400

class Pricing(db.Model):
    price_id=db.Column(db.String(36),primary_key=True,default=generate_uuid)
    nightly_price=db.Column(db.Integer,nullable=False)
    currency=db.Column(db.String,nullable=False)
    weekly_discount_percentage=db.Column(db.Integer,nullable=True)
    monthly_discount_percentage=db.Column(db.Integer,nullable=True)
    Addnl_prices=db.Column(db.JSON,nullable=True)
    prop_id=db.Column(db.String(36),db.ForeignKey('property_listed.prop_id'),nullable=True)

    def __init__(self,price_id,nightly_price,currency,weekly_discount_percentage,monthly_discount_percentage,Addnl_prices,prop_id):
        self.price_id=price_id
        self.nightly_price=nightly_price
        self.currency=currency
        self.weekly_discount_percentage=weekly_discount_percentage
        self.monthly_discount_percentage=monthly_discount_percentage
        self.Addnl_prices=Addnl_prices
        self.prop_id=prop_id

@app.route('/api/dashboard/pricing',methods=['POST','GET'])
@jwt_required()
def price_list():
    if request.method=='POST':
        try:
            price_id=generate_uuid()
            data=request.get_json()
            nightly_price=data.get('nightly_price')
            currency=data.get('currency')
            weekly_discount_percentage=data.get('weekly_discount_percentage')
            monthly_discount_percentage=data.get('monthly_discount_percentage')
            Addnl_prices={
                "cleaning_fee":data.get('cleaning_fee'),
                "addnl_guests":data.get('addnl_guests'),
                "addnl_after":data.get('addnl_after'),
                "security_deposit":data.get('security_deposit'),
                "weekend_pricing":data.get('weekend_pricing')
            }
            prop_id=session['prop_id']
            price_id=generate_uuid()
            Price=Pricing(price_id=price_id,nightly_price=nightly_price,currency=currency,weekly_discount_percentage=weekly_discount_percentage,monthly_discount_percentage=monthly_discount_percentage,Addnl_prices=Addnl_prices,prop_id=prop_id)
            db.session.add(Price)
            db.session.commit()
            session['price_id']=price_id
            return jsonify({'message':'Done pricing'})
        except Exception as e:
            return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/pricing/update',methods=['POST','GET'])
@jwt_required()
def price_update():
    if request.method=='POST':
        try:
            data=request.get_json()
            prop_id=data.get('property_id')
            price=Pricing.query.filter_by(prop_id=prop_id).first()
            price.nightly_price=data.get('nightly_price')
            price.currency=data.get('currency')
            price.weekly_discount_percentage=data.get('weekly_discount_percentage')
            price.monthly_discount_percentage=data.get('monthly_discount_percentage')
            price.Addnl_prices={
                "cleaning_fee":data.get('cleaning_fee'),
                "addnl_guests":data.get('addnl_guests'),
                "addnl_after":data.get('addnl_after'),
                "security_deposit":data.get('security_deposit'),
                "weekend_pricing":data.get('weekend_pricing')
            }
            db.session.commit()
            return jsonify({'message':'Done pricing'})
        except Exception as e:
            return jsonify({'error':str(e)}),400


class Dynamicpricing(db.Model):
    Dyn_price_id=db.Column(db.String(36),primary_key=True,nullable=False)
    Check_in=db.Column(db.Date(),nullable=True)
    Check_out=db.Column(db.Date(),nullable=True)
    Price=db.Column(db.Integer(),nullable=False)
    Min_stay=db.Column(db.Integer(),nullable=True)
    Status=db.Column(db.String(),nullable=False)
    prop_id=db.Column(db.String(36),db.ForeignKey('property_listed.prop_id'),nullable=True)
    
    def __init__(self,Dyn_price_id,Check_in,Check_out,Price,Min_stay,Status,prop_id):
        self.Dyn_price_id=Dyn_price_id
        self.Check_in=Check_in
        self.Check_out=Check_out
        self.Price=Price
        self.Min_stay=Min_stay
        self.Status=Status
        self.prop_id=prop_id

class User_profile(db.Model):
    Profile_id =db.Column(db.String(36),primary_key=True,nullable=True)
    User_id=db.Column(db.String(36),db.ForeignKey('user.User_id'),nullable=True)
    Gender=db.Column(db.String(10),nullable=True)
    Location=db.Column(db.String(100),nullable=True)
    Dob=db.Column(db.Date(),nullable=True)
    Self_Description=db.Column(db.String(500),nullable=True)
    Member_since=db.Column(db.Date,nullable=False)
    Languages=db.Column(db.JSON,nullable=False)
    User_photo_url=db.Column(db.String(200),nullable=True)

    def __init__(self,Profile_id,User_id,Gender,Location,Dob,Self_Description,Member_since,Languages,User_photo_url):
        self.Profile_id=Profile_id
        self.User_id=User_id
        self.Gender=Gender
        self.Location=Location
        self.Dob=Dob
        self.Self_Description=Self_Description
        self.Member_since=Member_since
        self.Languages=Languages
        self.User_photo_url=User_photo_url

@app.route('/api/dashboard/dynamic_pricing',methods=['POST','GET'])
@jwt_required()
def dynamic_pricing():
    if request.method == 'POST':
        try:
           data = request.get_json()
           Dyn_price_id=generate_uuid()
           Check_in = datetime.strptime(data.get('Check_in'), '%Y-%m-%d').date()
           Check_out = datetime.strptime(data.get('Check_out'), '%Y-%m-%d').date()
           Price=data.get('Price')
           Min_stay=data.get('Min_stay')
           Status=data.get('Status')
           prop_id=data.get('id')
           new_dp=Dynamicpricing(Dyn_price_id=Dyn_price_id,Check_in=Check_in,Check_out=Check_out,Price=Price,Min_stay=Min_stay,Status=Status,prop_id=prop_id)
           db.session.add(new_dp)
           db.session.commit()
           return jsonify({'message':'added successfully'}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/lists',methods=['GET','POST'])
@jwt_required()
def listings():
    User_id=get_jwt_identity()
    if request.method == 'GET':
        try:
            which_host=Host.query.filter_by(User_id=User_id).first()
            list=which_host.Listings
            return jsonify({'listings':list}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400
@app.route('/api/dashboard/name',methods=['GET'])
@jwt_required()
def name_user():
    if request.method=='GET':
        user_id=get_jwt_identity()
        user=User.query.filter_by(User_id=user_id).first()
        user_profile=User_profile.query.filter_by(User_id=user_id).first()
        User_photo_url=user_profile.User_photo_url
    return jsonify({'Name':user.firstname,'User_photo':User_photo_url}),200
@app.route('/api/dashboard/user/listings',methods=['GET','POST','PATCH'])
@jwt_required()
def user_listings():
    if request.method == 'POST':
        try:
            page=request.args.get('page',1,type=int)
            per_page=5
            User_id=get_jwt_identity()
            Host_id=session.get('host_id')
            properties=PropertyListed.query.filter_by(Host_id=Host_id).paginate(page=page,per_page=per_page,error_out=False)
            listings=[]
            for prop in properties.items:
                addr=Address.query.filter_by(prop_id=prop.prop_id).first()
                if ( not addr):
                    loc="to be updated"
                else:
                    loc=addr.city
                listings.append({'name':prop.listing_name,'description':prop.Summary,'location':loc,'image':prop.photo_url,'id':prop.prop_id})
            return jsonify({'listings':listings,'total_pages':properties.pages,'current_page':properties.page,'total_items': properties.total}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400
@app.route('/api/dashboard/property/view', methods=['POST'])
@jwt_required()
def view_property():
    try:
        data = request.get_json()
        prop_id = data.get('property')
        print("Requested Property ID:", prop_id)

        prop = PropertyListed.query.filter_by(prop_id=prop_id).first()
        rb = RoomsBeds.query.filter_by(prop_id=prop_id).first()
        addr = Address.query.filter_by(prop_id=prop_id).first()
        am = Amenities.query.filter_by(prop_id=prop_id).first()
        price = Pricing.query.filter_by(prop_id=prop_id).first()
        lat=getattr(prop,'latitude','')
        lng=getattr(prop,'longitude','')
        # Fallbacks if any object is None
        sendData = [{
            'step2': {
                'prop_type': getattr(prop, 'prop_type', ''),
                'Coastal_Area': getattr(prop, 'Coastal_Area', ''),
                'Accomodates': getattr(prop, 'Accomodates', ''),
                'bedrooms': getattr(rb, 'bedrooms', ''),
                'beds': getattr(rb, 'beds', ''),
                'bed_type': getattr(rb, 'bed_type', ''),
                'bathrooms': getattr(rb, 'bathrooms', ''),
                'kitchens': getattr(rb, 'kitchens', '')
            }
        }, {
            'step3': {
                'listing_name': getattr(prop, 'listing_name', ''),
                'Summary': getattr(prop, 'Summary', '')
            }
        }, {
            'step4': {
                'addr_line1': getattr(addr, 'addr_line1', ''),
                'addr_line2': getattr(addr, 'addr_line2', ''),
                'country': getattr(addr, 'country', ''),
                'city': getattr(addr, 'city', ''),
                'region': getattr(addr, 'region', ''),
                'zip': getattr(addr, 'zip', ''),
                'latitude': float(lat),
                'longitude':float(lng),
            }
        }, {
            'step5': {
                'amenities': getattr(am, 'amenities', []),
                'safety_features': getattr(am, 'safety_features', [])
            }
        }, {
            'step6': {
                'photo_url': getattr(prop, 'photo_url', '')
            }
        }, {
            'step7': {
                'nightly_price': getattr(price, 'nightly_price', ''),
                'currency': getattr(price, 'currency', ''),
                'weekly_discount_percentage': getattr(price, 'weekly_discount_percentage', ''),
                'monthly_discount_percentage': getattr(price, 'monthly_discount_percentage', ''),
                'cleaning_fee': (getattr(price, 'Addnl_prices', {}) or {}).get('cleaning_fee', ''),
                'addnl_guests': (getattr(price, 'Addnl_prices', {}) or {}).get('addnl_guests', ''),
                'addnl_after': (getattr(price, 'Addnl_prices', {}) or {}).get('addnl_after', ''),
                'security_deposit': (getattr(price, 'Addnl_prices', {}) or {}).get('security_deposit', ''),
                'weekend_pricing': (getattr(price, 'Addnl_prices', {}) or {}).get('weekend_pricing', '')
            }
        }]

        return jsonify({'listings': sendData}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/dashboard/property/delete',methods=['GET','POST'])
@jwt_required()
def delete_property():
    if request.method=='POST':
        try:
            data=request.get_json()
            prop_id=data.get('property')
            property=PropertyListed.query.filter_by(prop_id=prop_id).first()
            rb=RoomsBeds.query.filter_by(prop_id=prop_id).first()
            addr=Address.query.filter_by(prop_id=prop_id).first()
            am=Amenities.query.filter_by(prop_id=prop_id).first()
            price=Pricing.query.filter_by(prop_id=prop_id).first()
            user_id=get_jwt_identity()
            Host_id=session['host_id']
            print(Host_id)
            host=Host.query.filter_by(Host_id=Host_id).first()
            print(host)
            host.Listings=host.Listings-1
            hp=host.Properties
            hp.remove(prop_id)
            db.session.delete(property)
            db.session.delete(rb)
            if addr:
                db.session.delete(addr)
            if am:
                db.session.delete(am)
            if price:
                db.session.delete(price)
            db.session.commit()
            return jsonify({'message':'Property deleted successfully'}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400
@app.route('/api/dashboard/deleteaddress',methods=['POST','GET'])
def delete_address():
    if request.method=='GET':
        try:
            address=['7a49fcc4-7740-41f2-b79e-da0160d7b101','481a53f7-118e-4f1a-b7e8-21f67187502f','a45ac11c-9dcd-4506-97a5-585e9d8593c9','a067b3dc-b787-4b4b-b7a4-f0b6a856adb2','4fac169c-b024-4915-ab0b-b65c3e1e5470','fe443909-75ae-4822-8899-226bf9b0399b','65b0b784-a2e7-466f-bc7e-62a187886013','a5211693-56a6-492b-ba7c-39f266bbcc82','fcfbe45a-0de6-4f9b-b295-4b8a999f9d0d']
            for addr_id in address:
                addr=Address.query.filter_by(addr_id=addr_id).first()
                db.session.delete(addr)
                db.session.commit()
            return jsonify({'message':'successfully deleted'}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400


@app.route('/api/dashboard/userprofile/viewupdate',methods=['POST','GET'])
@jwt_required()
def user_profile_data():
    if request.method=='GET':
        try:
            user_id=get_jwt_identity()
            user=User.query.filter_by(User_id=user_id).first()
            if user:
                firstname=user.firstname
                lastname=user.lastname
                email=user.email
                phone=user.phone
                userType=user.userType
            profile=User_profile.query.filter_by(User_id=user_id).first()
            if profile:  
                Gender=profile.Gender 
                Location=profile.Location 
                Dob=profile.Dob 
                Self_Description=profile.Self_Description 
                User_photo_url=profile.User_photo_url 
                Member_since=profile.Member_since 
                Languages=profile.Languages 
            else:
                Gender=''
                Location=''
                Dob= ''
                Self_Description=''
                User_photo_url=''
                Member_since=''
                Languages=''
            data={
                'firstname':firstname,
                'lastname':lastname,
                'email':email,
                'phone':phone,
                'userType':userType,
                'Gender':Gender,
                'Location':Location,
                'Dob':Dob,
                'Self_Description':Self_Description,
                'User_photo_url':User_photo_url,
                'Member_since':Member_since,
                'Languages':Languages
                }
            return jsonify(data),200
        except Exception as e:
            return jsonify({'error':str(e)}),400
    if request.method=='POST':
        try:
            data=request.get_json()
            user_id=get_jwt_identity()
            user=User.query.filter_by(User_id=user_id).first()
            if user:
                user.firstname=data.get('firstname')
                user.lastname=data.get('lastname')
                user.email=data.get('email')
                user.phone=data.get('phone')
                user.userType=data.get('userType')
                db.session.commit()
            Member_since_str = data.get('Member_since')
            Languages_str = data.get('Languages')
            if data.get('userType')=='Host':
                host=Host.query.filter_by(User_id=user_id).first()
                if host:
                    host.Member_since=datetime.strptime(Member_since_str, '%Y-%m-%d').date()
                    host.Languages=[lang.strip() for lang in Languages_str.split(',')]
                    db.session.commit()
                else:
                    Member_since = datetime.strptime(Member_since_str, '%Y-%m-%d').date()
                    Languages = [lang.strip() for lang in Languages_str.split(',')]
                    new_host = Host(
                        Host_id=str(uuid.uuid4()),
                        Review_of_host=None,
                        Member_since=Member_since,
                        Languages=Languages,
                        Listings=0,
                        Properties=[],
                        User_id=user_id
                    )
                    db.session.add(new_host)
                    db.session.commit()
                    session['Host_id'] = new_host.Host_id
            profile=User_profile.query.filter_by(User_id=user_id).first()
            if profile:
                profile.Gender=data.get('Gender')
                profile.Location=data.get('Location')
                profile.Dob=datetime.strptime(data.get('Dob'), '%Y-%m-%d').date()
                profile.Self_Description=data.get('Self_Description')
                profile.User_photo_url=data.get('User_photo_url')
                profile.Member_since=datetime.strptime(Member_since_str, '%Y-%m-%d').date()
                profile.Languages=[lang.strip() for lang in Languages_str.split(',')]
                db.session.commit()
            else:
                Gender = data.get('Gender')
                Location = data.get('Location')
                Dob = datetime.strptime(data.get('Dob'), '%Y-%m-%d').date()
                Self_Description = data.get('Self_Description')
                User_photo_url = data.get('User_photo_url')
                Member_since = datetime.strptime(Member_since_str, '%Y-%m-%d').date()
                Languages = [lang.strip() for lang in Languages_str.split(',')]
                Profile_id=generate_uuid()
                new_profile = User_profile(Profile_id=Profile_id,User_id=user_id,Gender=Gender,Location=Location,Dob=Dob,Self_Description=Self_Description,Member_since=Member_since,Languages=Languages,User_photo_url=User_photo_url)
                db.session.add(new_profile)
                db.session.commit()
            return jsonify({'message':'added and updated'}),200
        except Exception as e:
            return jsonify({'message':str(e)}),400
@app.route('/api/dashboard/upload_user_photo', methods=['POST'])
@jwt_required()
def upload_photo():
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo uploaded'}), 400

    photo = request.files['photo']
    filename = secure_filename(photo.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    photo.save(filepath)

    file_url = f"http://localhost:5000/static/uploads/{filename}"
    return jsonify({'url': file_url}), 200

# if request.method == 'GET':
    #     try:
    #         page=request.args.get('page',1,type=int)
    #         per_page=2
    #         data=[]
    #         properties=PropertyListed.query.filter_by(status="available").paginate(page=page,per_page=per_page,error_out=False)
    #         for prop in properties.items:
    #             prop_id=prop.prop_id
    #             addr=Address.query.filter_by(prop_id=prop_id).first()
    #             rb=RoomsBeds.query.filter_by(prop_id=prop_id).first()
    #             price=Pricing.query.filter_by(prop_id=prop_id).first()
    #             data.append({'title':prop.listing_name, 'image':f"http://localhost:5000/{prop.photo_url}",'location':addr.city,'bedrooms':rb.bedrooms,'bathrooms':rb.bathrooms,'price':price.nightly_price,'id':prop_id})
    #         return jsonify({'message':data,'total_pages':properties.pages,'current_page':properties.page,'total_items':properties.total}),200
    #     except Exception as e:
    #         return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/property/card',methods=['POST','GET'])
def property_card():
    try:
        keyword=request.args.get('keyword','',type=str)
        location=request.args.get('location','',type=str)
        min_price=request.args.get('min_price',0.0,type=float)
        max_price=request.args.get('max_price',None,type=float)
        sort_by=request.args.get('sort_by','date_desc',type=str)
        page=request.args.get('page',1,type=int)
        per_page=6
        query=db.session.query(PropertyListed).join(Address,Address.prop_id==PropertyListed.prop_id).join(Pricing,Pricing.prop_id==PropertyListed.prop_id).join(RoomsBeds,RoomsBeds.prop_id==PropertyListed.prop_id)
        if keyword:
            query=query.filter(or_(
                PropertyListed.listing_name.ilike(f'%{keyword}%'),
                Address.city.ilike(f'%{keyword}%'),
                Address.country.ilike(f'%{keyword}%'),
                Address.region.ilike(f'%{keyword}%'),
                RoomsBeds.bedrooms.cast(db.String).ilike(f'%{keyword}%'),
                RoomsBeds.bathrooms.cast(db.String).ilike(f'%{keyword}%')))
        if location:
            query=query.filter(or_(
                Address.city.ilike(f"%{location}%"),
                Address.country.ilike(f"%{location}%"),
                Address.region.ilike(f"%{location}%")))
        query=query.filter(Pricing.nightly_price>=min_price)
        if max_price is not None:
            query=query.filter(Pricing.nightly_price<=max_price)
        sort_options={'price_asc':Pricing.nightly_price.asc(),'price_desc':Pricing.nightly_price.desc(),'date_asc':PropertyListed.date.asc(),'date_desc':PropertyListed.date.desc(),}
        query=query.order_by(sort_options.get(sort_by,PropertyListed.date.desc()))
        paginated=query.paginate(page=page,per_page=per_page,error_out=False)
        listings=[]
        for prop in paginated.items:
            addr=Address.query.filter_by(prop_id=prop.prop_id).first()
            loc=addr.city if addr else "Unknown"
            price=Pricing.query.filter_by(prop_id=prop.prop_id).first()
            rb=RoomsBeds.query.filter_by(prop_id=prop.prop_id).first()
            listings.append({'title':prop.listing_name,'image':f"http://localhost:5000/{prop.photo_url}",'location':addr.city,'bedrooms':rb.bedrooms,'bathrooms':rb.bathrooms,'price':price.nightly_price,'id':prop.prop_id})
        return jsonify({'message':listings,'total_pages':paginated.pages,'current_page':paginated.page,'total_items':paginated.total}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400
@app.route('/api/dashboard/property/details',methods=['POST','GET'])
def property_details():
    if request.method == 'POST':
        try:
            data=request.get_json()
            prop_id=data.get('prop_id')
            prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
            addr=Address.query.filter_by(prop_id=prop_id).first()
            rb=RoomsBeds.query.filter_by(prop_id=prop_id).first()
            am=Amenities.query.filter_by(prop_id=prop_id).first()
            price=Pricing.query.filter_by(prop_id=prop_id).first()
            addnl_prices=price.Addnl_prices
            host_id=prop.Host_id
            host=Host.query.filter_by(Host_id=host_id).first()
            User_id=host.User_id
            user=User.query.filter_by(User_id=User_id).first()
            user_profile=User_profile.query.filter_by(User_id=User_id).first()
            iva_tax=price.nightly_price*0.22
            acc_tax=price.nightly_price*0.12
            data={
                'property_name':prop.listing_name,
                'property_type':prop.prop_type,
                'property_image':f'http://localhost:5000/{prop.photo_url}',
                'Summary':prop.Summary,
                'Accomodates':prop.Accomodates,
                'city':addr.city,
                'region':addr.region,
                'country':addr.country,
                'latitude':float(prop.latitude),
                'longitude':float(prop.longitude),
                'beds':rb.beds,
                'bathrooms':rb.bathrooms,
                'kitchens':rb.kitchens,
                'bedrooms':rb.bedrooms,
                'bed_type':rb.bed_type,
                'amenities':am.amenities,
                'safety_features':am.safety_features,
                'host_fname': user.firstname,
                'host_lname':user.lastname,
                'Member_since':host.Member_since,
                'Languages':host.Languages,
                'Profile_picture':user_profile.User_photo_url,
                'email':user.email,
                'phone':user.phone,
                'service_fee':price.nightly_price,
                'addnl_guest_fee':addnl_prices['addnl_guests'],
                'cleaning_fee':addnl_prices['cleaning_fee'],
                'security_fee':addnl_prices['security_deposit'],
                'iva_tax':iva_tax,
                'acc_tax':acc_tax,
                'weekly_discount':price.weekly_discount_percentage,
                'monthly_discount':price.monthly_discount_percentage
            }
            return jsonify(data),200
        except Exception as e:
            return jsonify({'error':str(e)}),400


class Booking(db.Model):
    Book_id=db.Column(db.String(36),primary_key=True,nullable=False,default=generate_uuid)
    Check_in=db.Column(db.Date(),nullable=False)
    Check_out=db.Column(db.Date(),nullable=False)
    Guests=db.Column(db.Integer(),nullable=False)
    Nights=db.Column(db.Integer(),nullable=True)
    Bill_id=db.Column(db.String(36),nullable=True)
    Prop_id=db.Column(db.String(36),nullable=False)
    User_id=db.Column(db.String(36),db.ForeignKey('user.User_id'),nullable=True)
    status=db.Column(db.String(),nullable=True,default='unpaid')
    def __init__(self,Book_id,Check_in,Check_out,Guests,Nights,Bill_id,Prop_id,User_id):
        self.Book_id=Book_id
        self.Check_in=Check_in
        self.Check_out=Check_out
        self.Guests=Guests
        self.Nights=Nights
        self.Bill_id=Bill_id
        self.Prop_id=Prop_id
        self.User_id=User_id

class Billing(db.Model):
    Bill_id=db.Column(db.String(36),primary_key=True,nullable=False)
    User_id=db.Column(db.String(36),db.ForeignKey('user.User_id'),nullable=True)
    guests=db.Column(db.Integer(),nullable=True)
    nights=db.Column(db.Integer(),nullable=True)
    service_fee=db.Column(db.Integer(),nullable=True)
    addnl_guest_fee=db.Column(db.Integer(),nullable=True)
    security_fee=db.Column(db.Integer(),nullable=True)
    cleaning_fee=db.Column(db.Integer(),nullable=True)
    iva_tax=db.Column(db.Integer(),nullable=True)
    acc_tax=db.Column(db.Integer(),nullable=True)
    discount=db.Column(db.Integer(),nullable=True)
    total=db.Column(db.Integer(),nullable=True)
    prop_id=db.Column(db.String(36),nullable=True)

    def __init__(self,Bill_id,User_id,guests,nights,service_fee,addnl_guest_fee,security_fee,cleaning_fee,iva_tax,acc_tax,discount,total,prop_id):
        self.Bill_id=Bill_id
        self.User_id=User_id
        self.guests=guests
        self.nights=nights
        self.service_fee=service_fee
        self.addnl_guest_fee=addnl_guest_fee
        self.security_fee=security_fee
        self.cleaning_fee=cleaning_fee
        self.iva_tax=iva_tax
        self.acc_tax=acc_tax
        self.discount=discount
        self.total=total
        self.prop_id=prop_id

class Review(db.Model):
    Review_id=db.Column(db.String(36),primary_key=True,nullable=False)
    Prop_id=db.Column(db.String(36),db.ForeignKey('property_listed.prop_id'),nullable=False)
    Host_id=db.Column(db.String(36),nullable=True)
    Message_prop=db.Column(db.String(500),nullable=True)
    Message_host=db.Column(db.String(500),nullable=True)
    Star_prop=db.Column(db.Integer(),nullable=True)
    Star_host=db.Column(db.Integer(),nullable=True)
    Date=db.Column(db.Date(),nullable=True)
    User_id=db.Column(db.String(36),nullable=False)
    Book_id=db.Column(db.String(36),nullable=False)

    def __init__(self,Review_id,Prop_id,Host_id,Message_prop,Message_host,Star_prop,Star_host,Date,User_id,Book_id):
        self.Review_id=Review_id
        self.Prop_id=Prop_id
        self.Host_id=Host_id
        self.Message_prop=Message_prop
        self.Message_host=Message_host
        self.Star_prop=Star_prop
        self.Star_host=Star_host
        self.Date=Date
        self.User_id=User_id
        self.Book_id=Book_id

@app.route('/api/review/posting',methods=['POST','GET'])
@jwt_required()
def review_post():
    try:
        if request.method=='POST':
            data=request.get_json()
            prop_id=data.get('prop_id')
            book_id=data.get('book_id')
            Review_id=generate_uuid()
            prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
            Host_id=prop.Host_id
            Message_prop=data.get('Message_prop')
            Message_host=data.get('Message_host')
            Star_prop=data.get('Star_prop')
            Star_host=data.get('Star_host')
            Date=date.today()
            User_id=get_jwt_identity()
            new_review=Review(Review_id=Review_id,Prop_id=prop_id,Host_id=Host_id,Message_prop=Message_prop,Message_host=Message_host,Star_prop=Star_prop,Star_host=Star_host,Date=Date,User_id=User_id,Book_id=book_id)
            db.session.add(new_review)
            db.session.commit()
            if Message_host or Star_host:
                host=Host.query.filter_by(Host_id=Host_id).first()
                host.Review_id=Review_id
            if Message_prop or Star_prop:
                prop.Review_id=Review_id
            db.session.commit()
            return jsonify({'message':'done successfully'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400
# @app.route('/dashboard/billing',methods=['POST','GET'])
# @jwt_required()
# def bill_list():
#     if request.method=='POST':
#         try:
#             price_id=session['price_id']
#             price=Pricing.query.filter_by(price_id=price_id).first()
#             addnl_price=price.Addnl_prices
#             today=datetime.date.today()
#             day_of_week=today.strftime('%A')
#             per_price=price.nightly_price
#             if (day_of_week=='Saturday' or day_of_week=='Sunday'):
#                 per_price=addnl_price['weekend_pricing']
#             Bill_id=generate_uuid()
#             guests=request.form.get('guests')
#             nights=request.form.get('nights')
#             prop_id=session['prop_id']
#             service_fee=guests*per_price
#             User_id=request.form.get['User_id']
#             addnl_guest_fee=0
#             if (guests>addnl_price['addnl_after']):
#                 g=addnl_price['addnl_after']-guests
#                 addnl_guest_fee=g*addnl_price['addnl_guests']
#             security_fee=addnl_price['security_deposit']
#             cleaning_fee=addnl_price['cleaning_fee']
#             iva_tax=request.form.get('iva_tax')
#             acc_tax=request.form.get('acc_tax')
#             discount=0
#             if (nights>7 and nights<30):
#                 discount=price.weekly_discount_percentage*service_fee
#             elif (nights>30):
#                 discount=price.monthly_discount_percentage*service_fee
#             total=service_fee+addnl_guest_fee+security_fee+cleaning_fee+iva_tax+acc_tax-discount
#             bill=Billing(Bill_id=Bill_id,User_id=User_id,guests=guests,nights=nights,service_fee=service_fee,addnl_guest_fee=addnl_guest_fee,security_fee=security_fee,cleaning_fee=cleaning_fee,iva_tax=iva_tax,acc_tax=acc_tax,discount=discount,total=total,prop_id=prop_id)
#             db.session.add(bill)
#             db.session.commit()
#         except Exception as e:
#             return jsonify({'error':str(e)}),400
# class Dynamicpricing(db.Model):
#     Dyn_price_id=db.Column(db.String(36),nullable=False)
#     Check_in=db.Column(db.Date(),nullable=True)
#     Check_out=db.Column(db.Date(),nullable=True)
#     Price=db.Column(db.Integer(),nullable=False)
#     Min_stay=db.Column(db.Integer(),nullable=True)
#     Status=db.Column(db.String(),nullable=False)
#     prop_id=db.Column(db.String(36),db.ForeignKey('property_listed.prop_id'),nullable=True)
    
#     def __init__(self,Dyn_price_id,Check_in,Check_out,Price,Min_stay,Status,prop_id):
#         Dyn_price_id=Dyn_price_id
#         Check_in=Check_in
#         Check_out=Check_out
#         Price=Price
#         Min_stay=Min_stay
#         Status=Status
#         prop_id=prop_id

@app.route('/api/dashboard/user/booking',methods=['POST','GET'])
def user_booking():
    if request.method=='POST':
        try:
            data=request.get_json()
            email=data.get('email')
            user=User.query.filter_by(email=email).first()
            session['email']=email
            if user:
                mess='Registered'
            else:
                mess='Not registered'
            check_in=data.get('check_in')
            check_out=data.get('check_out')
            guests=data.get('guests')
            nights=data.get('nights')
            prop_id=data.get('property_id')
            print(prop_id)
            session['check_in']=check_in
            print(session['check_in'])
            session['check_out']=check_out
            session['guests']=guests
            session['nights']=nights
            session['prop_id']=prop_id
            print(session['prop_id'])
            return jsonify({'message':mess}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/user/booking/info',methods=['GET','POST'])
@jwt_required()
def user_booking_info():
    if request.method=='GET':
        try:
            email=session.get('email')
            print(email)
            user=User.query.filter_by(email=email).first()
            if user:
                check_in=session.get('check_in')
                check_out=session.get('check_out')
                guests=session.get('guests')
                nights=session.get('nights')
                print(nights)
                prop_id=session.get('prop_id')
                print(prop_id)
                phone=user.phone
                firstname=user.firstname
                lastname=user.lastname
                prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
                listing_name=prop.listing_name
                Photo_url=prop.photo_url
                photo_url=f'http://localhost:5000/{Photo_url}'
                Accomodates=prop.Accomodates
                Summary=prop.Summary
                rb=RoomsBeds.query.filter_by(prop_id=prop_id).first()
                bedrooms=rb.bedrooms
                bathrooms=rb.bathrooms
                bed_type=rb.bed_type
                beds=rb.beds
                kitchens=rb.kitchens
                am=Amenities.query.filter_by(prop_id=prop_id).first()
                amenities=am.amenities
                safety_features=am.safety_features
                addr=Address.query.filter_by(prop_id=prop_id).first()
                addr_line1=addr.addr_line1
                addr_line2=addr.addr_line2
                country=addr.country
                city=addr.city
                region=addr.region
                zip=addr.zip
                data={
                    'email':email,
                    'phone':phone,
                    'firstname':firstname,
                    'lastname':lastname,
                    'check_in':check_in,
                    'check_out':check_out,
                    'guests':guests,
                    'nights':nights,
                    'listing_name':listing_name,
                    'photo_url':photo_url,
                    'Accomodates':Accomodates,
                    'Summary':Summary,
                    'bedrooms':bedrooms,
                    'bathrooms':bathrooms,
                    'bed_type':bed_type,
                    'beds':beds,
                    'kitchens':kitchens,
                    'amenities':amenities,
                    'safety_features':safety_features,
                    'addr_line1':addr_line1,
                    'addr_line2':addr_line2,
                    'country':country,
                    'city':city,
                    'region':region,
                    'zip':zip
                }
                return jsonify(data),200
            else:
                return jsonify({'message':'user doesnt exist'}),400
        except Exception as e:
            return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/user/booking/proceed',methods=['POST','GET'])
@jwt_required()
def proceed_booking():
    try:
        if request.method=='POST':
            data=request.get_json()
            Prop_id=session.get('prop_id')
            email=session.get('email')
            Check_in_str = data.get('check_in')
            Check_out_str = data.get('check_out')
            Check_in = datetime.strptime(Check_in_str, '%Y-%m-%d').date()
            print(Check_in)
            Check_out = datetime.strptime(Check_out_str, '%Y-%m-%d').date()
            Guests=data.get('guests')
            Nights=data.get('nights')
            user=User.query.filter_by(email=email).first()
            User_id=user.User_id
            Book_id=generate_uuid()
            Bill_id=generate_uuid()
            session['Bill_id']=Bill_id
            if session.get('Book_id'):
                Book_id=session.get('Book_id')
                print(Book_id)
                booking=Booking.query.filter_by(Book_id=Book_id).first()
                booking.Check_in=Check_in
                booking.Check_out=Check_out
                booking.Guests=Guests
                booking.Nights=Nights
                session['Book_id']=booking.Book_id
                db.session.commit()
                return jsonify({'message':'booking updated'}),200
            else:
                new_booking=Booking(Book_id=Book_id,Check_in=Check_in,Check_out=Check_out,Guests=Guests,Nights=Nights,Bill_id=Bill_id,Prop_id=Prop_id,User_id=User_id)
                db.session.add(new_booking)
                db.session.commit()
                session.pop('check_in')
                session.pop('check_out')
                session.pop('guests')
                session.pop('nights')
                session['Book_id']=Book_id
                print(session['Book_id'])
                return jsonify({'message':'billing proceed'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/user/billing',methods=['POST','GET'])
@jwt_required()
def bill_list():
    if request.method=='POST':
        try:
            Prop_id=session.get('prop_id')
            price=Pricing.query.filter_by(prop_id=Prop_id).first()
            dynamic_pricings=Dynamicpricing.query.filter_by(prop_id=Prop_id).all()
            for dynamic_pricing in dynamic_pricings:
                print(dynamic_pricing.Check_in)
                print(dynamic_pricing.Check_out)
            price_id=price.price_id
            addnl_price=price.Addnl_prices
            today=date.today()
            day_of_week=today.strftime('%A')
            per_price=price.nightly_price
            if (day_of_week=='Saturday' or day_of_week=='Sunday'):
                per_price=addnl_price['weekend_pricing']
            Bill_id=generate_uuid()
            Book_id=session.get('Book_id')
            book=Booking.query.filter_by(Book_id=Book_id).first()
            service_fee_per_guest=set_service_fee(book.Check_in,book.Check_out,per_price,dynamic_pricings)
            guests=book.Guests
            nights=book.Nights
            prop_id=Prop_id
            service_fee=guests*service_fee_per_guest
            User_id=book.User_id
            addnl_guest_fee=0
            if (guests>addnl_price['addnl_after']):
                g=guests-addnl_price['addnl_after']
                addnl_guest_fee=g*addnl_price['addnl_guests']
            security_fee=addnl_price['security_deposit']
            cleaning_fee=addnl_price['cleaning_fee']
            iva_tax=0.22*service_fee
            acc_tax=0.12*service_fee
            discount=0
            if (nights>=7 and nights<30):
                discount=price.weekly_discount_percentage*service_fee/100
            elif (nights>30):
                discount=price.monthly_discount_percentage*service_fee
            total=service_fee+addnl_guest_fee+security_fee+cleaning_fee+iva_tax+acc_tax-discount
            bill=Billing(Bill_id=Bill_id,User_id=User_id,guests=guests,nights=nights,service_fee=service_fee,addnl_guest_fee=addnl_guest_fee,security_fee=security_fee,cleaning_fee=cleaning_fee,iva_tax=iva_tax,acc_tax=acc_tax,discount=discount,total=total,prop_id=prop_id)
            db.session.add(bill)
            db.session.commit()
            book=Booking.query.filter_by(Book_id=Book_id).first()
            book.Bill_id=Bill_id
            db.session.commit()
            
            return jsonify({'message':'Done and added'}),200
        except Exception as e:
            return jsonify({'error':str(e)}),400
    if request.method=='GET':
        try:
            Book_id=session.get('Book_id')
            print(Book_id)
            book=Booking.query.filter_by(Book_id=Book_id).first()
            Check_in=book.Check_in
            Check_out=book.Check_out
            Guests=book.Guests
            Prop_id=book.Prop_id
            Bill_id=book.Bill_id
            Prop_id=book.Prop_id
            User_id=book.User_id
            bill=Billing.query.filter_by(Bill_id=Bill_id).first()
            service_fee=bill.service_fee
            addnl_guests=bill.addnl_guest_fee
            security_fee=bill.security_fee
            cleaning_fee=bill.cleaning_fee
            iva_tax=bill.iva_tax
            acc_tax=bill.acc_tax
            discount=bill.discount
            total=bill.total
            prop=PropertyListed.query.filter_by(prop_id=Prop_id).first()
            listing_name=prop.listing_name
            Summary=prop.Summary
            Photo_url=prop.photo_url
            photo_url=f'http://localhost:5000/{Photo_url}'
            rb=RoomsBeds.query.filter_by(prop_id=Prop_id).first()
            beds=rb.beds
            bathrooms=rb.bathrooms
            bedrooms=rb.bedrooms
            kitchens=rb.kitchens
            user=User.query.filter_by(User_id=User_id).first()
            email=user.email
            phone=user.phone
            firstname=user.firstname
            lastname=user.lastname
            data={
                'Check_in':Check_in,
                'Check_out':Check_out,
                'Guests':Guests,
                'listing_name':listing_name,
                'Summary':Summary,
                'photo_url':photo_url,
                'beds':beds,
                'bathrooms':bathrooms,
                'bedrooms':bedrooms,
                'kitchens':kitchens,
                'email':email,
                'phone':phone,
                'firstname':firstname,
                'lastname':lastname,
                'service_fee':service_fee,
                'addnl_guests':addnl_guests,
                'security_fee':security_fee,
                'cleaning_fee': cleaning_fee,
                'iva_tax':iva_tax,
                'acc_tax':acc_tax,
                'discount':discount,
                'total':total
            }
            return jsonify(data),200
        except Exception as e:
            return jsonify({'error': str(e)})
@app.route('/api/dashboard/user/bookingbilling/delete',methods=['GET','POST'])
@jwt_required()
def delete_booking_billing():
    try:
        if request.method=='GET':
            Book_id=session.get('Book_id')
            booking=Booking.query.filter_by(Book_id=Book_id).first()
            Bill_id=booking.Bill_id
            bill=Billing.query.filter_by(Bill_id=Bill_id).first()
            db.session.delete(bill)
            db.session.commit()
            db.session.delete(booking)
            db.session.commit()
            return jsonify({'message':'successfully deleted'}),200
        if request.method=='POST':
            data=request.get_json()
            Book_id=data.get('Book_id')
            booking=Booking.query.filter_by(Book_id=Book_id).first()
            Bill_id=booking.Bill_id
            bill=Billing.query.filter_by(Bill_id=Bill_id).first()
            db.session.delete(bill)
            db.session.commit()
            db.session.delete(booking)
            db.session.commit()
            return jsonify({'message':'successfully deleted'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/sidebar/user/bookingbilling/delete',methods=['GET','POST'])
@jwt_required()
def delete_sidebar_booking_billing():
    try:
        if request.method=='POST':
            Book_id=data.get('Book_id')
            booking=Booking.query.filter_by(Book_id=Book_id).first()
            Bill_id=booking.Bill_id
            bill=Billing.query.filter_by(Bill_id=Bill_id).first()
            db.session.delete(bill)
            db.session.commit()
            db.session.delete(booking)
            db.session.commit()
            return jsonify({'message':'successfully deleted'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400


@app.route('/api/dashboard/sidebar/user/booking',methods=['GET','POST'])
@jwt_required()
def booking_sidebar():
    try:
        if request.method=='GET':
            User_id=get_jwt_identity()
            page=request.args.get('page',1,type=int)
            per_page=5
            data=[]
            bookings=Booking.query.filter_by(User_id=User_id).paginate(page=page,per_page=per_page,error_out=False)
            for booking in bookings.items:
                print(booking)
                status=booking.status
                Check_in=booking.Check_in
                Check_out=booking.Check_out
                Bill_id=booking.Bill_id
                Book_id=booking.Book_id
                billing=Billing.query.filter_by(Bill_id=Bill_id).first()
                total=billing.total
                prop_id=booking.Prop_id
                print(prop_id)
                prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
                prop_name=prop.listing_name
                prop_photo=prop.photo_url
                print(prop_photo)
                prop_photo_url=f'http://localhost:5000/{prop_photo}'
                data.append({'Check_in':Check_in,'Check_out':Check_out,'total':total,'status':status,'prop_name':prop_name,'prop_photo':prop_photo_url,'prop_id':prop_id,'Book_id':Book_id})
            return jsonify({'data':data,'total_pages':bookings.pages,'current_page':bookings.page,'total_items':bookings.total}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400
@app.route('/api/dashboard/sidebar/user/booking/viewmore',methods=['GET','POST'])
@jwt_required()
def booking_viewmore():
    try:
        if request.method=='POST':
            User_id=get_jwt_identity()
            moredetails={}
            data=request.get_json()
            prop_id=data['prop_id']
            Book_id=data['Book_id']
            prop=PropertyListed.query.filter_by(prop_id=prop_id).first()
            prop_name=prop.listing_name
            prop_photo=prop.photo_url
            prop_photo_url=f'http://localhost:5000/{prop_photo}'
            rb=RoomsBeds.query.filter_by(prop_id=prop_id).first()
            beds=rb.beds
            bedrooms=rb.bedrooms
            bathrooms=rb.bathrooms
            kitchens=rb.kitchens
            booking=Booking.query.filter_by(Book_id=Book_id).first()
            Check_in=booking.Check_in
            Check_out=booking.Check_out
            status=booking.status
            guests=booking.Guests
            user=User.query.filter_by(User_id=User_id).first()
            user_fname=user.firstname
            user_lname=user.lastname
            email=user.email
            phone=user.phone
            Bill_id=booking.Bill_id
            billing=Billing.query.filter_by(Bill_id=Bill_id).first()
            total=billing.total
            service_fee=billing.service_fee
            addnl_guest_fee=billing.addnl_guest_fee
            security_fee=billing.security_fee
            cleaning_fee=billing.cleaning_fee
            iva_tax=billing.iva_tax
            acc_tax=billing.acc_tax
            discount=billing.discount
            moredetails={'prop_name':prop_name,'prop_photo_url':prop_photo_url,'beds':beds,'bedrooms':bedrooms,'bathrooms':bathrooms,'kitchens':kitchens,'Check_in':Check_in,'Check_out':Check_out,'status':status,'guests':guests,'user_fname':user_fname,'user_lname':user_lname,'email':email,'phone':phone,'service_fee':service_fee,'total':total,'addnl_guest_fee':addnl_guest_fee,'security_fee':security_fee,'cleaning_fee':cleaning_fee,'iva_tax':iva_tax,'acc_tax':acc_tax,'discount':discount}
            return jsonify(moredetails),200
    except Exception as e:
        return jsonify({'error':str(e)}),400

# @app.route('/api/confirm/generatebill',methods=['POST','GET'])
def gen_bill():
    try:
        if request.method=='GET':
            session.pop('Book_id')
            session.pop('prop_id')
            session.pop('email')
            return jsonify({'message':'session cleared'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400
@app.route('/api/delete/booking',methods=['POST','GET'])
def delete_booking_table():
    try:
        if request.method=='POST':
            return {'message':'dropped sucessfully'},200
    except Exception as e:
        return jsonify({'error':str(e)}),400


@app.route('/api/onlytest/property/coordinates',methods=['POST','GET'])
def test_property_coordinates():
    try:
        if request.method=='POST':
            properties=PropertyListed.query.all()
            for prop in properties:
                
                prop_id=prop.prop_id
                addr=Address.query.filter_by(prop_id=prop_id).first()
                total_addr=addr.city+" "+addr.country
                url = f"https://api.opencagedata.com/geocode/v1/json?q={total_addr}&key={key}"
                res=requests.get(url)
                data=res.json()
                latlng=data['results'][0]['geometry']
                lat=latlng['lat']
                lng=latlng['lng']
                lat_str=str(lat)
                lng_str=str(lng)
                print(lat_str)
                print(lng_str)
                prop.latitude=lat_str
                prop.longitude=lng_str
                db.session.commit()
        return jsonify({'message':'done successfully'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400

@app.route('/api/dashboard/check/available',methods=['GET','POST'])
def check_available():
    try:
        if request.method=='POST':
            data=request.get_json()
            prop_id=data['prop_id']
            l_dates=[]
            bookings=Booking.query.filter_by(Prop_id=prop_id).all()
            for booking in bookings:
                n=booking.Check_out-booking.Check_in
                for i in range(n.days):
                    l_dates.append(booking.Check_in+timedelta(days=i))
        return jsonify({'data':l_dates}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400

@app.route('/api/add_dates_and_status',methods=['POST','GET'])
def add_dates_and_status():
    try:
        if request.method=='POST':
            i=0
            properties=PropertyListed.query.all()
            l_date=["2025-02-03","2025-04-12","2025-06-18","2025-05-23"]
            converted_dates = [datetime.strptime(date_str, "%Y-%m-%d").date() for date_str in l_date]
            for prop in properties:
                prop.date=converted_dates[i]
                prop.status="available"
                i=i+1
                db.session.commit()
        return jsonify({'message':'done'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400

stripe.api_key=os.environ.get('STRIPE_SECRET_KEY')
@app.route("/api/create_payment",methods=['POST'])
@jwt_required()
def create_payment():
    try:
        Book_id=session.get('Book_id')
        booking=Booking.query.filter_by(Book_id=Book_id).first()
        Bill_id=booking.Bill_id
        billing=Billing.query.filter_by(Bill_id=Bill_id).first()
        price=billing.total
        checkout_session =stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                'price_data':{
                    'currency':'inr',
                    'product_data':{'name':'Test Product'},
                    'unit_amount':int(price * 100),
                },
                'quantity':1,
            }],
            mode='payment',
            success_url='http://localhost:3000/paymentsuccess',
            cancel_url='http://localhost:3000/paymentfailed'
        )
        return jsonify(id=checkout_session.id),200
    except Exception as e:
        print('error',e)
        return jsonify({'error':str(e)}),400

@app.route("/api/payment/success/process",methods=['POST','GET'])
@jwt_required()
def successful_payment():
    try:
        if request.method=='POST':
            Book_id=session.get('Book_id')
            booking=Booking.query.filter_by(Book_id=Book_id).first()
            booking.status="paid"
            db.session.commit()
            session.pop('email')
            session.pop('Book_id')
            session.pop('prop_id')
            return jsonify({'message':'successful'}),200
    except Exception as e:
        return jsonify({'error':str(e)}),400



with app.app_context():
    # Create all tables
    db.create_all()

    # Add new columns to existing table
    with db.engine.connect() as conn:
        try:
            conn.execute(text('ALTER TABLE property_listed ADD COLUMN latitude STRING'))
        except Exception as e:
            print("Latitude column may already exist:", e)
        try:
            conn.execute(text('ALTER TABLE property_listed ADD COLUMN longitude STRING'))
        except Exception as e:
            print("Longitude column may already exist:", e)
        try:
            conn.execute(text('ALTER TABLE property_listed ADD COLUMN date DATE'))
        except Exception as e:
            print("Date column may already exist:", e)
        try:
            conn.execute(text('ALTER TABLE property_listed ADD COLUMN status STRING'))
        except Exception as e:
            print("Status column may already exist:", e)
if __name__ == '__main__':
    app.run(debug=True)
