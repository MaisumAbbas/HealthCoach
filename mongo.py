from flask import Flask, jsonify, request, json, render_template
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token)
import smtplib, ssl
import bcrypt
from bson.binary import Binary
from gridfs import GridFS
import admin


#for machine learning
import numpy as np
import matplotlib.pyplot as plt #pyplot may not be installed
import pandas as pd
from apyori import apriori

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'healthcoach'
app.config['MONGO_URI'] = 'mongodb://hcAdmin:hc_FYP1@ds155699.mlab.com:55699/healthcoach'
app.config['JWT_SECRET_KEY'] = 'secret'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

CORS(app)

@app.route('/users/register', methods=['POST'])
def register():
    try:
        users = mongo.db.Login_Details
        first_name = request.get_json()['first_name']
        last_name = request.get_json()['last_name']
        email = request.get_json()['email']
        password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf')
        cat = request.get_json()['cat']
        created = datetime.utcnow()
        response = users.find_one({'email' : email})
        if response:
            if (response['email'] == email):
                return jsonify({'result': 'email already registered'})
        else:
            user = users.insert_one({
                'first_name' : first_name,
                'last_name' : last_name,
                'email' : email,
                'password' : password,
                'cat' : cat,
                'created' : created,
            })
            return jsonify({'result': 'registered'})
    except Exception:
        return 'error'

@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.Login_Details
    email = request.get_json()['email']
    password = request.get_json()['password']
    cat = request.get_json()['cat']
    result = ""
    response = users.find_one({'email' : email})
    if response:
        if bcrypt.check_password_hash(response['password'], password) and (response['cat'] == cat):
            access_token = create_access_token(identity = {
            'email': response['email'],
            'cat' : response['cat']
            })
            result = jsonify({"token": access_token})
        else:
            result = jsonify({"error": "Invalid username and password"})
    else:
        result = jsonify({"result" : "No results found"})
    return result
    
@app.route('/users/contact', methods=['POST'])
def contact():
    users = mongo.db.Queries
    name = request.get_json()['name']
    email = request.get_json()['email']
    subject = request.get_json()['subject']
    message = request.get_json()['message']
    created = datetime.utcnow()
    user_id = users.insert_one({
        'name' : name,
        'email' : email,
        'subject' : subject,
        'message' : message,
        'created' : created,
    })
    return jsonify({'result': 'Added'})

@app.route("/users/get_users", methods = ['GET'])
def get_users():
    try:
        db = mongo.db.Login_Details
        result=db.find({},{"first_name": 1, "last_name": 1, "email": 1, "cat": 1})
        users = []
        for user in result:
            users.append({"first_name": user['first_name'], "last_name" : user['last_name'], "email" : user['email'], "cat" : user['cat']})
        return jsonify(users)
    except Exception:
        return 'error'

@app.route("/users/get_query", methods = ['GET'])
def get_query():
    try:
        db = mongo.db.Queries
        result=db.find({},{"name": 1, "email": 1, "subject": 1, "message": 1})
        queries = []
        for query in result:
            queries.append({"name": query['name'], "email" : query['email'], "subject" : query['subject'], "message" : query['message']})
        return jsonify(queries)
    except Exception:
        return 'error'

@app.route("/users/sendEmail", methods = ['POST'])
def sendEmail():
    try:
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = "coachhealth43@gmail.com"  # Enter your address
        receiver_email = request.get_json()['email'] # Enter receiver address
        password = "health1234"
        message = """\
        Subject: Forgotten Password

        Please visit this link to change it. http://localhost:4200/c_pass"""
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        return jsonify({"result" : "Email Sent"})
    except Exception:
        return 'error'

@app.route("/users/sendWarning", methods = ['POST'])
def sendWarning():
    try:
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = "coachhealth43@gmail.com"  # Enter your address
        receiver_email = request.get_json()['user'] # Enter receiver address
        cat = request.get_json()['type'] 
        password = "health1234"
        if (cat == "other"):
            message = """\
            Subject: Issue With Remedy

            Please Review Your Remedies"""
        else:
            message = """\
            Subject: Inappropraite Conduct
            You have been reported by one of the user. Please be careful. Your account can get terminated on receiving more reports like these in future."""
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        complaint = mongo.db.Complaints
        name = request.get_json()['name']
        complaint.delete_one({"name": name})
        return jsonify({"result" : "Email Sent"})
    except Exception:
        return 'error'

@app.route('/users/add_user', methods=['POST'])
def add_user():
    try:
        addUser = mongo.db.Login_Details
        addUserDetails = mongo.db.User_Personal_Details
        first_name = request.get_json()['first_name']
        last_name = request.get_json()['last_name']
        email = request.get_json()['email']
        password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf')
        cat = 'admin'
        address = request.get_json()['address']
        zipCode = request.get_json()['zip']
        city = request.get_json()['city']
        country = request.get_json()['country']
        desc = request.get_json()['desc']
        created = datetime.utcnow()
        user_id = addUser.insert_one({
            'first_name' : first_name,
            'last_name' : last_name,
            'email' : email,
            'password' : password,
            'cat' : cat,
            'created' : created,
        })
        new_user = addUser.find_one({'email': email})
        details = addUserDetails.insert_one({
            '_id': new_user['_id'],
            'address': address,
            'zip': zipCode,
            'city': city,
            'country': country,
            'desc': desc,
            'created': created
        })
        return jsonify({'result': "User Added Successfully"})
    except Exception:
            return 'error'

@app.route("/users/delete_user", methods = ['POST'])
def delete_user():
    try:
        delUser = mongo.db.Login_Details
        delUserDetails = mongo.db.User_Personal_Details
        email = request.get_json()['email']
        target_user = delUser.find_one({'email': email})
        delUser.delete_one({"email": email})
        delUserDetails.delete_one({"_id": target_user['_id']})
        return jsonify({"result" : "Deleted Successfully"})
    except Exception:
        return 'error'

@app.route("/users/changePassword", methods = ['POST'])
def changePassword():
    try:
        db = mongo.db.Login_Details
        newpassword = bcrypt.generate_password_hash(request.get_json()['newPass']).decode('utf')
        oldpassword = request.get_json()['oldPass']
        user = request.get_json()['user']
        response = db.find_one({'email' : user}, {"password": 1})
        if bcrypt.check_password_hash(response['password'], oldpassword):
            status = db.update_one({"email" : user},{"$set": {
                "password" : newpassword
            }})
            return jsonify({"result" : "Password Updated Successfully"})
        else:
            return jsonify({"result" : "Same Password"})
    except Exception:
        return 'error'

@app.route("/users/changeForgotPassword", methods = ['POST'])
def changeForgotPassword():
    try:
        db = mongo.db.Login_Details
        newPass = bcrypt.generate_password_hash(request.get_json()['nPass']).decode('utf')
        user = 'maisum279@gmail.com'
        status = db.update_one({"email" : user},{"$set": {
            "password" : newPass
        }})
        return jsonify({"result" : "Password Updated Successfully"})
    except Exception:
        return 'error'

@app.route("/users/get_complaint", methods = ['GET'])
def get_complaint():
    try:
        db = mongo.db.Complaints
        result=db.find({},{"name": 1, "desc": 1, "user": 1, "type": 1})
        complaint = []
        for com in result:
            complaint.append({"name": com['name'], "desc" : com['desc'], "user" : com['user'], "type" : com['type']})
        return jsonify(complaint)
    except Exception:
        return 'error'

@app.route("/users/ignore_complaint", methods = ['POST'])
def ignore_complaint():
    try:
        complaint = mongo.db.Complaints
        name = request.get_json()['name']
        complaint.delete_one({"name": name})
        return jsonify({"result" : "Ignored Successfully"})
    except Exception:
        return 'error'

@app.route("/users/ignore_query", methods = ['POST'])
def ignore_query():
    try:
        query = mongo.db.Queries
        name = request.get_json()['name']
        email = request.get_json()['email']
        subject = request.get_json()['subject']
        message = request.get_json()['message']
        query.delete_one({"name": name, "email": email, "subject": subject, "message": message})
        return jsonify({"result" : "Ignored Successfully"})
    except Exception:
        return 'error'

@app.route("/users/answer_query", methods = ['POST'])
def answer_query():
    try:
        query = mongo.db.Queries
        name = request.get_json()['name']
        print(name)
        email = request.get_json()['email']
        print(email)
        subject = request.get_json()['subject']
        message = request.get_json()['message']
        query.delete_one({"name": name, "email": email, "subject": subject, "message": message})
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = "coachhealth43@gmail.com"  # Enter your address
        receiver_email = request.get_json()['email'] # Enter receiver address
        password = "health1234"
        ans = request.get_json()['ans']
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, ans)
        return jsonify({"result" : "Email Sent"})
    except Exception:
        return 'error'

@app.route("/users/workDetails", methods = ['POST'])
def workDetails():
    try:
        doctor = mongo.db.Login_Details
        doctorDetails = mongo.db.User_Work_Details
        email = request.get_json()['email']
        result1 = doctor.find_one({'email': email})
        print("f")
        result = doctorDetails.find({'_id': result1['_id']}, {"hospital": 1, "title": 1, "experience": 1, "hospital_address": 1, "hospital_zip": 1, "hospital_city": 1, "hospital_country": 1 ,"hospital_desc": 1})
        data = []
        print("g")
        for query in result:
            data.append({"hospital": query['hospital'], "title": query['title'], "experience": query['experience'] ,"hospital_address": query['hospital_address'], "hospital_zip": query['hospital_zip'], "hospital_city": query['hospital_city'], "hospital_country": query['hospital_country'], "hospital_desc": query['hospital_desc']})
        print("h")
        print(data)
        return jsonify(data)
    except Exception:
        return 'error'

@app.route("/users/saveDoctorData", methods = ['POST'])
def saveDoctorData():
    try:
        doctor = mongo.db.Login_Details
        doctorPersonalDetails = mongo.db.User_Personal_Details
        doctorWorkDetails = mongo.db.User_Work_Details
        email = request.get_json()['email']
        address = request.get_json()['address']
        age = request.get_json()['age']
        city = request.get_json()['city']
        country = request.get_json()['country']
        zipCode = request.get_json()['zip']
        desc = request.get_json()['desc']
        hospital = request.get_json()['hospital']
        title = request.get_json()['title']
        experience = request.get_json()['experience']
        hospital_address = request.get_json()['hospital_address']
        hospital_city = request.get_json()['hospital_city']
        hospital_country = request.get_json()['hospital_country']
        hospital_zip = request.get_json()['hospital_zip']
        hospital_desc = request.get_json()['hospital_desc']
        created = datetime.utcnow()
        act = doctor.find_one({"email": email})
        act2 = doctorPersonalDetails.find({"_id" : act['_id']}).count()
        if act2 == 0:
            act2 = doctorPersonalDetails.insert_one({
                "_id": act['_id'],
                "address": address,
                "age": age,
                "city": city,
                "country": country,
                "zip": zipCode,
                "desc" : desc,
                "created" : created
        })
        else:
            act2 = doctorPersonalDetails.update_one({"_id" : act['_id']},{"$set": {
                "address": address,
                "age": age,
                "city": city,
                "country": country,
                "zip": zipCode,
                "desc" : desc,
                "created" : created
            }})
        act3 = doctorWorkDetails.find({"_id" : act['_id']}).count()
        if act3 == 0:
            act3 = doctorWorkDetails.insert_one({
                "_id": act['_id'],
                "hospital": hospital,
                "title": title,
                "experience": experience,
                "hospital_address": hospital_address,
                "hospital_city": hospital_city,
                "hospital_country": hospital_country,
                "hospital_zip": hospital_zip,
                "hospital_desc": hospital_desc,
                "created" : created
        })
        else:
            act3 = doctorWorkDetails.update_one({"_id" : act['_id']},{"$set": {
                "hospital": hospital,
                "title": title,
                "experience": experience,
                "hospital_address": hospital_address,
                "hospital_city": hospital_city,
                "hospital_country": hospital_country,
                "hospital_zip": hospital_zip,
                "hospital_desc": hospital_desc,
                "created" : created
            }})
        return jsonify({"result" : "Data Updated Successfully"})
    except Exception:
        return 'error'

@app.route("/users/get_request", methods = ['POST'])
def get_request():
    try:
        db = mongo.db.Online_Consultation
        sender = request.get_json()['email']
        result = db.find({"receiver": sender}, {"sender": 1, "receiver": 1, "meds": 1, "problem": 1, "age": 1, "days": 1, "other": 1})
        requests = []
        for dr in result:
            requests.append({"sender": dr['sender'], "receiver" : dr['receiver'], "meds": dr['meds'], "problem": dr['problem'], "age": dr['age'], "days": dr['days'], "other": dr['other']})
        return jsonify(requests)
    except Exception:
        return 'error'

@app.route("/users/patientRequestData", methods = ['POST'])
def patientRequestData():
    try:
        doctor = mongo.db.Online_Consultation
        sender = request.get_json()['sender']
        receiver = request.get_json()['receiver']
        result = doctor.find({'receiver': sender, 'sender': receiver}, {"meds": 1, "problem": 1, "age": 1, "days": 1, "other": 1})
        data = []
        for query in result:
            data.append({"meds": query['meds'], "problem": query['problem'], "age": query['age'], "days": query['days'], "other": query['other']})
        print(data)
        print("k")
        return jsonify(data)
    except Exception:
        return 'error'

@app.route("/users/delPatientRequestData", methods = ['POST'])
def delPatientRequestData():
    try:
        doctor = mongo.db.Online_Consultation
        sender = request.get_json()['sender']
        print(sender)
        receiver = request.get_json()['receiver']
        print(receiver)
        meds = request.get_json()['meds']
        problem = request.get_json()['problem']
        age = request.get_json()['age']
        days = request.get_json()['days']
        other = request.get_json()['other']
        result = doctor.delete_one({'sender': receiver, 'receiver': sender, "meds": meds, "problem": problem, "age": age, "days": days, "other": other})
        return jsonify({"result" : "Deleted Successfully"})
    except Exception:
        return 'error'

@app.route("/users/contactPat", methods = ['POST'])
def contactPat():
    try:
        prescribe = mongo.db.Prescribe_Medicine
        diagnosis = mongo.db.Diagnosis
        cause = request.get_json()['illness']
        print(cause)
        medicines = request.get_json()['meds']
        print(medicines)
        other = request.get_json()['other']
        print(other)
        sender = request.get_json()['sender']
        print(sender)
        receiver = request.get_json()['receiver']
        print(receiver)
        created = datetime.utcnow()
        print("F")
        status = diagnosis.insert_one({
            "sender": sender,
            "receiver": receiver,
            "cause": cause,
            "medicines" : medicines,
            "other": other,
            "created": created
        })
        check = prescribe.find({"cause": cause, "medicines": medicines}).count()
        if check == 0:
            act = prescribe.insert_one({
                "cause": cause,
                "medicines": medicines,
                "prescription": 1
            })
        else:
            pres = prescribe.find_one({"cause": cause, "medicines": medicines}, {"prescription": 1})
            act = prescribe.update_one({"cause": cause, "medicines": medicines},{"$set": {
                "prescription": pres['prescription']+1
            }})
        return jsonify({"result" : "Prescription Sent Successfully"})
    except Exception:
        return 'error'

@app.route("/users/get_doctors", methods = ['GET'])
def get_doctors():
    try:
        db = mongo.db.Login_Details
        db2 = mongo.db.User_Work_Details
        result = db.find({'cat': 'doctor'}, {"first_name": 1, "last_name": 1, "email": 1})
        doctors = []
        for dr in result:
            doctors.append({"first_name": dr['first_name'], "last_name" : dr['last_name'], "email": dr['email']})
        return jsonify(doctors)
    except Exception:
        return 'error'

@app.route("/users/get_doctors_title", methods = ['GET'])
def get_doctors_title():
    try:
        db = mongo.db.User_Work_Details
        db2 = mongo.db.User_Work_Details
        result = db.find({}, {"title": 1})
        titles = []
        for dr in result:
            titles.append({"title": dr['title']})
        return jsonify(titles)
    except Exception:
        return 'error'

@app.route("/users/getPatientData", methods = ['POST'])
def getPatientData():
    try:
        patient = mongo.db.Login_Details
        email = request.get_json()['email']
        result = patient.find({'email': email}, {"first_name": 1, "last_name": 1, "email": 1})
        data = []
        for query in result:
            data.append({"first_name": query['first_name'], "last_name": query['last_name'], "email": query['email']})
        return jsonify(data)
    except Exception:
        return 'error'

@app.route("/users/getPatientDetails", methods = ['POST'])
def getPatientDetails():
    try:
        patient = mongo.db.Login_Details
        patientDetails = mongo.db.User_Personal_Details
        email = request.get_json()['email']
        result1 = patient.find_one({'email': email})
        result = patientDetails.find({'_id': result1['_id']}, {"address": 1, "age": 1, "city": 1, "country": 1, "zip": 1, "desc": 1})
        data = []
        for query in result:
            data.append({"address": query['address'], "age": query['age'], "city": query['city'], "country": query['country'], "zip": query['zip'], "desc": query['desc']})
        return jsonify(data)
    except Exception:
        return 'error'

@app.route("/users/savePatientData", methods = ['POST'])
def savePatientData():
    try:
        patient = mongo.db.Login_Details
        patientDetails = mongo.db.User_Personal_Details
        email = request.get_json()['email']
        address = request.get_json()['address']
        age = request.get_json()['age']
        city = request.get_json()['city']
        country = request.get_json()['country']
        zipCode = request.get_json()['zip']
        desc = request.get_json()['desc']
        created = datetime.utcnow()
        act = patient.find_one({"email": email})
        act2 = patientDetails.find({"_id" : act['_id']}).count()
        if act2 == 0:
            act2 = patientDetails.insert_one({
            "_id": act['_id'],
            "address": address,
            "age": age,
            "city": city,
            "country": country,
            "zip": zipCode,
            "desc" : desc,
            "created" : created
        })
        else:
            act2 = patientDetails.update_one({"_id" : act['_id']},{"$set": {
                "address": address,
                "age": age,
                "city": city,
                "country": country,
                "zip": zipCode,
                "desc" : desc,
                "created" : created
            }})
        return jsonify({"result" : "Data Updated Successfully"})
    except Exception:
        return 'error'

@app.route("/users/get_meds", methods = ['GET'])
def get_meds():
    try:
        db = mongo.db.Prescribe_Medicine
        result = db.find({},{"cause": 1, "medicines": 1, "prescription": 1})
        medicine = []
        for med in result:
            medicine.append({"cause": med['cause'], "medicines" : med['medicines'], "prescription": med['prescription']})
        return jsonify(medicine)
    except Exception:
        return 'error'

@app.route("/users/contactDoctor", methods = ['POST'])
def contactDoc():
    try:
        diagnosis = mongo.db.Online_Consultation
        sender = request.get_json()['sender']
        receiver = request.get_json()['receiver']
        meds = request.get_json()['meds']
        problem = request.get_json()['problem']
        age = request.get_json()['age']
        days = request.get_json()['days']
        other = request.get_json()['other']
        created = datetime.utcnow()
        status = diagnosis.insert_one({
            "sender" : sender,
            "receiver" : receiver,
            "meds" : meds,
            "problem" : problem,
            "age": age,
            "days": days,
            "other": other,
            "created": created
        })
        return jsonify({"result" : "Diagnose Request Sent Successfully"})
    except Exception:
        return 'error'

@app.route("/users/patientPrescriptionData", methods = ['POST'])
def patientPrescriptionData():
    try:
        doctor = mongo.db.Diagnosis
        sender = request.get_json()['sender']
        print(sender)
        receiver = request.get_json()['receiver']
        print(receiver)
        result = doctor.find({'receiver': receiver, 'sender': sender}, {"cause": 1, "medicines": 1, "other": 1})
        data = []
        for query in result:
            data.append({"cause": query['cause'], "medicines": query['medicines'], "other": query['other']})
        print(data)
        return jsonify(data)
    except Exception:
        return 'error'

#report doctor is in doctor.py as the email is same

@app.route("/users/get_cause", methods = ['GET'])
def get_cause():
    try:
        db = mongo.db.Symptoms
        result=db.find({},{"cause": 1, "symptoms": 1})
        #result=db.find({},{"cause": 1, "symptoms": 1})
        symptom = []
        for sym in result:
            symptom.append({"cause": sym['cause'], "symptoms" : sym['symptoms']})
        return jsonify(symptom)
    except Exception:
        return 'error'

@app.route("/users/getPres", methods = ['POST'])
def getPres():
    try:
        db = mongo.db.Diagnosis
        sender = request.get_json()['sender']
        receiver = request.get_json()['receiver']
        result=db.find({"sender": sender, "receiver": receiver},{"sender": 1, "receiver": 1, "created": 1})
        symptom = []
        for sym in result:
            symptom.append({"sender": sym['sender'], "receiver" : sym['receiver'], "created" : sym['created']})
        return jsonify(symptom)
    except Exception:
        return 'error'


@app.route("/users/add_remedy", methods = ['POST'])
def add_remedy():
    try:
        remedy = mongo.db.Home_Remedies
        name = request.get_json()['name']
        desc = request.get_json()['desc']
        user = request.get_json()['user']
        created = datetime.utcnow()
        status = remedy.insert_one({
            "name" : name,
            "desc" : desc,
            "user" : user,
            "created" : created
        })
        return jsonify({"result" : "Remedy Added Successfully"})
    except Exception:
        return 'error'

@app.route("/users/delete_remedy", methods = ['POST'])
def delete_remedy():
    try:
        remedy = mongo.db.Home_Remedies
        name = request.get_json()['name']
        remedy.delete_one({"name": name})
        return jsonify({"result" : "Deleted Successfully"})
    except Exception:
        return 'error'

@app.route("/users/update_remedy", methods = ['POST'])
def update_remedy():
    try:
        remedy = mongo.db.Home_Remedies
        name = request.get_json()['name']
        desc = request.get_json()['desc']
        created = datetime.utcnow()
        status = remedy.update_one({"name" : name},{"$set": {
            "desc" : desc,
            "created" : created
        }})
        return jsonify({"result" : "Remedy Updated Successfully"})
    except Exception:
        print ("exception error")
        return 'error'

@app.route("/users/get_remedy", methods = ['GET'])
def get_remedy():
    try:
        db = mongo.db.Home_Remedies
        result=db.find({},{"name": 1, "desc": 1})
        remedy = []
        for rem in result:
            remedy.append({"name": rem['name'], "desc" : rem['desc']})
        return jsonify(remedy)
    except Exception:
        return 'error'

@app.route("/users/getUserRemedy", methods = ['POST'])
def getUserRemedy():
    try:
        db = mongo.db.Home_Remedies
        user = request.get_json()['user']
        result=db.find({'user': user},{"name": 1, "desc": 1})
        remedy = []
        for rem in result:
            remedy.append({"name": rem['name'], "desc" : rem['desc']})
        return jsonify(remedy)
    except Exception:
        return 'error'


@app.route("/users/report_remedy", methods = ['POST'])
def report_remedy():
    try:
        remedy = mongo.db.Home_Remedies
        complaint = mongo.db.Complaints
        name = request.get_json()['name']
        created = datetime.utcnow()
        found = remedy.find_one({"name": name})
        put = complaint.insert_one({
            "name" : found['name'],
            "desc" : found['desc'],
            "user" : found['user'],
            "type" : "other",
            "created" : created
        })
        return jsonify({"result" : "Reported Successfully"})
    except Exception:
        return 'error'

@app.route("/users/search_remedy", methods = ['POST'])
def search_remedy():
    try:
        remedy = mongo.db.Home_Remedies
        search = request.get_json()['search']
        status = remedy.find({},{"$elemMatch": {
            "name" : search
        }})
        found = []
        for rem in status:
            found.append({"name": rem['search']})
        return jsonify(found)
    except Exception:
        print ("exception error")
        return 'error'

@app.route("/users/sendFeedback", methods = ['POST'])
def sendFeedback():
    try:
        feed = mongo.db.Feedback
        feedback = request.get_json()['feedback']
        created = datetime.utcnow()
        status = feed.insert_one({
            "feedback" : feedback, 
            "created" : created
        })
        return jsonify({"result" : "Feedback Sent"})
    except Exception:
        return 'error'

@app.route("/users/get_diagnosis", methods = ['POST'])
def get_diagnosis():
    try:
        remedy = mongo.db.Home_Remedies
        med = mongo.db.Prescribe_Medicine
        diagnose = mongo.db.Report
        user = request.get_json()['user']
        illness = request.get_json()['illness']
        print(illness)
        result1 = remedy.find({'name': illness}, {"desc": 1}).count
        result2 = med.find({"cause": illness}, {"medicines": 1}).count
        result3 = remedy.find({'name': illness}, {"desc": 1})
        result4 = med.find({"cause": illness}, {"medicines": 1})
        created = datetime.utcnow()
        if (result1 == 0 and result2 != 0):
            status = diagnose.insert_one({
                "user" : user,
                "illness" : illness,
                "remedy" : '',
                "medicine": result4['medicines'],
                "created" : created
            })
        elif (result1 != 0 and result2 == 0):
            status = diagnose.insert_one({
                "user" : user,
                "illness" : illness,
                "remedy" : result3['desc'],
                "medicine": '',
                "created" : created
            })
        elif (result1 == 0 and result2 == 0):
            status = diagnose.insert_one({
                "user" : user,
                "illness" : illness,
                "remedy" : result3['desc'],
                "medicine": result4['medicines'],
                "created" : created
            })
        else:
            status = diagnose.insert_one({
                "user" : user,
                "illness" : illness,
                "remedy" : '',
                "medicine": '',
                "created" : created
            })
        return jsonify({"result" : "Diagnosis Successful"})
    except Exception:
        return 'error'

@app.route("/users/get_report", methods = ['POST'])
def get_report():
    try:
        db = mongo.db.Report
        user = request.get_json()['user']
        result=db.find({'user': user},{"user": 1, "illness": 1, "remedy": 1, "medicine": 1, "created": 1})
        reports = []
        for rep in result:
            reports.append({"user": rep['user'], "illness" : rep['illness'], "remedy": rep['remedy'], "medicine": rep['medicine'], "created": rep['created']})
        #db = mongo.db.medRep
        #Illness = request.get_json()['illness']
        #result = db.find({'Illness': Illness}, {"Illness": 1, "Description": 1, "Symptoms": 1, "What-to-do": 1, "Remedy": 1})
        #reports = []
        #for rep in result:
        #    reports.append({"Illness": rep['Illness'] ,"Description": rep['Description'], "Symptoms": rep['Symptoms'], "What-to-do": rep['What-to-do'], "Remedy": rep['Remedy'] })
        return jsonify(reports)
    except Exception:
        return 'error'

@app.route("/users/view_report", methods = ['POST'])
def view_report():
    try:
        db = mongo.db.medRep
        Illness = request.get_json()['Illness']
        result = db.find({'Illness': Illness}, {"Illness": 1, "Description": 1, "Symptoms": 1, "What_to_do": 1, "Remedy": 1})
        reports = []
        for rep in result:
            reports.append({"Illness": rep['Illness'], "Description": rep['Description'], "Symptoms": rep['Symptoms'], "What_to_do": rep['What_to_do'], "Remedy": rep['Remedy']})
        return jsonify(reports)
    except Exception:
        return 'error'

@app.route("/users/reportComplaint", methods = ['POST'])
def reportComplaint():
    try:
        db = mongo.db.Login_Details
        complaint = mongo.db.Complaints
        name = request.get_json()['name']
        user = request.get_json()['email']
        desc = request.get_json()['message']
        created = datetime.utcnow()
        print("G")
        found = db.find_one({"email": user})
        print("H")
        put = complaint.insert_one({
            "name" : found['first_name'],
            "desc" : desc,
            "user" : user,
            "type" : found['cat'],
            "created" : created
        })
        return jsonify({"result" : "Reported Successfully"})
    except Exception:
        return 'error'

@app.route("/users/deleteAccount", methods = ['POST'])
def deleteAccount():
    try:
        delUser = mongo.db.Login_Details
        delUserDetails = mongo.db.User_Personal_Details
        email = request.get_json()['email']
        target_user = delUser.find_one({'email': email})
        delUser.delete_one({"email": email})
        delUserDetails.delete_one({"_id": target_user['_id']})
        return jsonify({"result" : "Deleted Successfully"})
    except Exception:
        return 'error'

@app.route("/users/upload", methods=['POST'])
def upload():
    try:
        pic = mongo.db.Pictures
        print("D")
        email = request.get_json()['email']
        file = request.get_json()['file']
        print("S")
        print(file)
        put = pic.insert_one({
            #"email": email,
            "file": file
        })
        return jsonify({"result" : "Image Upload Successful"})
    except Exception:
        return 'error'

@app.route("/users/addDisease", methods=['POST'])
def addDisease():
    try:
        sym = mongo.db.Symptoms
        cause = request.get_json()['cause']
        symptoms = request.get_json()['symptoms']
        status = sym.insert_one({
            "cause" : cause,
            "symptoms" : symptoms
        })
        return jsonify({"result" : "Disease Added Successfully"})
    except Exception:
        return 'error'

@app.route("/users/getSymptoms", methods=['POST'])
def getSymptoms():
    try:
        email = request.get_json()['email']
        
        # user Input symptoms list
        user_input_symptoms = request.get_json()['symptoms'];
        #print("Must Enter 3 Symptoms to predict some Causes by this Algorithm.");
        #for e in range(0,3):
        #    user_input_symptoms.append(str(input("Enter Symptom %i: "%(e+1))));

        # print("user_input_symptoms: ",user_input_symptoms);
        trans_data = pd.read_csv('Book2.csv', header=None)
        trans_data.head()
        trans_data.shape
        
        # All Causes fetched from  the dataset
        causes = list(trans_data[0]);
        # print(trans_data.head())
        records = []
        for i in range(0, 327):
            records.append([str(trans_data.values[i,j]) for j in range(0, 2)])
        association_rules = apriori(records, min_support=0.003, min_confidence=0.8, min_lift=1, min_length=2)
        association_results = list(association_rules)
        print("records: ", records)
        print();
        print(len(association_results))
        print();
        # confidence = []
        # for i in range(0, len(association_results)):
        #     confidence.append(association_results[i][2][0][2]);
        
        indexes = [];
        for i in range (0, len(association_results)):
            #print();
            print(association_results[i]);
            #print();
            cause_symptoms = list(association_results[i][0]);
            print("Cause and symptoms: ",cause_symptoms);
            
            if(len(cause_symptoms)==1):
                cause_symptoms = list(cause_symptoms[0].split(","));

            if(len(cause_symptoms)==2):
                cause_symptoms = list(cause_symptoms[0].split(","))+list(cause_symptoms[1].split(","));
            
            # Remove spaces in start
            updated_cause_symptoms = [];
            for e in range(0,len(cause_symptoms)):
                if(cause_symptoms[e][0]==' '):
                    updated_cause_symptoms.append(cause_symptoms[e][1:len(cause_symptoms[e])]);
                else:
                    updated_cause_symptoms.append(cause_symptoms[e]);
            
            cause_symptoms = updated_cause_symptoms;
            #print("Cause and symptoms: ",cause_symptoms);
            #print("Confidence: ",association_results[i][2][0][2]);
            counter = 0;
            for e in range(0,len(user_input_symptoms)):
                # print("user_input_symptoms[e]: ",user_input_symptoms[e] in cause_symptoms);
                if(user_input_symptoms[e] in cause_symptoms):
                    counter = counter + 1;
            # print("counter: ",counter);
            if(counter>=2):
                indexes.append(i);
        
        result_set = [];
        for i in range(0,len(indexes)):
            conf = association_results[indexes[i]][2][0][2];
            if(conf==1.0):
                result_set.append(list(association_results[indexes[i]][0]));
        # print("result_set: ",result_set);
        # Fetch Only causes
        resultant_causes = [];
        for i in range(0,len(result_set)):        
            for j in range(0,len(result_set[i])):
                if(result_set[i][j] in causes):
                    resultant_causes.append(result_set[i][j]);
        
        print(" ");
        print("Causes: ",resultant_causes);
        return (jsonify(resultant_causes))
    except Exception:
        return 'error'

@app.route('/parse_table', methods=['POST'])
def upload_file():
    print(request.files)
    # check if the post request has the file part
    if 'file' not in request.files:
        print('no file in request')
        return""
    file = request.files['file']
    if file.filename == '':
        print('no selected file')
        return""
    if file and allowed_file(file.filename):
        print("hello")
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return ""
    print("end")
    return""

if __name__ == '__main__':
    app.run(debug=True)