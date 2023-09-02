from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
from flask_bootstrap import Bootstrap
import logging
import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, current_user
from flask_login import UserMixin
from functools import wraps
from urllib.parse import quote_plus



app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
# Database connection configuration
db_host = os.environ.get('DB_HOST')
db_user = os.environ.get('DB_USER')
db_password = os.environ.get('DB_PASSWORD')
db_name = os.environ.get('DB_NAME')

# Create a database connection using mysql.connector
conn = mysql.connector.connect(
    user=db_user,
    password=db_password,
    host=db_host,
    database=db_name,
    ssl_disabled=True
)
cursor = conn.cursor()
# defining zip for jinja
app.jinja_env.filters['zip'] = zip

# Configure the database URI
db_password_encoded = quote_plus(db_password)

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{db_user}:{db_password_encoded}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking

# # Specify mysql.connector as the DBAPI for SQLAlchemy
# app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'dbapi': 'mysql.connector'}}

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)


# Role-based decorators
def role_required(role):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        return decorated_view
    return decorator



login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/')

def index():
    # query = "SELECT * FROM top_20"
    query = """
    SELECT t.*, IFNULL(f.total_frauds, 0) AS total_frauds
    FROM top_20 t
    LEFT JOIN (
        SELECT hospital_id, COUNT(*) AS total_frauds
        FROM fraud_df
        GROUP BY hospital_id
    ) f ON t.ID = f.hospital_id"""
    cursor.execute(query)
    data = cursor.fetchall()
    return render_template("index.html",data = data)

@app.route('/district/<int:district_id>')
def district_page(district_id):
    # Fetch the first 20 entries from the database for the selected district
    query = f'SELECT ID,`Hospital Name`,Score,District,Risk FROM sorted_score WHERE District = {district_id} LIMIT 20'
    cursor.execute(query)
    district_data = cursor.fetchall()

    return render_template('district_page.html', district_data=district_data,district_id = district_id)


@app.route('/fraud_details/<int:hospital_id>')
def fraud_details(hospital_id):
    # Query fraud details from the fraud_df table
    query = f"SELECT * FROM fraud_df WHERE hospital_id = {hospital_id}"
    cursor.execute(query)
    hospital_fraud = cursor.fetchall()
    return render_template('fraud_details.html', hospital_fraud=hospital_fraud, hospital_id=hospital_id)


@app.route('/fraud_case_details/<int:hospital_id>/<int:patient_id>')
def fraud_case_details(hospital_id, patient_id):
    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # Query the fraud case details for the specified patient ID
    query = f"SELECT * FROM fraud_df WHERE patient_id = {patient_id}"
    cursor.execute(query)
    fraud_case = cursor.fetchall()
    # Log the data
    logger.debug("Fraud Case Data: %s", fraud_case)

    query2 = f"SELECT `Hospital Name`,District FROM top_20 WHERE ID = {hospital_id}"
    cursor.execute(query2)
    fraud_hosp = cursor.fetchall()

    return render_template('fraud_case_details.html', fraud_case=fraud_case, fraud_hosp=fraud_hosp)

@app.route('/update_classification/<int:patient_id>', methods=['POST'])
def update_classification(patient_id):
    if request.method == 'POST':
        if 'classified_fraud' in request.form:
            classification_status = 1  # Classified as fraud
        elif 'classified_not_fraud' in request.form:
            classification_status = 0  # Classified as not fraud

        # Re-query the fraud case details for the specified patient ID
        query = f"SELECT * FROM fraud_df WHERE patient_id = {patient_id}"
        cursor.execute(query)
        fraud_case = cursor.fetchone()

        # Update the classification status in the fraud_df table
        update_query = f"UPDATE fraud_df SET expert_classification = {classification_status} WHERE patient_id = {patient_id}"
        cursor.execute(update_query)
        conn.commit()  # Commit the transaction

        flash("Classification updated successfully", "success")
        return redirect(url_for('fraud_case_details', hospital_id=fraud_case[1], patient_id=patient_id))

@app.route('/hospital_data')
def hospital():
    # Fetch the most recent visit for each patient
    query = """
    SELECT p.PatientID, p.FullName, p.Gender, p.age, p.PatientType, p.TreatmentCode, p.ActionTaken, p.NextVisitSuggestion, p.Prescription
    FROM patients_data AS p
    JOIN (
        SELECT PatientID, MAX(VisitDate) AS max_visit_date
        FROM patients_data
        GROUP BY PatientID
    ) AS v ON p.PatientID = v.PatientID AND p.VisitDate = v.max_visit_date
    """

    cursor.execute(query)
    recent_visits = cursor.fetchall()

    query2 = """
             SELECT PatientID, COUNT(*) 
             FROM patients_data
             GROUP BY PatientID
    """
    cursor.execute(query2)
    total_visits = cursor.fetchall()

    return render_template("hospital_patients.html", recent_visits=recent_visits, total_visits=total_visits)


@app.route('/timeline/<int:PatientID>')
def timeline(PatientID):
    # Fetch all visits of the patient from the treatments table
    select_query = "SELECT p.PatientID, p.FullName, p.Gender, p.age, p.PatientType, p.TreatmentCode, p.ActionTaken, p.NextVisitSuggestion, p.Prescription, p.VisitDate FROM patients_data AS p WHERE PatientID = %s ORDER BY VisitDate"
    cursor.execute(select_query, (PatientID,))
    visits = cursor.fetchall()

    return render_template("timeline.html", visits=visits)

@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        patient_type = request.form.get('patient_type')
        full_name = request.form.get('full_name')
        gender = request.form.get('gender')
        age = int(request.form.get('age'))
        patient_type1 = request.form.get('patient_type1')

        if patient_type1 == 'new':
            # Insert patient data into the patients_data table
            insert_query = "INSERT INTO patients_data (PatientID, FullName, Gender, Age, PatientType) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(insert_query, (patient_id, full_name, gender, age, patient_type))
            conn.commit()

        elif patient_type1 == 'revisiting':
            # Update patient data for revisiting patients
            update_query = "UPDATE patients_data SET FullName = %s, Gender = %s, Age = %s, PatientType = %s WHERE PatientID = %s"
            cursor.execute(update_query, (full_name, gender, age, patient_type, patient_id))
            conn.commit()

        return redirect(url_for('add_patient'))

    return render_template('add_patient.html')




@app.route('/update_patient', methods=['GET', 'POST'])
def update_patient():
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        treatment_code = request.form.get('treatment_code')
        action_taken = request.form.get('action_taken')
        next_visit_suggestion = request.form.get('next_visit_suggestion')
        prescription = request.form.get('prescription')

        # Update patient data for the most recent entry without existing values
        update_query = """
        UPDATE patients_data
        SET TreatmentCode = %s, ActionTaken = %s, NextVisitSuggestion = %s, Prescription = %s
        WHERE PatientID = %s AND
            TreatmentCode IS NULL AND ActionTaken IS NULL AND NextVisitSuggestion IS NULL AND Prescription IS NULL
        ORDER BY VisitDate DESC
        LIMIT 1
        """
        cursor.execute(update_query, (treatment_code, action_taken, next_visit_suggestion, prescription, patient_id))
        conn.commit()

        return redirect(url_for('update_patient'))

    return render_template('update_patient.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        role = request.form.get('role')

        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')
