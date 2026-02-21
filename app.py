import os
import json
import base64
import hashlib
import secrets
import requests as http_requests
import calendar
from datetime import datetime, date, timedelta
from functools import wraps
from io import BytesIO

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, jsonify, send_file)
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=30)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

# --- Database ---
def get_db():
    db_url = os.environ.get('DATABASE_URL', '')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        company_name TEXT DEFAULT '',
        company_address TEXT DEFAULT '',
        company_email TEXT DEFAULT '',
        company_phone TEXT DEFAULT '',
        logo_data TEXT DEFAULT '',
        brand_color TEXT DEFAULT '#2563eb',
        pan_number TEXT DEFAULT '',
        tan_number TEXT DEFAULT '',
        pf_reg_number TEXT DEFAULT '',
        esi_reg_number TEXT DEFAULT '',
        is_superadmin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS employees (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        emp_code TEXT DEFAULT '',
        name TEXT NOT NULL,
        email TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        department TEXT DEFAULT '',
        designation TEXT DEFAULT '',
        date_of_joining DATE,
        pan_number TEXT DEFAULT '',
        uan_number TEXT DEFAULT '',
        esi_number TEXT DEFAULT '',
        bank_name TEXT DEFAULT '',
        bank_account TEXT DEFAULT '',
        bank_ifsc TEXT DEFAULT '',
        ctc_annual REAL DEFAULT 0,
        basic_percent REAL DEFAULT 40,
        hra_percent REAL DEFAULT 50,
        da_amount REAL DEFAULT 0,
        special_allowance REAL DEFAULT 0,
        pf_applicable BOOLEAN DEFAULT TRUE,
        esi_applicable BOOLEAN DEFAULT FALSE,
        pt_applicable BOOLEAN DEFAULT TRUE,
        pt_state TEXT DEFAULT 'Maharashtra',
        tax_regime TEXT DEFAULT 'new',
        status TEXT DEFAULT 'active',
        payroll_country TEXT DEFAULT 'IN',
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS payslips (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        employee_id INTEGER REFERENCES employees(id),
        month INTEGER NOT NULL,
        year INTEGER NOT NULL,
        days_in_month INTEGER DEFAULT 30,
        days_worked INTEGER DEFAULT 30,
        lop_days INTEGER DEFAULT 0,
        basic REAL DEFAULT 0,
        hra REAL DEFAULT 0,
        da REAL DEFAULT 0,
        special_allowance REAL DEFAULT 0,
        other_earnings REAL DEFAULT 0,
        other_earnings_desc TEXT DEFAULT '',
        gross_earnings REAL DEFAULT 0,
        pf_employee REAL DEFAULT 0,
        pf_employer REAL DEFAULT 0,
        esi_employee REAL DEFAULT 0,
        esi_employer REAL DEFAULT 0,
        professional_tax REAL DEFAULT 0,
        tds REAL DEFAULT 0,
        other_deductions REAL DEFAULT 0,
        other_deductions_desc TEXT DEFAULT '',
        total_deductions REAL DEFAULT 0,
        net_pay REAL DEFAULT 0,
        status TEXT DEFAULT 'draft',
        generated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(employee_id, month, year)
    )''')
    conn.close()

    # Migrations
    conn = get_db()
    cur = conn.cursor()
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT FALSE",
        "UPDATE users SET is_superadmin = TRUE WHERE id = (SELECT MIN(id) FROM users)",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS payroll_country TEXT DEFAULT 'IN'",
        "ALTER TABLE payslips ADD COLUMN IF NOT EXISTS company_name TEXT DEFAULT ''",
        # Simple payroll: custom tax labels & rates for US/UK/EU
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax1_label TEXT DEFAULT ''",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax1_rate REAL DEFAULT 0",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax2_label TEXT DEFAULT ''",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax2_rate REAL DEFAULT 0",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax3_label TEXT DEFAULT ''",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax3_rate REAL DEFAULT 0",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax4_label TEXT DEFAULT ''",
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS custom_tax4_rate REAL DEFAULT 0",
        # Store payroll_country on payslip for PDF rendering
        "ALTER TABLE payslips ADD COLUMN IF NOT EXISTS payroll_country TEXT DEFAULT 'IN'",
    ]
    for m in migrations:
        try:
            cur.execute(m)
        except Exception:
            pass
    conn.close()

init_db()

# --- Auth helpers ---
def hash_pw(pw):
    """Hash password with bcrypt"""
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_pw(pw, hashed):
    """Verify password against bcrypt hash; also supports legacy sha256"""
    try:
        return bcrypt.checkpw(pw.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, AttributeError):
        if hashlib.sha256(pw.encode()).hexdigest() == hashed:
            return True
        return False

def generate_otp():
    return f"{secrets.randbelow(900000) + 100000}"

def send_otp_email(email, code, purpose='login'):
    smtp_host = os.environ.get('SMTP_HOST', '')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER', '')
    smtp_pass = os.environ.get('SMTP_PASS', '')
    smtp_from = os.environ.get('SMTP_FROM', smtp_user)
    if not smtp_host or not smtp_user:
        print(f"OTP for {email}: {code}")
        return True
    purpose_text = 'login' if purpose == 'login' else 'verification'
    subject = f"Your PayslipSnap {purpose_text} code: {code}"
    html = f"""<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:24px">
        <h2 style="color:#2563eb">PayslipSnap</h2>
        <p style="color:#666;font-size:14px">Your {purpose_text} code is:</p>
        <div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#1a1a2e;text-align:center;
                    padding:20px;background:#f0f4ff;border-radius:12px;margin:16px 0">{code}</div>
        <p style="color:#999;font-size:12px">This code expires in 5 minutes. Do not share it.</p>
        <p style="color:#999;font-size:11px;margin-top:20px">Part of <a href="https://snapsuite.up.railway.app" style="color:#2563eb">SnapSuite</a></p>
    </div>"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = smtp_from
    msg['To'] = email
    msg.attach(MIMEText(html, 'html'))
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False

def register_with_hub(company_name, email, currency):
    hub = os.environ.get('FINANCESNAP_URL', 'https://snapsuite.up.railway.app')
    try:
        http_requests.post(f'{hub}/api/register-company', json={
            'app_name': 'PayslipSnap', 'company_name': company_name,
            'email': email, 'currency': currency,
            'app_url': 'https://payslipsnap.up.railway.app'
        }, timeout=5)
    except: pass

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/welcome')
        return f(*args, **kwargs)
    return decorated

def get_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE id=%s', (session['user_id'],))
    user = cur.fetchone()
    conn.close()
    return user

# --- Auth routes ---
@app.route('/demo')
def demo_auto_login():
    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email='demo@snapsuite.app'")
    user = cur.fetchone(); conn.close()
    if user:
        session['user_id'] = user['id']
        return redirect('/')
    return redirect('/login')

@app.route('/welcome')
def welcome():
    if 'user_id' in session: return redirect('/')
    return render_template('landing.html')

@app.route('/login', methods=['GET'])
def login():
    if 'user_id' in session: return redirect('/')
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def register():
    if 'user_id' in session: return redirect('/')
    return render_template('login.html', show_register=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/welcome')

# --- OTP API ---
@app.route('/api/auth/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    purpose = data.get('purpose', 'login')
    if not email or '@' not in email:
        return jsonify({"error": "Valid email required"}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT COUNT(*) as cnt FROM otp_codes
                   WHERE email=%s AND created_at > NOW() - INTERVAL '15 minutes'""", (email,))
    if cur.fetchone()['cnt'] >= 5:
        conn.close()
        return jsonify({"error": "Too many requests. Wait 15 minutes."}), 429
    if purpose == 'login':
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        if not cur.fetchone():
            conn.close()
            return jsonify({"error": "No account found with this email"}), 404
    if purpose == 'register':
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        if cur.fetchone():
            conn.close()
            return jsonify({"error": "Email already registered. Please sign in."}), 409
    cur.execute("UPDATE otp_codes SET used=TRUE WHERE email=%s AND purpose=%s AND used=FALSE", (email, purpose))
    code = generate_otp()
    expires = datetime.utcnow() + timedelta(minutes=5)
    cur.execute("INSERT INTO otp_codes (email, code, purpose, expires_at) VALUES (%s,%s,%s,%s)",
                (email, code, purpose, expires))
    conn.close()
    if send_otp_email(email, code, purpose):
        return jsonify({"success": True})
    return jsonify({"error": "Failed to send email"}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    code = (data.get('code') or '').strip()
    purpose = data.get('purpose', 'login')
    if not email or not code or len(code) != 6:
        return jsonify({"error": "Email and 6-digit code required"}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT * FROM otp_codes
                   WHERE email=%s AND purpose=%s AND used=FALSE AND expires_at > NOW()
                   ORDER BY created_at DESC LIMIT 1""", (email, purpose))
    otp_rec = cur.fetchone()
    if not otp_rec:
        conn.close()
        return jsonify({"error": "Code expired. Request a new one."}), 400
    if otp_rec['attempts'] >= 3:
        cur.execute("UPDATE otp_codes SET used=TRUE WHERE id=%s", (otp_rec['id'],))
        conn.close()
        return jsonify({"error": "Too many attempts. Request a new code."}), 429
    cur.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE id=%s", (otp_rec['id'],))
    if not secrets.compare_digest(code, otp_rec['code']):
        conn.close()
        remaining = 2 - otp_rec['attempts']
        return jsonify({"error": f"Invalid code. {remaining} attempt(s) remaining."}), 400
    cur.execute("UPDATE otp_codes SET used=TRUE WHERE id=%s", (otp_rec['id'],))
    if purpose == 'login':
        cur.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cur.fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session.permanent = True
            return jsonify({"success": True, "redirect": "/"})
        return jsonify({"error": "User not found"}), 404
    conn.close()
    return jsonify({"success": True, "verified": True})

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')
    company = (data.get('company_name') or '').strip()
    currency = data.get('currency', 'MYR')
    code = (data.get('code') or '').strip()
    if not email or not password or not company:
        return jsonify({"error": "All fields required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(code) != 6:
        return jsonify({"error": "Valid 6-digit code required"}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT * FROM otp_codes
                   WHERE email=%s AND purpose='register' AND used=FALSE AND expires_at > NOW()
                   ORDER BY created_at DESC LIMIT 1""", (email,))
    otp_rec = cur.fetchone()
    if not otp_rec or not secrets.compare_digest(code, otp_rec['code']):
        conn.close()
        return jsonify({"error": "Invalid or expired code"}), 400
    if otp_rec['attempts'] >= 3:
        conn.close()
        return jsonify({"error": "Too many attempts. Request a new code."}), 429
    cur.execute("UPDATE otp_codes SET used=TRUE WHERE id=%s", (otp_rec['id'],))
    cur.execute('SELECT id FROM users WHERE email=%s', (email,))
    if cur.fetchone():
        conn.close()
        return jsonify({"error": "Email already registered"}), 409
    cur.execute('SELECT COUNT(*) as cnt FROM users')
    is_first = cur.fetchone()['cnt'] == 0
    try:
        cur.execute('''INSERT INTO users (email, password_hash, company_name, currency, is_superadmin)
                      VALUES (%s,%s,%s,%s,%s) RETURNING id''',
                   (email, hash_pw(password), company, currency, is_first))
        user_id = cur.fetchone()['id']
        conn.close()
        session['user_id'] = user_id
        session.permanent = True
        register_with_hub(company, email, currency)
        return jsonify({"success": True, "redirect": "/settings"})
    except psycopg2.IntegrityError:
        conn.close()
        return jsonify({"error": "Email already registered"}), 409

# --- Indian Payroll Calculations ---
def calc_indian_payroll(employee, month, year, days_worked, lop_days, other_earnings=0, other_deductions=0):
    """Calculate Indian payroll based on CTC structure."""
    ctc_annual = float(employee.get('ctc_annual', 0) or 0)
    ctc_monthly = ctc_annual / 12

    basic_pct = float(employee.get('basic_percent', 40) or 40) / 100
    hra_pct = float(employee.get('hra_percent', 50) or 50) / 100
    da_fixed = float(employee.get('da_amount', 0) or 0)

    days_in_month = calendar.monthrange(year, month)[1]
    ratio = days_worked / days_in_month if days_in_month > 0 else 1

    # Earnings
    basic_full = ctc_monthly * basic_pct
    basic = basic_full * ratio

    hra_full = basic_full * hra_pct
    hra = hra_full * ratio

    da = da_fixed * ratio

    # PF employer contribution (12% of basic, max base ₹15,000)
    pf_base = min(basic_full, 15000)
    pf_employer = pf_base * 0.12

    # Special allowance = CTC monthly - basic - hra - da - employer PF
    special_full = ctc_monthly - basic_full - hra_full - da_fixed - pf_employer
    if special_full < 0:
        special_full = 0
    special_allowance = special_full * ratio

    gross = basic + hra + da + special_allowance + other_earnings

    # Deductions
    # PF Employee (12% of basic, max base ₹15,000)
    pf_employee = 0
    if employee.get('pf_applicable', True):
        pf_employee = min(basic, 15000 * ratio) * 0.12

    # ESI (0.75% employee if gross < ₹21,000)
    esi_employee = 0
    esi_employer = 0
    if employee.get('esi_applicable', False) and gross < 21000:
        esi_employee = gross * 0.0075
        esi_employer = gross * 0.0325

    # Professional Tax (state-wise)
    pt = 0
    if employee.get('pt_applicable', True):
        pt = get_professional_tax(employee.get('pt_state', 'Maharashtra'), gross)

    # TDS (simplified monthly based on annual taxable income)
    tds = calc_monthly_tds(employee, ctc_annual)
    tds = tds * ratio  # Pro-rate for LOP

    total_deductions = pf_employee + esi_employee + pt + tds + other_deductions
    net_pay = gross - total_deductions

    return {
        'days_in_month': days_in_month,
        'days_worked': days_worked,
        'lop_days': lop_days,
        'basic': round(basic, 2),
        'hra': round(hra, 2),
        'da': round(da, 2),
        'special_allowance': round(special_allowance, 2),
        'other_earnings': round(other_earnings, 2),
        'gross_earnings': round(gross, 2),
        'pf_employee': round(pf_employee, 2),
        'pf_employer': round(pf_employer * ratio, 2),
        'esi_employee': round(esi_employee, 2),
        'esi_employer': round(esi_employer, 2),
        'professional_tax': round(pt, 2),
        'tds': round(tds, 2),
        'other_deductions': round(other_deductions, 2),
        'total_deductions': round(total_deductions, 2),
        'net_pay': round(net_pay, 2),
    }

def get_professional_tax(state, monthly_gross):
    """State-wise professional tax (simplified)."""
    pt_slabs = {
        'Maharashtra': [(7500, 0), (10000, 175), (999999999, 200)],
        'Karnataka': [(15000, 0), (25000, 200), (999999999, 200)],
        'Tamil Nadu': [(3500, 0), (5000, 16.50), (7500, 39), (10000, 85), (12500, 127), (999999999, 208)],
        'West Bengal': [(10000, 0), (15000, 110), (25000, 130), (40000, 150), (999999999, 200)],
        'Telangana': [(15000, 0), (20000, 150), (999999999, 200)],
        'Gujarat': [(5999, 0), (8999, 80), (11999, 150), (999999999, 200)],
        'Andhra Pradesh': [(15000, 0), (20000, 150), (999999999, 200)],
        'Kerala': [(11999, 0), (17999, 120), (999999999, 208)],
        'Rajasthan': [(999999999, 150)],  # Flat
        'Madhya Pradesh': [(18750, 0), (25000, 187), (999999999, 208)],
    }
    slabs = pt_slabs.get(state, [(999999999, 200)])
    for limit, tax in slabs:
        if monthly_gross <= limit:
            return tax
    return 200

def calc_monthly_tds(employee, ctc_annual):
    """Simplified monthly TDS based on tax regime."""
    regime = employee.get('tax_regime', 'new')

    # Standard deduction
    std_deduction = 75000 if regime == 'new' else 50000

    # PF deduction
    basic_annual = ctc_annual * float(employee.get('basic_percent', 40) or 40) / 100
    pf_annual = min(basic_annual, 15000 * 12) * 0.12

    if regime == 'new':
        # New regime: only standard deduction + NPS
        taxable = ctc_annual - std_deduction
        tax = calc_new_regime_tax(taxable)
    else:
        # Old regime: 80C, HRA exemption, etc. (simplified)
        section_80c = min(pf_annual + 50000, 150000)  # PF + assumed investments
        taxable = ctc_annual - std_deduction - section_80c
        tax = calc_old_regime_tax(taxable)

    # Add cess 4%
    tax = tax * 1.04
    monthly_tds = tax / 12
    return max(0, round(monthly_tds, 2))

def calc_new_regime_tax(taxable):
    """FY 2025-26 New Tax Regime slabs."""
    if taxable <= 400000:
        return 0
    # Rebate u/s 87A for income up to 12L (new regime)
    slabs = [
        (400000, 0),
        (800000, 0.05),
        (1200000, 0.10),
        (1600000, 0.15),
        (2000000, 0.20),
        (2400000, 0.25),
        (float('inf'), 0.30),
    ]
    tax = 0
    prev = 0
    for limit, rate in slabs:
        if taxable <= prev:
            break
        bracket = min(taxable, limit) - prev
        tax += max(0, bracket) * rate
        prev = limit
    # Rebate u/s 87A: if taxable <= 12L, tax = 0 (new regime FY25-26)
    if taxable <= 1200000:
        tax = 0
    return tax

def calc_old_regime_tax(taxable):
    """Old Tax Regime slabs."""
    if taxable <= 250000:
        return 0
    slabs = [
        (250000, 0),
        (500000, 0.05),
        (1000000, 0.10),
        (float('inf'), 0.30),
    ]
    tax = 0
    prev = 0
    for limit, rate in slabs:
        if taxable <= prev:
            break
        bracket = min(taxable, limit) - prev
        tax += max(0, bracket) * rate
        prev = limit
    # Rebate u/s 87A: if taxable <= 5L, tax = 0
    if taxable <= 500000:
        tax = 0
    return tax

# --- Canadian Payroll Calculations ---
def calc_canadian_payroll(employee, month, year, days_worked, lop_days, other_earnings=0, other_deductions=0):
    """Calculate Canadian payroll: CPP, EI, Federal + Provincial tax."""
    annual_salary = float(employee.get('ctc_annual', 0) or 0)
    monthly_gross_full = annual_salary / 12

    days_in_month = calendar.monthrange(year, month)[1]
    ratio = days_worked / days_in_month if days_in_month > 0 else 1

    monthly_gross = monthly_gross_full * ratio + other_earnings

    # CPP (2025): 5.95% employee, max pensionable $71,300, basic exemption $3,500
    cpp_max_pensionable = 71300
    cpp_basic_exemption = 3500
    cpp_rate = 0.0595
    cpp_max_annual = (cpp_max_pensionable - cpp_basic_exemption) * cpp_rate
    cpp_monthly_max = cpp_max_annual / 12
    cpp_pensionable = max(0, monthly_gross - cpp_basic_exemption / 12)
    cpp_employee = min(cpp_pensionable * cpp_rate, cpp_monthly_max)
    cpp_employer = cpp_employee  # Employer matches

    # EI (2025): 1.63% employee, max insurable $65,700
    ei_max_insurable = 65700
    ei_rate = 0.0163
    ei_max_annual = ei_max_insurable * ei_rate
    ei_monthly_max = ei_max_annual / 12
    ei_employee = min(monthly_gross * ei_rate, ei_monthly_max)
    ei_employer = ei_employee * 1.4  # Employer pays 1.4x

    # Federal Tax (2025 brackets)
    federal_tax = calc_canadian_federal_tax(annual_salary) / 12 * ratio

    # Provincial Tax
    province = employee.get('pt_state', 'Ontario')
    provincial_tax = calc_canadian_provincial_tax(annual_salary, province) / 12 * ratio

    total_deductions = cpp_employee + ei_employee + federal_tax + provincial_tax + other_deductions
    net_pay = monthly_gross - total_deductions

    return {
        'days_in_month': days_in_month,
        'days_worked': days_worked,
        'lop_days': lop_days,
        'basic': round(monthly_gross, 2),  # In Canada, "basic" = gross salary
        'hra': 0,
        'da': 0,
        'special_allowance': 0,
        'other_earnings': round(other_earnings, 2),
        'gross_earnings': round(monthly_gross, 2),
        'pf_employee': round(cpp_employee, 2),   # CPP maps to PF field
        'pf_employer': round(cpp_employer, 2),
        'esi_employee': round(ei_employee, 2),    # EI maps to ESI field
        'esi_employer': round(ei_employer, 2),
        'professional_tax': round(provincial_tax, 2),  # Provincial maps to PT field
        'tds': round(federal_tax, 2),             # Federal tax maps to TDS field
        'other_deductions': round(other_deductions, 2),
        'total_deductions': round(total_deductions, 2),
        'net_pay': round(net_pay, 2),
    }

def calc_canadian_federal_tax(annual_income):
    """2025 Canadian Federal Tax brackets."""
    # Basic personal amount
    bpa = 16129
    taxable = max(0, annual_income - bpa)
    if taxable <= 0:
        return 0
    slabs = [
        (57375, 0.15),
        (57375, 0.205),
        (63088, 0.26),
        (75408, 0.29),
        (float('inf'), 0.33),
    ]
    tax = 0
    remaining = taxable
    for bracket_size, rate in slabs:
        if remaining <= 0:
            break
        amount = min(remaining, bracket_size)
        tax += amount * rate
        remaining -= amount
    return max(0, tax)

def calc_canadian_provincial_tax(annual_income, province):
    """Simplified provincial tax rates for major provinces."""
    # Basic personal amounts and top marginal rates (simplified)
    province_data = {
        'Ontario': {'bpa': 11865, 'slabs': [(51446, 0.0505), (51446, 0.0915), (150000, 0.1116), (float('inf'), 0.1216)]},
        'British Columbia': {'bpa': 12580, 'slabs': [(47937, 0.0506), (47937, 0.077), (13658, 0.105), (23044, 0.1229), (48971, 0.147), (float('inf'), 0.168)]},
        'Alberta': {'bpa': 21003, 'slabs': [(148269, 0.10), (29654, 0.12), (59307, 0.13), (118614, 0.14), (float('inf'), 0.15)]},
        'Quebec': {'bpa': 17183, 'slabs': [(51780, 0.14), (51780, 0.19), (19305, 0.24), (float('inf'), 0.2575)]},
        'Manitoba': {'bpa': 15780, 'slabs': [(47000, 0.108), (53000, 0.1275), (float('inf'), 0.174)]},
        'Saskatchewan': {'bpa': 17661, 'slabs': [(52057, 0.105), (96618, 0.125), (float('inf'), 0.145)]},
        'Nova Scotia': {'bpa': 8481, 'slabs': [(29590, 0.0879), (29590, 0.1495), (33820, 0.1667), (57000, 0.175), (float('inf'), 0.21)]},
        'New Brunswick': {'bpa': 13044, 'slabs': [(49958, 0.094), (49958, 0.14), (81348, 0.16), (float('inf'), 0.195)]},
    }
    data = province_data.get(province, province_data['Ontario'])
    taxable = max(0, annual_income - data['bpa'])
    if taxable <= 0:
        return 0
    tax = 0
    remaining = taxable
    for bracket_size, rate in data['slabs']:
        if remaining <= 0:
            break
        amount = min(remaining, bracket_size)
        tax += amount * rate
        remaining -= amount
    return max(0, tax)


# --- Simple Payroll (US/UK/EU) — user-defined tax percentages ---
def calc_simple_payroll(employee, month, year, days_worked, lop_days, other_earnings=0, other_deductions=0):
    """Calculate payroll using user-defined tax percentages applied to gross salary"""
    import calendar
    days_in_month = calendar.monthrange(year, month)[1]
    annual = float(employee.get('ctc_annual', 0) or 0)
    monthly_gross = annual / 12

    # Pro-rate for LOP
    if lop_days > 0 and days_in_month > 0:
        monthly_gross = monthly_gross * days_worked / days_in_month

    gross = monthly_gross + other_earnings

    # Apply custom tax percentages
    tax1_rate = float(employee.get('custom_tax1_rate', 0) or 0)
    tax2_rate = float(employee.get('custom_tax2_rate', 0) or 0)
    tax3_rate = float(employee.get('custom_tax3_rate', 0) or 0)
    tax4_rate = float(employee.get('custom_tax4_rate', 0) or 0)

    tax1_amt = round(gross * tax1_rate / 100, 2)
    tax2_amt = round(gross * tax2_rate / 100, 2)
    tax3_amt = round(gross * tax3_rate / 100, 2)
    tax4_amt = round(gross * tax4_rate / 100, 2)

    total_deductions = tax1_amt + tax2_amt + tax3_amt + tax4_amt + other_deductions
    net_pay = gross - total_deductions

    return {
        'days_in_month': days_in_month,
        'days_worked': days_worked,
        'basic': round(gross, 2),       # For simple mode, basic = gross
        'hra': 0,
        'da': 0,
        'special_allowance': 0,
        'other_earnings': other_earnings,
        'gross_earnings': round(gross, 2),
        'pf_employee': tax1_amt,         # Reuse pf_employee slot for tax1
        'pf_employer': 0,
        'esi_employee': tax2_amt,        # Reuse esi_employee slot for tax2
        'esi_employer': 0,
        'professional_tax': tax3_amt,    # Reuse professional_tax slot for tax3
        'tds': tax4_amt,                 # Reuse tds slot for tax4
        'other_deductions': other_deductions,
        'total_deductions': round(total_deductions, 2),
        'net_pay': round(net_pay, 2),
    }


# --- Dashboard ---
@app.route('/')
@login_required
def dashboard():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Employees
    cur.execute('SELECT COUNT(*) as total, COUNT(CASE WHEN status=%s THEN 1 END) as active FROM employees WHERE user_id=%s',
               ('active', user['id']))
    emp_stats = cur.fetchone()

    # Current month payroll
    now = datetime.now()
    cur.execute('''SELECT COUNT(*) as generated, COALESCE(SUM(net_pay), 0) as total_payout,
                  COALESCE(SUM(gross_earnings), 0) as total_gross,
                  COALESCE(SUM(tds), 0) as total_tds,
                  COALESCE(SUM(pf_employee + pf_employer), 0) as total_pf
                  FROM payslips WHERE user_id=%s AND month=%s AND year=%s''',
               (user['id'], now.month, now.year))
    payroll = cur.fetchone()

    # Recent payslips
    cur.execute('''SELECT p.*, e.name as emp_name, e.emp_code, e.designation
                  FROM payslips p JOIN employees e ON p.employee_id = e.id
                  WHERE p.user_id=%s ORDER BY p.year DESC, p.month DESC, e.name LIMIT 20''',
               (user['id'],))
    recent = cur.fetchall()

    conn.close()
    return render_template('dashboard.html', user=user, emp_stats=emp_stats,
                         payroll=payroll, recent=recent, now=now)

# --- Employees ---
@app.route('/employees')
@login_required
def employees():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    status_filter = request.args.get('status', 'active')
    if status_filter == 'all':
        cur.execute('SELECT * FROM employees WHERE user_id=%s ORDER BY name', (user['id'],))
    else:
        cur.execute('SELECT * FROM employees WHERE user_id=%s AND status=%s ORDER BY name', (user['id'], status_filter))
    emps = cur.fetchall()
    conn.close()
    return render_template('employees.html', user=user, employees=emps, status_filter=status_filter)

@app.route('/employee/add', methods=['GET', 'POST'])
@login_required
def add_employee():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()

        doj = request.form.get('date_of_joining') or None
        ctc = float(request.form.get('ctc_annual', 0) or 0)

        cur.execute('''INSERT INTO employees (user_id, emp_code, name, email, phone, department,
                      designation, date_of_joining, pan_number, uan_number, esi_number,
                      bank_name, bank_account, bank_ifsc, ctc_annual, basic_percent,
                      hra_percent, da_amount, pf_applicable, esi_applicable, pt_applicable,
                      pt_state, tax_regime, payroll_country,
                      custom_tax1_label, custom_tax1_rate, custom_tax2_label, custom_tax2_rate,
                      custom_tax3_label, custom_tax3_rate, custom_tax4_label, custom_tax4_rate)
                      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                      RETURNING id''',
                   (user['id'], request.form.get('emp_code', ''),
                    request.form['name'], request.form.get('email', ''),
                    request.form.get('phone', ''), request.form.get('department', ''),
                    request.form.get('designation', ''), doj,
                    request.form.get('pan_number', ''), request.form.get('uan_number', ''),
                    request.form.get('esi_number', ''), request.form.get('bank_name', ''),
                    request.form.get('bank_account', ''), request.form.get('bank_ifsc', ''),
                    ctc, float(request.form.get('basic_percent', 40) or 40),
                    float(request.form.get('hra_percent', 50) or 50),
                    float(request.form.get('da_amount', 0) or 0),
                    request.form.get('pf_applicable') == 'on',
                    request.form.get('esi_applicable') == 'on',
                    request.form.get('pt_applicable') == 'on',
                    request.form.get('pt_state', 'Maharashtra'),
                    request.form.get('tax_regime', 'new'),
                    request.form.get('payroll_country', 'IN'),
                    request.form.get('custom_tax1_label', ''),
                    float(request.form.get('custom_tax1_rate', 0) or 0),
                    request.form.get('custom_tax2_label', ''),
                    float(request.form.get('custom_tax2_rate', 0) or 0),
                    request.form.get('custom_tax3_label', ''),
                    float(request.form.get('custom_tax3_rate', 0) or 0),
                    request.form.get('custom_tax4_label', ''),
                    float(request.form.get('custom_tax4_rate', 0) or 0)))
        conn.close()
        flash(f'Employee {request.form["name"]} added!', 'success')
        return redirect(url_for('employees'))
    return render_template('employee_form.html', user=user, employee=None)

@app.route('/employee/<int:emp_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_employee(emp_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM employees WHERE id=%s AND user_id=%s', (emp_id, user['id']))
    emp = cur.fetchone()
    if not emp:
        flash('Employee not found', 'error')
        return redirect(url_for('employees'))

    if request.method == 'POST':
        doj = request.form.get('date_of_joining') or None
        cur2 = conn.cursor()
        cur2.execute('''UPDATE employees SET emp_code=%s, name=%s, email=%s, phone=%s,
                       department=%s, designation=%s, date_of_joining=%s, pan_number=%s,
                       uan_number=%s, esi_number=%s, bank_name=%s, bank_account=%s,
                       bank_ifsc=%s, ctc_annual=%s, basic_percent=%s, hra_percent=%s,
                       da_amount=%s, pf_applicable=%s, esi_applicable=%s, pt_applicable=%s,
                       pt_state=%s, tax_regime=%s, status=%s, payroll_country=%s,
                       custom_tax1_label=%s, custom_tax1_rate=%s, custom_tax2_label=%s, custom_tax2_rate=%s,
                       custom_tax3_label=%s, custom_tax3_rate=%s, custom_tax4_label=%s, custom_tax4_rate=%s
                       WHERE id=%s AND user_id=%s''',
                    (request.form.get('emp_code', ''), request.form['name'],
                     request.form.get('email', ''), request.form.get('phone', ''),
                     request.form.get('department', ''), request.form.get('designation', ''),
                     doj, request.form.get('pan_number', ''),
                     request.form.get('uan_number', ''), request.form.get('esi_number', ''),
                     request.form.get('bank_name', ''), request.form.get('bank_account', ''),
                     request.form.get('bank_ifsc', ''),
                     float(request.form.get('ctc_annual', 0) or 0),
                     float(request.form.get('basic_percent', 40) or 40),
                     float(request.form.get('hra_percent', 50) or 50),
                     float(request.form.get('da_amount', 0) or 0),
                     request.form.get('pf_applicable') == 'on',
                     request.form.get('esi_applicable') == 'on',
                     request.form.get('pt_applicable') == 'on',
                     request.form.get('pt_state', 'Maharashtra'),
                     request.form.get('tax_regime', 'new'),
                     request.form.get('status', 'active'),
                     request.form.get('payroll_country', 'IN'),
                     request.form.get('custom_tax1_label', ''),
                     float(request.form.get('custom_tax1_rate', 0) or 0),
                     request.form.get('custom_tax2_label', ''),
                     float(request.form.get('custom_tax2_rate', 0) or 0),
                     request.form.get('custom_tax3_label', ''),
                     float(request.form.get('custom_tax3_rate', 0) or 0),
                     request.form.get('custom_tax4_label', ''),
                     float(request.form.get('custom_tax4_rate', 0) or 0),
                     emp_id, user['id']))
        conn.close()
        flash(f'Employee updated!', 'success')
        return redirect(url_for('employees'))

    conn.close()
    return render_template('employee_form.html', user=user, employee=emp)

# --- Generate Payslips ---
@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate_payslips():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if request.method == 'POST':
        month = int(request.form['month'])
        year = int(request.form['year'])
        emp_ids = request.form.getlist('employee_ids')

        if not emp_ids:
            # Select all active employees
            cur.execute('SELECT id FROM employees WHERE user_id=%s AND status=%s', (user['id'], 'active'))
            emp_ids = [str(r['id']) for r in cur.fetchall()]

        generated = 0
        for eid in emp_ids:
            cur.execute('SELECT * FROM employees WHERE id=%s AND user_id=%s', (int(eid), user['id']))
            emp = cur.fetchone()
            if not emp:
                continue

            # Check if already exists
            cur.execute('SELECT id FROM payslips WHERE employee_id=%s AND month=%s AND year=%s',
                       (int(eid), month, year))
            if cur.fetchone():
                continue  # Skip already generated

            days_in_month = calendar.monthrange(year, month)[1]
            lop = int(request.form.get(f'lop_{eid}', 0) or 0)
            days_worked = days_in_month - lop
            other_earn = float(request.form.get(f'bonus_{eid}', 0) or 0)
            other_ded = float(request.form.get(f'deduction_{eid}', 0) or 0)

            # Branch by country
            country = emp.get('payroll_country', 'IN')
            if country == 'CA':
                calc = calc_canadian_payroll(emp, month, year, days_worked, lop, other_earn, other_ded)
            elif country in ('US', 'UK', 'EU', 'MY'):
                calc = calc_simple_payroll(emp, month, year, days_worked, lop, other_earn, other_ded)
            else:
                calc = calc_indian_payroll(emp, month, year, days_worked, lop, other_earn, other_ded)

            cur2 = conn.cursor()
            cur2.execute('''INSERT INTO payslips (user_id, employee_id, month, year,
                          days_in_month, days_worked, lop_days, basic, hra, da,
                          special_allowance, other_earnings, gross_earnings,
                          pf_employee, pf_employer, esi_employee, esi_employer,
                          professional_tax, tds, other_deductions, total_deductions,
                          net_pay, status, payroll_country)
                          VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (user['id'], int(eid), month, year,
                         calc['days_in_month'], calc['days_worked'], lop,
                         calc['basic'], calc['hra'], calc['da'],
                         calc['special_allowance'], calc['other_earnings'], calc['gross_earnings'],
                         calc['pf_employee'], calc['pf_employer'],
                         calc['esi_employee'], calc['esi_employer'],
                         calc['professional_tax'], calc['tds'],
                         calc['other_deductions'], calc['total_deductions'],
                         calc['net_pay'], 'generated', country))
            generated += 1

        conn.close()
        flash(f'{generated} payslip(s) generated for {calendar.month_name[month]} {year}!', 'success')
        return redirect(url_for('payslips', month=month, year=year))

    # GET - show form
    cur.execute('SELECT * FROM employees WHERE user_id=%s AND status=%s ORDER BY name', (user['id'], 'active'))
    emps = cur.fetchall()
    conn.close()

    now = datetime.now()
    return render_template('generate.html', user=user, employees=emps,
                         current_month=now.month, current_year=now.year)

# --- View Payslips ---
@app.route('/payslips')
@login_required
def payslips():
    user = get_user()
    month = int(request.args.get('month', datetime.now().month))
    year = int(request.args.get('year', datetime.now().year))

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT p.*, e.name as emp_name, e.emp_code, e.designation, e.department
                  FROM payslips p JOIN employees e ON p.employee_id = e.id
                  WHERE p.user_id=%s AND p.month=%s AND p.year=%s
                  ORDER BY e.name''',
               (user['id'], month, year))
    slips = cur.fetchall()

    # Totals
    cur.execute('''SELECT COALESCE(SUM(gross_earnings), 0) as total_gross,
                  COALESCE(SUM(net_pay), 0) as total_net,
                  COALESCE(SUM(tds), 0) as total_tds,
                  COALESCE(SUM(pf_employee + pf_employer), 0) as total_pf,
                  COALESCE(SUM(esi_employee + esi_employer), 0) as total_esi,
                  COALESCE(SUM(professional_tax), 0) as total_pt,
                  COUNT(*) as count
                  FROM payslips WHERE user_id=%s AND month=%s AND year=%s''',
               (user['id'], month, year))
    totals = cur.fetchone()
    conn.close()

    return render_template('payslips.html', user=user, payslips=slips, totals=totals,
                         month=month, year=year, month_name=calendar.month_name[month])

# --- View Single Payslip ---
@app.route('/payslip/<int:slip_id>')
@login_required
def view_payslip(slip_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT p.*, e.name as emp_name, e.emp_code, e.designation, e.department,
                  e.pan_number as emp_pan, e.uan_number, e.bank_name, e.bank_account,
                  e.date_of_joining, e.payroll_country,
                  e.custom_tax1_label, e.custom_tax2_label, e.custom_tax3_label, e.custom_tax4_label,
                  e.custom_tax1_rate, e.custom_tax2_rate, e.custom_tax3_rate, e.custom_tax4_rate
                  FROM payslips p JOIN employees e ON p.employee_id = e.id
                  WHERE p.id=%s AND p.user_id=%s''', (slip_id, user['id']))
    slip = cur.fetchone()
    conn.close()
    if not slip:
        flash('Payslip not found', 'error')
        return redirect(url_for('dashboard'))
    return render_template('view_payslip.html', user=user, slip=slip,
                         month_name=calendar.month_name[slip['month']])

# --- Download PDF ---
@app.route('/payslip/<int:slip_id>/pdf')
@login_required
def download_pdf(slip_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT p.*, e.name as emp_name, e.emp_code, e.designation, e.department,
                  e.pan_number as emp_pan, e.uan_number, e.bank_name, e.bank_account,
                  e.date_of_joining, e.payroll_country,
                  e.custom_tax1_label, e.custom_tax2_label, e.custom_tax3_label, e.custom_tax4_label,
                  e.custom_tax1_rate, e.custom_tax2_rate, e.custom_tax3_rate, e.custom_tax4_rate
                  FROM payslips p JOIN employees e ON p.employee_id = e.id
                  WHERE p.id=%s AND p.user_id=%s''', (slip_id, user['id']))
    slip = cur.fetchone()
    conn.close()
    if not slip:
        flash('Payslip not found', 'error')
        return redirect(url_for('dashboard'))

    try:
        pdf_buffer = generate_payslip_pdf(user, slip)
        fname = f"Payslip-{slip['emp_name'].replace(' ','-')}-{calendar.month_name[slip['month']]}-{slip['year']}.pdf"
        return send_file(pdf_buffer, as_attachment=True, download_name=fname, mimetype='application/pdf')
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f'PDF error: {str(e)}', 'error')
        return redirect(url_for('view_payslip', slip_id=slip_id))

def generate_payslip_pdf(user, slip):
    from fpdf import FPDF

    brand = user.get('brand_color', '#2563eb') or '#2563eb'
    br = int(brand[1:3], 16)
    bg = int(brand[3:5], 16)
    bb = int(brand[5:7], 16)

    company = user.get('company_name', '') or 'Company'
    month_name = calendar.month_name[slip['month']]

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Header bar
    pdf.set_fill_color(br, bg, bb)
    pdf.rect(0, 0, 210, 6, 'F')

    # Company info
    pdf.set_y(12)
    pdf.set_font('Helvetica', 'B', 18)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 8, company, ln=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(100, 100, 100)
    if user.get('company_address'):
        pdf.cell(0, 4, str(user['company_address']), ln=True)

    # Title
    pdf.set_y(12)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 8, 'PAYSLIP', align='R', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 5, f"{month_name} {slip['year']}", align='R', ln=True)

    # Divider
    pdf.set_y(pdf.get_y() + 4)
    pdf.set_draw_color(br, bg, bb)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.set_y(pdf.get_y() + 4)

    # Employee details grid
    pdf.set_font('Helvetica', '', 9)

    def info_row(label1, val1, label2, val2):
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(30, 5, label1)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(65, 5, str(val1 or '-'))
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(30, 5, label2)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(65, 5, str(val2 or '-'), ln=True)

    info_row('Employee:', slip.get('emp_name', ''), 'Emp Code:', slip.get('emp_code', ''))
    info_row('Department:', slip.get('department', ''), 'Designation:', slip.get('designation', ''))
    info_row('PAN:', slip.get('emp_pan', ''), 'UAN:', slip.get('uan_number', ''))
    info_row('Bank:', slip.get('bank_name', ''), 'Account:', slip.get('bank_account', ''))
    info_row('Days in Month:', slip.get('days_in_month', 30), 'Days Worked:', slip.get('days_worked', 30))

    pdf.set_y(pdf.get_y() + 6)

    # Country-specific labels and currency
    country = slip.get('payroll_country', 'IN')
    if country == 'CA':
        curr = 'C$'
        earn_labels = [('Gross Salary', slip.get('basic', 0))]
        ded_labels = [
            ('CPP (Employee)', slip.get('pf_employee', 0)),
            ('EI (Employee)', slip.get('esi_employee', 0)),
            ('Provincial Tax', slip.get('professional_tax', 0)),
            ('Federal Tax', slip.get('tds', 0)),
        ]
        id_label_1 = 'SIN'
        id_label_2 = 'CRA BN'
        employer_labels = f"CPP (Employer): C${float(slip.get('pf_employer', 0) or 0):,.2f}    |    EI (Employer): C${float(slip.get('esi_employer', 0) or 0):,.2f}"
    elif country in ('US', 'UK', 'EU', 'MY'):
        curr_map = {'US': '$', 'UK': 'GBP ', 'EU': 'EUR ', 'MY': 'RM'}
        curr = curr_map.get(country, '$')
        earn_labels = [('Gross Salary', slip.get('basic', 0))]
        # Use custom tax labels from employee record
        t1_label = slip.get('custom_tax1_label', '') or 'Tax 1'
        t2_label = slip.get('custom_tax2_label', '') or 'Tax 2'
        t3_label = slip.get('custom_tax3_label', '') or 'Tax 3'
        t4_label = slip.get('custom_tax4_label', '') or 'Tax 4'
        t1_rate = float(slip.get('custom_tax1_rate', 0) or 0)
        t2_rate = float(slip.get('custom_tax2_rate', 0) or 0)
        t3_rate = float(slip.get('custom_tax3_rate', 0) or 0)
        t4_rate = float(slip.get('custom_tax4_rate', 0) or 0)
        ded_labels = []
        if t1_rate > 0: ded_labels.append((f"{t1_label} ({t1_rate}%)", slip.get('pf_employee', 0)))
        if t2_rate > 0: ded_labels.append((f"{t2_label} ({t2_rate}%)", slip.get('esi_employee', 0)))
        if t3_rate > 0: ded_labels.append((f"{t3_label} ({t3_rate}%)", slip.get('professional_tax', 0)))
        if t4_rate > 0: ded_labels.append((f"{t4_label} ({t4_rate}%)", slip.get('tds', 0)))
        id_label_1 = {'US': 'SSN', 'UK': 'NI No.', 'EU': 'Tax ID', 'MY': 'IC No.'}.get(country, 'ID')
        id_label_2 = {'US': 'EIN', 'UK': 'PAYE Ref', 'EU': 'Employer ID', 'MY': 'EPF No.'}.get(country, 'Ref')
        employer_labels = ''
    else:
        curr = 'Rs.'
        earn_labels = [
            ('Basic', slip.get('basic', 0)),
            ('HRA', slip.get('hra', 0)),
            ('DA', slip.get('da', 0)),
            ('Special Allowance', slip.get('special_allowance', 0)),
        ]
        ded_labels = [
            ('PF (Employee)', slip.get('pf_employee', 0)),
            ('ESI (Employee)', slip.get('esi_employee', 0)),
            ('Professional Tax', slip.get('professional_tax', 0)),
            ('TDS / Income Tax', slip.get('tds', 0)),
        ]
        id_label_1 = 'PAN'
        id_label_2 = 'UAN'
        employer_labels = f"PF (Employer): Rs.{float(slip.get('pf_employer', 0) or 0):,.2f}    |    ESI (Employer): Rs.{float(slip.get('esi_employer', 0) or 0):,.2f}"

    # Earnings
    earnings = [(l, v) for l, v in earn_labels if float(v or 0) > 0]
    if float(slip.get('other_earnings', 0) or 0) > 0:
        earnings.append(('Other Earnings', slip.get('other_earnings', 0)))

    deductions = [(l, v) for l, v in ded_labels if float(v or 0) > 0]
    if float(slip.get('other_deductions', 0) or 0) > 0:
        deductions.append(('Other Deductions', slip.get('other_deductions', 0)))

    # Earnings & Deductions side by side
    col_w = 95

    # Headers
    pdf.set_fill_color(br, bg, bb)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 9)
    pdf.cell(col_w, 7, '  EARNINGS', fill=True)
    pdf.cell(col_w, 7, '  DEDUCTIONS', fill=True, ln=True)
    for i in range(max_rows):
        if i % 2 == 0:
            pdf.set_fill_color(248, 250, 252)
        else:
            pdf.set_fill_color(255, 255, 255)

        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(60, 60, 60)

        if i < len(earnings):
            pdf.cell(60, 6, f"  {earnings[i][0]}", fill=True)
            pdf.set_text_color(30, 30, 30)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(35, 6, f"{curr} {float(earnings[i][1] or 0):,.2f}", align='R', fill=True)
        else:
            pdf.cell(col_w, 6, '', fill=True)

        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(60, 60, 60)

        if i < len(deductions):
            pdf.cell(60, 6, f"  {deductions[i][0]}", fill=True)
            pdf.set_text_color(30, 30, 30)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(35, 6, f"{curr} {float(deductions[i][1] or 0):,.2f}", align='R', fill=True)
        else:
            pdf.cell(col_w, 6, '', fill=True)
        pdf.ln()

    # Totals row
    pdf.set_fill_color(br, bg, bb)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 9)
    pdf.cell(60, 7, '  GROSS EARNINGS', fill=True)
    pdf.cell(35, 7, f"{curr} {float(slip.get('gross_earnings', 0) or 0):,.2f}", align='R', fill=True)
    pdf.cell(60, 7, '  TOTAL DEDUCTIONS', fill=True)
    pdf.cell(35, 7, f"{curr} {float(slip.get('total_deductions', 0) or 0):,.2f}", align='R', fill=True)
    pdf.ln()

    # Net Pay box
    pdf.set_y(pdf.get_y() + 8)
    pdf.set_fill_color(240, 253, 244)
    pdf.set_draw_color(34, 197, 94)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(22, 101, 52)
    net = float(slip.get('net_pay', 0) or 0)
    pdf.cell(0, 12, f"  NET PAY:  {curr} {net:,.2f}", fill=True, border=1, ln=True)

    # Employer contributions
    pdf.set_y(pdf.get_y() + 8)
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, 'EMPLOYER CONTRIBUTIONS (Not deducted from salary)', ln=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.cell(0, 4, employer_labels, ln=True)

    # Footer
    if pdf.get_y() < 270:
        pdf.set_y(-12)
        pdf.set_fill_color(br, bg, bb)
        pdf.rect(0, 285, 210, 8, 'F')
        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 4, f"Generated by PayslipSnap  |  {company}  |  This is a computer-generated payslip", align='C')

    buffer = BytesIO()
    pdf.output(buffer)
    buffer.seek(0)
    return buffer

# --- Year-End Summary / Form 16 ---
@app.route('/yearend')
@login_required
def yearend():
    user = get_user()
    fy = request.args.get('fy', '')
    if not fy:
        # Default to current FY
        now = datetime.now()
        if now.month >= 4:
            fy = f"{now.year}-{now.year+1}"
        else:
            fy = f"{now.year-1}-{now.year}"

    parts = fy.split('-')
    start_year = int(parts[0])
    end_year = int(parts[1])

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Get all employees with FY data
    cur.execute('''SELECT e.id, e.name, e.emp_code, e.pan_number, e.designation,
                  COALESCE(SUM(p.basic), 0) as total_basic,
                  COALESCE(SUM(p.hra), 0) as total_hra,
                  COALESCE(SUM(p.da), 0) as total_da,
                  COALESCE(SUM(p.special_allowance), 0) as total_special,
                  COALESCE(SUM(p.gross_earnings), 0) as total_gross,
                  COALESCE(SUM(p.pf_employee), 0) as total_pf_ee,
                  COALESCE(SUM(p.pf_employer), 0) as total_pf_er,
                  COALESCE(SUM(p.professional_tax), 0) as total_pt,
                  COALESCE(SUM(p.tds), 0) as total_tds,
                  COALESCE(SUM(p.total_deductions), 0) as total_deductions,
                  COALESCE(SUM(p.net_pay), 0) as total_net,
                  COUNT(p.id) as months_paid
                  FROM employees e
                  LEFT JOIN payslips p ON e.id = p.employee_id
                    AND ((p.month >= 4 AND p.year = %s) OR (p.month <= 3 AND p.year = %s))
                  WHERE e.user_id = %s
                  GROUP BY e.id ORDER BY e.name''',
               (start_year, end_year, user['id']))
    employees = cur.fetchall()

    # Company totals
    totals = {
        'total_gross': sum(e['total_gross'] for e in employees),
        'total_pf': sum(e['total_pf_ee'] + e['total_pf_er'] for e in employees),
        'total_tds': sum(e['total_tds'] for e in employees),
        'total_net': sum(e['total_net'] for e in employees),
    }

    conn.close()
    return render_template('yearend.html', user=user, employees=employees,
                         totals=totals, fy=fy, start_year=start_year, end_year=end_year)

# --- Settings ---
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()

        logo_data = user.get('logo_data', '')
        logo_file = request.files.get('logo')
        brand_color = request.form.get('brand_color', '#2563eb')
        if logo_file and logo_file.filename:
            img_data = logo_file.read()
            ext = logo_file.filename.rsplit('.', 1)[-1].lower()
            media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
            logo_data = f"data:{media_type};base64,{base64.b64encode(img_data).decode()}"
            extracted = extract_brand_color(img_data)
            if extracted:
                brand_color = extracted

        cur.execute('''UPDATE users SET company_name=%s, company_address=%s, company_email=%s,
                      company_phone=%s, logo_data=%s, brand_color=%s, pan_number=%s,
                      tan_number=%s, pf_reg_number=%s, esi_reg_number=%s
                      WHERE id=%s''',
                   (request.form.get('company_name', ''),
                    request.form.get('company_address', ''),
                    request.form.get('company_email', ''),
                    request.form.get('company_phone', ''),
                    logo_data, brand_color,
                    request.form.get('pan_number', ''),
                    request.form.get('tan_number', ''),
                    request.form.get('pf_reg_number', ''),
                    request.form.get('esi_reg_number', ''),
                    user['id']))
        conn.close()
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', user=user)

# --- Admin ---
@app.route('/admin')
@login_required
def admin_dashboard():
    user = get_user()
    if not user.get('is_superadmin'):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT u.id, u.email, u.company_name, u.created_at,
                  COUNT(DISTINCT e.id) as emp_count,
                  COUNT(p.id) as payslip_count,
                  COALESCE(SUM(p.net_pay), 0) as total_paid
                  FROM users u LEFT JOIN employees e ON u.id = e.user_id
                  LEFT JOIN payslips p ON u.id = p.user_id
                  GROUP BY u.id ORDER BY u.created_at DESC''')
    companies = cur.fetchall()
    conn.close()
    return render_template('admin.html', user=user, companies=companies)

# --- API for SnapSuite ---
@app.route('/api/payroll')
def api_payroll():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE email=%s', (api_key,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid'}), 401
    month = request.args.get('month')
    year = request.args.get('year')
    company_name = request.args.get('company_name', '')
    q = 'SELECT p.*, e.name as emp_name FROM payslips p JOIN employees e ON p.employee_id=e.id WHERE p.user_id=%s'
    params = [user['id']]
    if month and year:
        q += ' AND p.month=%s AND p.year=%s'
        params.extend([month, year])
    if company_name:
        user_company = user.get('company_name', '') or ''
        if user_company.lower().strip() == company_name.lower().strip():
            q += " AND (LOWER(p.company_name)=LOWER(%s) OR p.company_name IS NULL OR p.company_name='')"
        else:
            q += ' AND LOWER(p.company_name)=LOWER(%s)'
        params.append(company_name)
    cur.execute(q + ' ORDER BY p.year DESC, p.month DESC', params)
    slips = cur.fetchall()
    conn.close()
    for s in slips:
        for k, v in s.items():
            if hasattr(v, 'isoformat'):
                s[k] = v.isoformat()
    return jsonify({'payslips': slips, 'count': len(slips)})

# --- Helpers ---
def extract_brand_color(img_bytes):
    try:
        from PIL import Image
        from collections import Counter
        img = Image.open(BytesIO(img_bytes)).convert('RGB')
        img = img.resize((100, 100))
        pixels = list(img.getdata())
        colored = []
        for r, g, b in pixels:
            brightness = (r + g + b) / 3
            saturation = max(r, g, b) - min(r, g, b)
            if brightness > 30 and brightness < 230 and saturation > 30:
                colored.append((r // 16 * 16, g // 16 * 16, b // 16 * 16))
        if not colored:
            return None
        most_common = Counter(colored).most_common(1)[0][0]
        return f"#{most_common[0]:02x}{most_common[1]:02x}{most_common[2]:02x}"
    except Exception:
        return None

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

# --- Seed Test Data ---
@app.route('/api/seed-test-data', methods=['POST'])
def seed_test_data():
    api_key = request.headers.get('X-API-Key', '')
    if not api_key: return jsonify({'error': 'API key required'}), 401
    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE email=%s', (api_key,))
    user = cur.fetchone()
    if not user: conn.close(); return jsonify({'error': 'Invalid API key'}), 401
    uid = user['id']

    employees = [
        ('BLM-001','Arjun Nair','arjun@bloomstudio.in','9876543210','Design','Senior Designer',
         '2023-06-15','ABCPN1234A','100123456789','',840000,40,50,0,0,'IN'),
        ('BLM-002','Sneha Patel','sneha@bloomstudio.in','9876500001','Development','Full Stack Developer',
         '2024-01-10','DEFPN5678B','100987654321','',960000,40,50,0,0,'IN'),
        ('BLM-003','Karthik Reddy','karthik@bloomstudio.in','9812345678','Design','Junior Designer',
         '2025-03-01','GHIPN9012C','100456789012','',480000,40,50,0,0,'IN'),
    ]
    emp_ids = []
    for e in employees:
        cur.execute("""INSERT INTO employees (user_id,emp_code,name,email,phone,department,designation,
                       date_of_joining,pan_number,uan_number,esi_number,ctc_annual,basic_percent,hra_percent,
                       da_amount,special_allowance,payroll_country)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                   (uid,e[0],e[1],e[2],e[3],e[4],e[5],e[6],e[7],e[8],e[9],e[10],e[11],e[12],e[13],e[14],e[15]))
        emp_ids.append(cur.fetchone()['id'])

    # Generate payslips for Jan 2026
    payslips = [
        # Arjun: CTC 8.4L → monthly ~70K
        (emp_ids[0], 1, 2026, 30, 30, 0, 28000, 14000, 0, 28000, 0, 70000, 1800, 1800, 0, 0, 200, 5833, 0, '', 9633, 60367, 'final'),
        # Sneha: CTC 9.6L → monthly ~80K
        (emp_ids[1], 1, 2026, 30, 30, 0, 32000, 16000, 0, 32000, 0, 80000, 1800, 1800, 0, 0, 200, 6667, 0, '', 10467, 69533, 'final'),
        # Karthik: CTC 4.8L → monthly ~40K
        (emp_ids[2], 1, 2026, 30, 30, 0, 16000, 8000, 0, 16000, 0, 40000, 1800, 1800, 780, 780, 200, 1667, 0, '', 7027, 32973, 'final'),
    ]
    for p in payslips:
        cur.execute("""INSERT INTO payslips (user_id,employee_id,month,year,days_in_month,days_worked,lop_days,
                       basic,hra,da,special_allowance,other_earnings,gross_earnings,
                       pf_employee,pf_employer,esi_employee,esi_employer,professional_tax,tds,
                       other_deductions,other_deductions_desc,total_deductions,net_pay,status,company_name)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Bloom Studio')
                       ON CONFLICT DO NOTHING""",
                   (uid,)+p)

    conn.commit(); conn.close()
    return jsonify({'success': True, 'company': 'Bloom Studio', 'employees': len(employees), 'payslips': len(payslips)})

# --- Demo Setup ---
@app.route('/api/demo-setup', methods=['POST'])
def demo_setup():
    secret = request.headers.get('X-Demo-Secret', '')
    if secret != 'snapsuite-demo-2026': return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    demo_email = 'demo@snapsuite.app'
    cur.execute('SELECT * FROM users WHERE email=%s', (demo_email,))
    user = cur.fetchone()
    if not user:
        cur.execute("""INSERT INTO users (email,password_hash,company_name,is_superadmin)
                       VALUES (%s,%s,'Bloom Studio',TRUE) RETURNING *""",
                   (demo_email, hash_pw('demo123')))
        user = cur.fetchone()
        conn.commit()
    uid = user['id']
    cur.execute('SELECT COUNT(*) as cnt FROM employees WHERE user_id=%s', (uid,))
    if cur.fetchone()['cnt'] == 0:
        emps = [
            ('BLM-001','Arjun Nair','arjun@bloomstudio.in','Design','Senior Designer','2023-06-15',840000),
            ('BLM-002','Sneha Patel','sneha@bloomstudio.in','Development','Full Stack Developer','2024-01-10',960000),
            ('BLM-003','Karthik Reddy','karthik@bloomstudio.in','Design','Junior Designer','2025-03-01',480000),
        ]
        eids = []
        for e in emps:
            cur.execute("""INSERT INTO employees (user_id,emp_code,name,email,department,designation,date_of_joining,
                           ctc_annual,basic_percent,hra_percent,payroll_country)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,40,50,'IN') RETURNING id""",
                       (uid,e[0],e[1],e[2],e[3],e[4],e[5],e[6]))
            eids.append(cur.fetchone()['id'])
        slips = [
            (eids[0],1,2026,28000,14000,28000,70000,1800,1800,0,0,200,5833,9633,60367),
            (eids[1],1,2026,32000,16000,32000,80000,1800,1800,0,0,200,6667,10467,69533),
            (eids[2],1,2026,16000,8000,16000,40000,1800,1800,780,780,200,1667,7027,32973),
        ]
        for s in slips:
            cur.execute("""INSERT INTO payslips (user_id,employee_id,month,year,days_in_month,days_worked,lop_days,
                           basic,hra,da,special_allowance,other_earnings,gross_earnings,
                           pf_employee,pf_employer,esi_employee,esi_employer,professional_tax,tds,
                           total_deductions,net_pay,status,company_name)
                           VALUES (%s,%s,%s,%s,30,30,0,%s,%s,0,%s,0,%s,%s,%s,%s,%s,%s,%s,%s,%s,'final','Bloom Studio')
                           ON CONFLICT DO NOTHING""",
                       (uid,s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],s[12],s[13],s[14]))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'app': 'PayslipSnap'})
