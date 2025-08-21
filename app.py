import sqlite3
import smtplib
import os
import datetime
from enum import Enum
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv
from collections import defaultdict
from thefuzz import process as fuzzy_process # For fuzzy search in KB
from werkzeug.utils import secure_filename
# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
socketio = SocketIO(app)
# Upload folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
# --- State for Chat ---
online_users = {} # Tracks online admins and technicians {email: sid}
# --- Models and Enums ---
class Role(Enum):
    ADMIN = 'admin'
    TECHNICIAN = 'technician'
    CLIENT = 'client'
class User(UserMixin):
    def __init__(self, id, email, role):
        self.id = id
        self.email = email
        self.role = role
# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    # Users Table - Added group_id
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, role TEXT, status TEXT DEFAULT 'active', group_id INTEGER,
                  FOREIGN KEY (group_id) REFERENCES groups(id))''')
    # Groups Table
    c.execute('''CREATE TABLE IF NOT EXISTS groups
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, contact_person TEXT, contact_email TEXT)''')
    # Tickets Table - Added 'location' column, SLA fields
    c.execute('''CREATE TABLE IF NOT EXISTS tickets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER, description TEXT,
                  priority TEXT, status TEXT, assigned_tech_id INTEGER, time_spent INTEGER,
                  resolution_notes TEXT, resolved_by_id INTEGER, resolved_at TEXT,
                  created_at TEXT, asset_id INTEGER, location TEXT, sla_claim_time INTEGER, sla_response_time INTEGER, sla_resolution_time INTEGER,
                  FOREIGN KEY (client_id) REFERENCES users(id),
                  FOREIGN KEY (assigned_tech_id) REFERENCES users(id),
                  FOREIGN KEY (resolved_by_id) REFERENCES users(id),
                  FOREIGN KEY (asset_id) REFERENCES assets(id))''')
    # Comments Table
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, user_id INTEGER,
                  comment_text TEXT, created_at TEXT,
                  FOREIGN KEY (ticket_id) REFERENCES tickets(id),
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    # Assets Table
    c.execute('''CREATE TABLE IF NOT EXISTS assets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, asset_name TEXT, asset_type TEXT,
                  assigned_user_id INTEGER, purchase_date TEXT, status TEXT,
                  FOREIGN KEY (assigned_user_id) REFERENCES users(id))''')
    # Chat Messages Table
    c.execute('''CREATE TABLE IF NOT EXISTS chat_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
                  message_text TEXT, created_at TEXT,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    # PC Repair Requests Table
    c.execute('''CREATE TABLE IF NOT EXISTS pc_repair_requests
                (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_name TEXT, customer_email TEXT,
                 device_type TEXT, issue_description TEXT, status TEXT DEFAULT 'pending',
                 created_at TEXT, assigned_tech_id INTEGER, quote REAL, notes TEXT,
                 FOREIGN KEY (assigned_tech_id) REFERENCES users(id))''')
    # Knowledge Base Articles Table
    c.execute('''CREATE TABLE IF NOT EXISTS knowledge_base_articles
                (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, category TEXT,
                 author_id INTEGER, created_at TEXT, last_updated_at TEXT,
                 FOREIGN KEY (author_id) REFERENCES users(id))''')
    # Attachments Table
    c.execute('''CREATE TABLE IF NOT EXISTS attachments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, file_name TEXT, file_path TEXT,
                  uploaded_by_id INTEGER, created_at TEXT,
                  FOREIGN KEY (ticket_id) REFERENCES tickets(id),
                  FOREIGN KEY (uploaded_by_id) REFERENCES users(id))''')
    # Audit Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, entity_type TEXT,
                  entity_id INTEGER, details TEXT, timestamp TEXT,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    # Insert sample admin user if not exists
    c.execute('SELECT * FROM users WHERE email = ?', ('jack@jsquared.com',))
    if c.fetchone() is None:
        hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
        c.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                  ('jack@jsquared.com', hashed_password, Role.ADMIN.value))
        conn.commit()
    conn.close()
# --- Email Notification ---
def send_email(to_email, subject, body):
    sender_email = os.getenv('SMTP_EMAIL')
    password = os.getenv('SMTP_PASSWORD')
    if not sender_email or not password:
        print("Email credentials not configured. Skipping email.")
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = f"J Squared Ticket Hub <{sender_email}>"
    msg['To'] = to_email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
            print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Email failed to send: {e}")
# --- Audit Log Function ---
def log_audit(user_id, action, entity_type, entity_id, details):
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute("INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (user_id, action, entity_type, entity_id, details, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
# --- User Authentication ---
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute("SELECT id, email, role FROM users WHERE id = ? AND status = 'active'", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(id=user_data[0], email=user_data[1], role=user_data[2])
    return None
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute("SELECT id, email, role, password_hash FROM users WHERE email = ? AND status = 'active'", (email,))
    user_data = c.fetchone()
    conn.close()
    if user_data and bcrypt.check_password_hash(user_data[3], password):
        user = User(id=user_data[0], email=user_data[1], role=user_data[2])
        login_user(user)
        return jsonify({'message': 'Logged in successfully!', 'role': user.role})
    return jsonify({'message': 'Invalid credentials or account disabled.'}), 401
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully!'})
@app.route('/status')
def status():
    if current_user.is_authenticated:
        return jsonify({'role': current_user.role, 'email': current_user.email})
    return jsonify({}), 401
# --- API Routes ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')
# --- Static Uploads ---
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# --- PC Repair Portal ---
@app.route('/pc-repair', methods=['POST'])
def submit_pc_repair_request():
    data = request.json
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute("""
        INSERT INTO pc_repair_requests (customer_name, customer_email, device_type, issue_description, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (data['customer_name'], data['customer_email'], data['device_type'], data['issue_description'], datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
    # Notify admin
    send_email('jack@jsquared.com', 'New PC Repair Request', f"Request from {data['customer_name']} for a {data['device_type']}.")
    return jsonify({'message': 'Your repair request has been submitted successfully! We will contact you shortly.'}), 201
@app.route('/pc-repair/requests', methods=['GET'])
@login_required
def get_pc_repair_requests():
    if current_user.role not in [Role.ADMIN.value, Role.TECHNICIAN.value]:
        return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT r.*, u.email as assigned_tech_email FROM pc_repair_requests r LEFT JOIN users u ON r.assigned_tech_id = u.id ORDER BY r.id DESC")
    requests = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(requests)
# --- Knowledge Base ---
@app.route('/kb/articles', methods=['GET', 'POST'])
@login_required
def manage_kb_articles():
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
   
    if request.method == 'POST':
        if current_user.role not in [Role.ADMIN.value, Role.TECHNICIAN.value]:
            return jsonify({'message': 'Unauthorized'}), 403
        data = request.json
        now = datetime.datetime.now().isoformat()
        c.execute("INSERT INTO knowledge_base_articles (title, content, category, author_id, created_at, last_updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (data['title'], data['content'], data['category'], current_user.id, now, now))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Article created successfully!'}), 201
    # GET request
    c.execute("SELECT a.*, u.email as author_email FROM knowledge_base_articles a JOIN users u ON a.author_id = u.id")
    articles = [dict(row) for row in c.fetchall()]
   
    search_term = request.args.get('search', '')
    if search_term:
        titles = [article['title'] for article in articles]
        best_matches = fuzzy_process.extract(search_term, titles, limit=10)
        matched_titles = {match[0] for match in best_matches if match[1] > 60}
        articles = [article for article in articles if article['title'] in matched_titles]
    conn.close()
    return jsonify(articles)
# --- Pricing Calculator ---
@app.route('/pricing/calculate', methods=['POST'])
def calculate_price():
    SERVICE_RATES = {
        'diagnostic': 60, 'virus_removal': 120, 'os_install': 150,
        'data_recovery': 250, 'hardware_install': 75, 'screen_replace': 180,
        'on_site_fee': 50
    }
    data = request.json
    services = data.get('services', [])
    total = sum(SERVICE_RATES.get(service, 0) for service in services)
    return jsonify({'estimated_total': total})
# --- Group Management ---
@app.route('/groups', methods=['GET', 'POST'])
@login_required
def manage_groups():
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if request.method == 'POST':
        data = request.json
        try:
            c.execute("INSERT INTO groups (name, contact_person, contact_email) VALUES (?, ?, ?)",
                      (data['name'], data.get('contact_person'), data.get('contact_email')))
            conn.commit()
            log_audit(current_user.id, 'create_group', 'group', c.lastrowid, f"Created group {data['name']}")
            return jsonify({'message': 'Group created successfully!'}), 201
        except sqlite3.IntegrityError:
            return jsonify({'message': 'A group with this name already exists.'}), 400
   
    c.execute("SELECT * FROM groups")
    groups = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(groups)
@app.route('/groups/<int:group_id>/users', methods=['GET'])
@login_required
def get_group_users(group_id):
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, email, role FROM users WHERE group_id = ?", (group_id,))
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)
# --- User Management (Modified for Groups) ---
@app.route('/register', methods=['POST'])
@login_required
def register():
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (email, password_hash, role, group_id) VALUES (?, ?, ?, ?)',
                  (data['email'], hashed_password, data['role'], data.get('group_id')))
        conn.commit()
        log_audit(current_user.id, 'register_user', 'user', c.lastrowid, f"Registered user {data['email']}")
        return jsonify({'message': 'User registered successfully!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Email already registered.'}), 400
    finally:
        conn.close()
@app.route('/user/<int:user_id>', methods=['POST', 'DELETE', 'GET'])
@login_required
def manage_user(user_id):
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if request.method == 'GET':
        c.execute("SELECT u.id, u.email, u.role, u.status, g.name as group_name FROM users u LEFT JOIN groups g ON u.group_id = g.id WHERE u.id = ?", (user_id,))
        user = c.fetchone()
        if not user: return jsonify({'message': 'User not found'}), 404
        c.execute("SELECT id, description, status FROM tickets WHERE client_id = ? OR assigned_tech_id = ?", (user_id, user_id))
        tickets = [dict(row) for row in c.fetchall()]
        c.execute("SELECT id, asset_name, status FROM assets WHERE assigned_user_id = ?", (user_id,))
        assets = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({'user': dict(user), 'tickets': tickets, 'assets': assets})
    if request.method == 'POST': # Update
        data = request.json
        c.execute("UPDATE users SET email = ?, role = ?, group_id = ? WHERE id = ?", (data['email'], data['role'], data.get('group_id'), user_id))
        conn.commit()
        log_audit(current_user.id, 'update_user', 'user', user_id, f"Updated user {data['email']}")
        conn.close()
        return jsonify({'message': 'User updated successfully'})
    if request.method == 'DELETE': # Soft delete
        c.execute("UPDATE users SET status = 'disabled' WHERE id = ?", (user_id,))
        conn.commit()
        log_audit(current_user.id, 'disable_user', 'user', user_id, "Disabled user")
        conn.close()
        return jsonify({'message': 'User disabled successfully'})
# --- Ticket Management ---
@app.route('/ticket', methods=['POST'])
@login_required
def create_ticket():
    description = request.form['description']
    location = request.form['location']
    asset_id = request.form.get('asset_id') or None
    priority = request.form['priority']
    file = request.files.get('file')
    filename = None
    filepath = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
    # SLA defaults in hours
    sla_claim_time = {'high': 1, 'medium': 4, 'low': 8}[priority]
    sla_response_time = {'high': 2, 'medium': 4, 'low': 8}[priority]
    sla_resolution_time = {'high': 8, 'medium': 24, 'low': 48}[priority]
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute('INSERT INTO tickets (client_id, description, priority, status, time_spent, created_at, asset_id, location, sla_claim_time, sla_response_time, sla_resolution_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
              (current_user.id, description, priority, 'open', 0, datetime.datetime.now().isoformat(), asset_id, location, sla_claim_time, sla_response_time, sla_resolution_time))
    ticket_id = c.lastrowid
    if filename:
        c.execute('INSERT INTO attachments (ticket_id, file_name, file_path, uploaded_by_id, created_at) VALUES (?, ?, ?, ?, ?)',
                  (ticket_id, filename, filename, current_user.id, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
    log_audit(current_user.id, 'create_ticket', 'ticket', ticket_id, f"Created ticket: {description[:50]}")
    send_email(current_user.email, 'New Ticket Created', f'Your ticket regarding "{description[:30]}..." has been created.')
    return jsonify({'message': 'Ticket created successfully!'}), 201
@app.route('/tickets', methods=['GET'])
@login_required
def view_tickets():
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    query = """
        SELECT t.id, t.description, t.priority, t.status, t.created_at, t.location, t.sla_claim_time, t.sla_response_time, t.sla_resolution_time, c.email as client_email, tech.email as assigned_tech_email
        FROM tickets t JOIN users c ON t.client_id = c.id LEFT JOIN users tech ON t.assigned_tech_id = tech.id
    """
    params = ()
    if current_user.role == Role.TECHNICIAN.value:
        query += " WHERE t.assigned_tech_id = ?"
        params = (current_user.id,)
    elif current_user.role == Role.CLIENT.value:
        query += " WHERE t.client_id = ?"
        params = (current_user.id,)
    c.execute(query + " ORDER BY t.id DESC", params)
    tickets = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(tickets)
@app.route('/ticket/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket_details(ticket_id):
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT t.*, c.email as client_email, tech.email as assigned_tech_email, res.email as resolved_by_email, a.asset_name as linked_asset_name
        FROM tickets t JOIN users c ON t.client_id = c.id LEFT JOIN users tech ON t.assigned_tech_id = tech.id
        LEFT JOIN users res ON t.resolved_by_id = res.id LEFT JOIN assets a ON t.asset_id = a.id WHERE t.id = ?
    """, (ticket_id,))
    ticket = c.fetchone()
    if not ticket:
        conn.close()
        return jsonify({'message': 'Ticket not found'}), 404
    c.execute("SELECT c.comment_text, c.created_at, u.email as user_email FROM comments c JOIN users u ON c.user_id = u.id WHERE c.ticket_id = ? ORDER BY c.created_at ASC", (ticket_id,))
    comments = [dict(row) for row in c.fetchall()]
    c.execute("SELECT att.file_name, att.file_path, att.created_at, u.email as uploaded_by_email FROM attachments att JOIN users u ON att.uploaded_by_id = u.id WHERE att.ticket_id = ?", (ticket_id,))
    attachments = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({'ticket': dict(ticket), 'comments': comments, 'attachments': attachments})
@app.route('/ticket/<int:ticket_id>/comment', methods=['POST'])
@login_required
def add_comment(ticket_id):
    comment_text = request.form['comment_text']
    file = request.files.get('file')
    filename = None
    filepath = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute("INSERT INTO comments (ticket_id, user_id, comment_text, created_at) VALUES (?, ?, ?, ?)",
              (ticket_id, current_user.id, comment_text, datetime.datetime.now().isoformat()))
    if filename:
        c.execute('INSERT INTO attachments (ticket_id, file_name, file_path, uploaded_by_id, created_at) VALUES (?, ?, ?, ?, ?)',
                  (ticket_id, filename, filename, current_user.id, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
    log_audit(current_user.id, 'add_comment', 'ticket', ticket_id, f"Added comment to ticket {ticket_id}")
    return jsonify({'message': 'Comment added successfully'}), 201
@app.route('/ticket/<int:ticket_id>/assign', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute('UPDATE tickets SET assigned_tech_id = ?, status = ? WHERE id = ? AND status != ?',
              (request.json.get('tech_id'), 'in-progress', ticket_id, 'resolved'))
    conn.commit()
    conn.close()
    log_audit(current_user.id, 'assign_ticket', 'ticket', ticket_id, f"Assigned ticket {ticket_id} to tech {request.json.get('tech_id')}")
    return jsonify({'message': 'Ticket assigned successfully.'})
@app.route('/ticket/<int:ticket_id>/resolve', methods=['POST'])
@login_required
def resolve_ticket(ticket_id):
    if current_user.role not in [Role.TECHNICIAN.value, Role.ADMIN.value]: return jsonify({'message': 'Unauthorized'}), 403
    data = request.json
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute("UPDATE tickets SET status = ?, time_spent = time_spent + ?, resolution_notes = ?, resolved_by_id = ?, resolved_at = ? WHERE id = ?",
              ('resolved', data.get('time_spent', 0), data.get('resolution_notes'), current_user.id, datetime.datetime.now().isoformat(), ticket_id))
    conn.commit()
    conn.close()
    log_audit(current_user.id, 'resolve_ticket', 'ticket', ticket_id, f"Resolved ticket {ticket_id}")
    return jsonify({'message': 'Ticket resolved successfully.'})
# --- Asset Management ---
@app.route('/assets', methods=['GET', 'POST'])
@login_required
def manage_assets():
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if request.method == 'POST':
        data = request.json
        c.execute("INSERT INTO assets (asset_name, asset_type, assigned_user_id, purchase_date, status) VALUES (?, ?, ?, ?, ?)",
                  (data['asset_name'], data['asset_type'], data.get('assigned_user_id'), data['purchase_date'], 'in-service'))
        conn.commit()
        log_audit(current_user.id, 'add_asset', 'asset', c.lastrowid, f"Added asset {data['asset_name']}")
        conn.close()
        return jsonify({'message': 'Asset added successfully'}), 201
    c.execute("SELECT a.*, u.email as assigned_user_email FROM assets a LEFT JOIN users u ON a.assigned_user_id = u.id")
    assets = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(assets)
@app.route('/my-assets', methods=['GET'])
@login_required
def get_my_assets():
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, asset_name FROM assets WHERE assigned_user_id = ?", (current_user.id,))
    assets = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(assets)
# --- Analytics ---
@app.route('/analytics', methods=['GET'])
@login_required
def get_analytics():
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM tickets")
    total_tickets = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM tickets WHERE status != 'resolved' AND status != 'closed'")
    open_tickets = c.fetchone()[0]
    c.execute("SELECT status, COUNT(*) FROM tickets GROUP BY status")
    tickets_by_status = dict(c.fetchall())
    c.execute("SELECT priority, COUNT(*) FROM tickets GROUP BY priority")
    tickets_by_priority = dict(c.fetchall())
    conn.close()
    return jsonify({'total_tickets': total_tickets, 'open_tickets': open_tickets, 'by_status': tickets_by_status, 'by_priority': tickets_by_priority})
# --- User Info for Asset Assignment ---
@app.route('/users', methods=['GET'])
@login_required
def get_users():
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT u.id, u.email, u.role, u.status, g.name as group_name FROM users u LEFT JOIN groups g ON u.group_id = g.id")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)
   
@app.route('/technicians', methods=['GET'])
@login_required
def get_technicians():
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE role = ? AND status = 'active'", (Role.TECHNICIAN.value,))
    technicians = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(technicians)
# --- Chat Routes ---
@app.route('/chat/messages', methods=['GET'])
@login_required
def get_chat_messages():
    if current_user.role not in [Role.ADMIN.value, Role.TECHNICIAN.value]:
        return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT m.message_text, m.created_at, u.email as user_email FROM chat_messages m JOIN users u ON m.user_id = u.id ORDER BY m.created_at ASC LIMIT 50")
    messages = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(messages)
# --- Audit Logs Route ---
@app.route('/audit-logs', methods=['GET'])
@login_required
def get_audit_logs():
    if current_user.role != Role.ADMIN.value: return jsonify({'message': 'Unauthorized'}), 403
    conn = sqlite3.connect('tickets.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT al.*, u.email as user_email FROM audit_logs al JOIN users u ON al.user_id = u.id ORDER BY al.timestamp DESC LIMIT 100")
    logs = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(logs)
# --- Chat SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated and current_user.role in [Role.ADMIN.value, Role.TECHNICIAN.value]:
        online_users[current_user.email] = request.sid
        join_room('tech_chat')
        emit('update_online_users', list(online_users.keys()), broadcast=True)
@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.email in online_users:
        del online_users[current_user.email]
        leave_room('tech_chat')
        emit('update_online_users', list(online_users.keys()), broadcast=True)
@socketio.on('send_message')
def handle_send_message(data):
    if current_user.is_authenticated and current_user.role in [Role.ADMIN.value, Role.TECHNICIAN.value]:
        message_text = data.get('message')
        if not message_text: return
        created_at = datetime.datetime.now().isoformat()
        conn = sqlite3.connect('tickets.db')
        c = conn.cursor()
        c.execute("INSERT INTO chat_messages (user_id, message_text, created_at) VALUES (?, ?, ?)",
                  (current_user.id, message_text, created_at))
        conn.commit()
        conn.close()
        message_data = {'user_email': current_user.email, 'message_text': message_text, 'created_at': created_at}
        emit('receive_message', message_data, room='tech_chat')
if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)