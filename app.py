import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from dateutil.relativedelta import relativedelta
from datetime import datetime
from flask import render_template, abort
from flask_socketio import SocketIO, send, join_room
import hashlib


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.debug = True 
DATABASE = 'market.db'
socketio = SocketIO(app)

# ✅ 관리자 기준 사용자명 (추후 DB 기반으로 변경 가능)
ADMIN_USERNAME = 'admin'

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.route('/init/alter_product_image')
def alter_product_image():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("ALTER TABLE product ADD COLUMN image TEXT DEFAULT 'default.png';")
        db.commit()
        return "✅ image 컬럼 추가 완료"
    except Exception as e:
        return f"⚠️ 오류: {e}"

@app.route('/init/dummy_users')
def insert_dummy_users():
    db = get_db()
    cursor = db.cursor()

    dummy_users = [
        ("user1", "pass1"),
        ("user2", "pass2"),
        ("user3", "pass3")
    ]

    for username, password in dummy_users:
        user_id = str(uuid.uuid4())
        try:
            cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", (user_id, username, password))
        except sqlite3.IntegrityError:
            # 이미 존재하는 사용자면 무시
            continue

    db.commit()
    return "✅ 더미 유저 3명 삽입 완료"


# 상품목록
@app.route('/init/dummy_products')
def insert_dummy_products():
    db = get_db()
    cursor = db.cursor()

    # username → id 매핑
    cursor.execute("SELECT username, id FROM user")
    users = {row['username']: row['id'] for row in cursor.fetchall()}

    dummy_data = [
        ("자전거", "빠른 자전거", "1200000", "default.png", "user1"),
        ("키링", "귀여운 키링", "13000", "default.png", "user2"),
        ("후드집업", "따뜻한 후드", "40000", "default.png", "user3"),
        ("노트북", "중고 맥북", "800000", "default.png", "user1"),
        ("가방", "여성용 가방", "45000", "default.png", "user2"),
        ("운동화", "나이키 신발", "60000", "default.png", "user3")
    ]

    for title, desc, price, image, seller_username in dummy_data:
        seller_id = users.get(seller_username)
        if not seller_id:
            continue  # 사용자가 없으면 건너뛰기

        pid = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image, active) VALUES (?, ?, ?, ?, ?, ?, 1)",
            (pid, title, desc, price, seller_id, image)
        )
    db.commit()
    return "✅ 더미 상품 6개 삽입 완료"




@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)

        # 상품 테이블 생성 (image, active 포함!)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                image TEXT DEFAULT 'default.png',
                active INTEGER DEFAULT 1
            )
        """)

        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        db.commit()

@app.route('/admin/reports')
def admin_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 관리자 확인
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    current_username = cursor.fetchone()['username']
    if current_username != 'admin':
        flash("⚠️ 관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    # 신고 내역
    cursor.execute("""
        SELECT r.*, 
               u1.username AS reporter_name, 
               u2.username AS target_name
        FROM report r
        LEFT JOIN user u1 ON r.reporter_id = u1.id
        LEFT JOIN user u2 ON r.target_id = u2.id
    """)
    reports = cursor.fetchall()

    # 전체 유저
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    # 전체 상품
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    return render_template('admin_reports.html', reports=reports, users=users, products=products)


@app.route('/init/dummy_reports')
def insert_dummy_reports():
    db = get_db()
    cursor = db.cursor()

    # 유저 ID 매핑
    cursor.execute("SELECT username, id FROM user")
    users = {row['username']: row['id'] for row in cursor.fetchall()}

    reporter_id = users.get("user1")
    target_id = users.get("user3")

    if not (reporter_id and target_id):
        return "❌ 필요한 유저(user1, user3)가 존재하지 않습니다."

    report_id = str(uuid.uuid4())
    reason = "사기가 의심됩니다."

    cursor.execute(
        "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
        (report_id, reporter_id, target_id, reason)
    )
    db.commit()
    return "✅ 더미 신고 1건 삽입 완료"

@app.route('/chat/list')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, username FROM user WHERE id != ?", (session['user_id'],))
    users = cursor.fetchall()

    current_user_id = session['user_id']
    current_user = cursor.execute("SELECT username FROM user WHERE id = ?", (current_user_id,)).fetchone()

    return render_template('chat_list.html', users=users, current_user=current_user)


# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/init/alter_product')
def alter_product_table():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("ALTER TABLE product ADD COLUMN active INTEGER DEFAULT 1;")
        db.commit()
        return "✅ product 테이블에 active 컬럼 추가 완료"
    except Exception as e:
        return f"⚠️ 오류: {e}"
    
# 상단 import 필요 (이미 되어있다면 생략)
import hashlib

# 회원가입 라우트
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ 비밀번호 해시 처리
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()

        db = get_db()
        cursor = db.cursor()

        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())

        # ✅ 해시된 비밀번호 저장
        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            (user_id, username, hashed_pw)
        )
        db.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')


# 상단에 이미 있다면 생략
import hashlib

# 로그인 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ 비밀번호 해시값 생성
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()

        db = get_db()
        cursor = db.cursor()

        # ✅ 해시된 비밀번호와 비교
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, hashed_pw))
        user = cursor.fetchone()

        if user:
            if 'status' in user.keys() and user['status'] == 'suspended':
                flash("휴면 계정입니다. 관리자에게 문의하세요.")
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')



# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 상품 + 판매자 username 조인해서 가져오기
    cursor.execute("""
        SELECT p.*, u.username AS seller_username 
        FROM product p 
        JOIN user u ON p.seller_id = u.id 
        WHERE p.active = 1
    """)
    all_products = cursor.fetchall()
    
    return render_template('dashboard.html', products=all_products, user=current_user)


# 프로필 페이지 라우터
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_bio':
            bio = request.form.get('bio', '')
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
            flash("소개글이 업데이트되었습니다.")
        elif action == 'update_password':
            new_pw = request.form.get('new_password', '').strip()
            if new_pw:
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_pw, session['user_id']))
                flash("비밀번호가 변경되었습니다.")
        db.commit()
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)




# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        report_id = str(uuid.uuid4())

        # 1. 신고 저장
        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, reason)
            VALUES (?, ?, ?, ?)
        """, (report_id, session['user_id'], target_id, reason))

        # 2. 상품 신고 누적 확인
        cursor.execute("SELECT COUNT(*) FROM report WHERE target_id = ? AND target_id IN (SELECT id FROM product)", (target_id,))
        product_report_count = cursor.fetchone()[0]

        if product_report_count >= 3:
            cursor.execute("UPDATE product SET active = 0 WHERE id = ?", (target_id,))
            flash("🚫 해당 상품은 신고 누적으로 비활성화되었습니다.")

        # 3. 유저 신고 누적 확인
        cursor.execute("SELECT COUNT(*) FROM report WHERE target_id = ? AND target_id IN (SELECT id FROM user)", (target_id,))
        user_report_count = cursor.fetchone()[0]

        if user_report_count >= 5:
            cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (target_id,))
            flash("⚠️ 해당 사용자는 휴면 계정으로 전환되었습니다.")

        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')


@app.route('/init/alter_user_status')
def alter_user_status():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("ALTER TABLE user ADD COLUMN status TEXT DEFAULT 'active';")
        db.commit()
        return "✅ user 테이블에 status 컬럼 추가 완료"
    except Exception as e:
        return f"⚠️ 오류: {e}"



#use_profile
@app.route('/user/<username>')
def user_profile(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        abort(404)
    return render_template('user_profile.html', user=user)


# 판매자와 실시간 채팅 페이지
@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('chat.html', user=current_user)

@app.route('/chat/<receiver_id>')
def private_chat(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    target_user = cursor.fetchone()

    if not target_user:
        flash("상대방이 존재하지 않습니다.")
        return redirect(url_for('dashboard'))

    return render_template('private_chat.html', user=current_user, target=target_user)


@app.route('/payment/<receiver_id>', methods=['GET', 'POST'])
def payment(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    recipient = cursor.fetchone()

    if not recipient:
        flash("수신자를 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        amount = request.form['amount']

        # ✅ 보안 강화: 유효한 숫자 및 양수 여부 검증
        if not amount.isdigit() or int(amount) <= 0:
            flash("유효하지 않은 금액입니다.")
            return redirect(url_for('payment', receiver_id=receiver_id))

        flash(f"{amount}원을 {recipient['username']}님에게 송금했습니다!")
        return redirect(url_for('dashboard'))

    return render_template('payment.html', recipient=recipient)

@app.route('/my_products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    my_items = cursor.fetchall()

    return render_template('my_products.html', products=my_items)



# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 여기서 price를 숫자로 미리 변환해서 넘겨주기
    product = dict(product)  # Row 객체를 딕셔너리로 변환
    product['price'] = int(product['price'])

    return render_template('view_product.html', product=product)


# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)

@socketio.on('send_private_message')
def handle_private_message(data):
    room = data['room']
    send({'sender': data['sender'], 'message': data['message']}, room=room)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)


