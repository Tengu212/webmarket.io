from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = '87654321'  # Используй уникальный ключ для безопасности

# Путь для загрузки изображений
UPLOAD_FOLDER = 'static/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Разрешенные расширения файлов изображений
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Функция для подключения к базе данных
def get_db_connection():
    conn = sqlite3.connect('shop.db')  # Подключаемся к базе данных
    conn.row_factory = sqlite3.Row  # Позволяет работать с результатами как с объектами
    return conn

# Функция для создания таблиц в базе данных (если они не существуют)
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Создаем таблицу товаров
    cursor.execute('''CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            image TEXT
        )''')

    # Создаем таблицу пользователей с полем is_admin
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0  -- Добавляем поле is_admin
        )''')

    # Создаем таблицу для корзины
    cursor.execute('''CREATE TABLE IF NOT EXISTS cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )''')
    
      # Создаем таблицу заказов
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            total_price REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')

    # Создаем таблицу для элементов заказа
    cursor.execute('''CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            price REAL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )''')
    
    # Проверяем, есть ли админ в базе данных, если нет - создаем
    cursor.execute('SELECT * FROM users WHERE is_admin = 1')
    admin_user = cursor.fetchone()
    if not admin_user:
        # Создаем админ-аккаунт (первоначальный пользователь)
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
        cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', 
                       ('admin', hashed_password, 1))  # Админ с паролем 'admin123'

    conn.commit()
    conn.close()

# Инициализируем базу данных при старте приложения
init_db()

# Функция для проверки расширения файла
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Главная страница
@app.route('/', methods=['GET'])
def index():
    query = request.args.get('query')  # Получаем поисковый запрос
    conn = get_db_connection()
    
    if query:
        # Выполняем поиск товаров по названию или описанию
        products = conn.execute('SELECT * FROM products WHERE name LIKE ? OR description LIKE ?', 
                                ('%' + query + '%', '%' + query + '%')).fetchall()
    else:
        # Если запроса нет, выводим все товары
        products = conn.execute('SELECT * FROM products').fetchall()
    
    conn.close()
    return render_template('index.html', products=products)

# Страница добавления товара
@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Перенаправление на страницу логина, если не авторизован

    # Проверяем, является ли пользователь администратором
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not user or user['is_admin'] == 0:
        return redirect(url_for('index'))  # Если не админ, перенаправляем на главную страницу

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        
        if not name or not description or not price:
            return render_template('add_product.html', error="Все поля обязательны для заполнения.")
        
        try:
            price = float(price)
        except ValueError:
            return render_template('add_product.html', error="Цена должна быть числом.")
        
        image_filename = None
        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        
        conn.execute('INSERT INTO products (name, description, price, image) VALUES (?, ?, ?, ?)',
                     (name, description, price, image_filename))
        conn.commit()
        conn.close()
        
        return redirect(url_for('index'))  # Перенаправление на главную страницу после добавления товара
    
    return render_template('add_product.html')

# Регистрация пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            return render_template('register.html', error="Все поля обязательны для заполнения.")
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            return render_template('register.html', error="Пользователь с таким именем уже существует.")
        
        conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', 
                     (username, hashed_password, 0))  # Стандартный пользователь
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))  # Перенаправление на страницу входа после регистрации
    
    return render_template('register.html')

# Вход пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))  # Если уже авторизован, перенаправляем на главную страницу

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            return render_template('login.html', error="Все поля обязательны для заполнения.")
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']  # Сохраняем флаг админа в сессии
            return redirect(url_for('index'))  # Перенаправление на главную страницу
        else:
            return render_template('login.html', error="Неверный логин или пароль.")
    
    return render_template('login.html')

# Выход пользователя
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

# Страница корзины
@app.route('/basket')
def basket():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    username = session.get('username')  # Получаем имя пользователя из сессии

    conn = get_db_connection()
    
    # Получаем все товары в корзине для текущего пользователя
    cart_items = conn.execute(''' 
        SELECT p.name, p.price, ci.quantity, p.id FROM cart_items ci
        JOIN products p ON ci.product_id = p.id
        WHERE ci.user_id = ? 
    ''', (user_id,)).fetchall()

    total_price = sum(item['price'] * item['quantity'] for item in cart_items)

    conn.close()

    return render_template('basket.html', username=username, cart_items=cart_items, total_price=total_price)

# Добавление товара в корзину
@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if product:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?', (user_id, product_id))
        existing_item = cursor.fetchone()

        if existing_item:
            cursor.execute('UPDATE cart_items SET quantity = quantity + 1 WHERE user_id = ? AND product_id = ?',
                           (user_id, product_id))
        else:
            cursor.execute('INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)',
                           (user_id, product_id, 1))
        
        conn.commit()
        conn.close()

    return redirect(url_for('basket'))

# Удаление товара из корзины
@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    
    conn.execute('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?', (user_id, product_id))
    conn.commit()
    conn.close()

    return redirect(url_for('basket'))

# Страница оформления заказа
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Перенаправление на страницу логина, если не авторизован

    user_id = session['user_id']
    conn = get_db_connection()

    # Получаем все товары в корзине для текущего пользователя
    cart_items = conn.execute(''' 
        SELECT p.name, p.price, ci.quantity, p.id FROM cart_items ci
        JOIN products p ON ci.product_id = p.id
        WHERE ci.user_id = ? 
    ''', (user_id,)).fetchall()

    total_price = sum(item['price'] * item['quantity'] for item in cart_items)

    if request.method == 'POST':
        # Получаем данные с формы оформления заказа
        name = request.form['name']
        address = request.form['address']

        if not name or not address:
            return render_template('checkout.html', error="Все поля обязательны для заполнения.", cart_items=cart_items, total_price=total_price)

        # Сохраняем заказ в базе данных
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO orders (user_id, name, address, total_price) 
                          VALUES (?, ?, ?, ?)''', (user_id, name, address, total_price))
        order_id = cursor.lastrowid  # Получаем ID только что созданного заказа

        # Добавляем товары из корзины в заказ
        for item in cart_items:
            cursor.execute('''INSERT INTO order_items (order_id, product_id, quantity, price) 
                              VALUES (?, ?, ?, ?)''', (order_id, item['id'], item['quantity'], item['price']))

        # Очищаем корзину
        cursor.execute('DELETE FROM cart_items WHERE user_id = ?', (user_id,))

        conn.commit()
        conn.close()

        return redirect(url_for('order_confirmation', order_id=order_id))  # Перенаправление на страницу подтверждения заказа

    return render_template('checkout.html', cart_items=cart_items, total_price=total_price)

# Страница подтверждения заказа
@app.route('/order_confirmation/<int:order_id>')
def order_confirmation(order_id):
    conn = get_db_connection()
    order = conn.execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone()
    order_items = conn.execute('''SELECT oi.quantity, oi.price, p.name FROM order_items oi
                                  JOIN products p ON oi.product_id = p.id
                                  WHERE oi.order_id = ?''', (order_id,)).fetchall()
    conn.close()

    return render_template('order_confirmation.html', order=order, order_items=order_items)



if __name__ == '__main__':
    app.run(debug=True)
