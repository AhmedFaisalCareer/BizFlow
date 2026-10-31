
import os
import hmac
import sqlite3
import secrets
import hashlib
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bizflow.db"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ahmed123")
SECRET_KEY = os.getenv("SECRET_KEY", "local-bizflow-development-key-change-me")

def get_db():
    db = sqlite3.connect(str(DB_PATH), timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL DEFAULT 0,
            stock INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            product_id INTEGER,
            quantity INTEGER NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        );
        """)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="BizFlow 360", lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=60 * 60 * 12,
    same_site="lax",
    https_only=False
)

def money(value):
    return f"Rs. {float(value or 0):,.2f}"

def page(content, title="Dashboard"):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title} | BizFlow 360</title>
    <style>
    *{{box-sizing:border-box}}
    body{{margin:0;background:#0b1020;color:#eef2ff;font-family:Arial,sans-serif}}
    .layout{{display:flex;min-height:100vh}}
    aside{{width:240px;background:#111a2e;padding:25px;flex-shrink:0}}
    aside h2{{color:#60a5fa;margin-top:0}}
    aside a{{display:block;padding:13px;color:#cbd5e1;text-decoration:none;border-radius:9px;margin:5px 0}}
    aside a:hover{{background:#253451;color:white}}
    main{{padding:35px;width:100%;max-width:1500px;margin:auto}}
    h1{{font-size:30px;margin-top:0}}
    .muted{{color:#94a3b8}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:18px;margin:25px 0}}
    .card{{background:#151f35;padding:23px;border:1px solid #293954;border-radius:15px}}
    .number{{font-size:27px;font-weight:bold;margin-top:12px}}
    input,select{{width:100%;padding:12px;background:#0d1729;border:1px solid #34445f;border-radius:8px;color:white;margin:7px 0 15px}}
    button,.btn{{background:#2563eb;color:white;border:0;padding:11px 17px;border-radius:8px;cursor:pointer;text-decoration:none;display:inline-block}}
    button:hover,.btn:hover{{background:#1d4ed8}}
    .danger{{background:#dc2626}}
    table{{width:100%;border-collapse:collapse;min-width:550px}}
    th,td{{padding:14px;text-align:left;border-bottom:1px solid #293954}}
    th{{color:#93c5fd}}
    .table-wrap{{overflow-x:auto}}
    .form-card{{max-width:650px;margin-bottom:25px}}
    .badge{{padding:5px 9px;border-radius:20px;background:#263c5d;font-size:12px}}
    .login{{max-width:400px;margin:12vh auto;padding:35px;background:#151f35;border:1px solid #293954;border-radius:18px}}
    .error{{color:#f87171}}
    @media(max-width:700px){{
        .layout{{display:block}}
        aside{{width:100%;padding:12px}}
        aside nav{{display:flex;flex-wrap:wrap}}
        aside a{{padding:9px;font-size:13px}}
        main{{padding:20px}}
    }}
    </style>
    </head>
    <body>
    {content}
    </body>
    </html>
    """

def shell(content, title):
    return page(f"""
    <div class="layout">
    <aside>
        <h2>BizFlow 360</h2>
        <p class="muted">Business Management</p>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/customers">Customers</a>
            <a href="/products">Products</a>
            <a href="/orders">Orders</a>
            <a href="/logout">Logout</a>
        </nav>
    </aside>
    <main>{content}</main>
    </div>
    """, title)

def require_login(request):
    return request.session.get("admin") is True

def login_redirect():
    return RedirectResponse("/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if require_login(request):
        return RedirectResponse("/", status_code=303)

    return HTMLResponse(page("""
    <div class="login">
        <h1>BizFlow 360</h1>
        <p class="muted">Admin Login</p>
        <form method="post" action="/login">
            <label>Admin Password</label>
            <input type="password" name="password" required autofocus>
            <button style="width:100%">Login</button>
        </form>
    </div>
    """, "Admin Login"))

@app.post("/login")
def login(password: str = Form(...)):
    if hmac.compare_digest(password, ADMIN_PASSWORD):
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("login_notice", "success", httponly=True, samesite="lax")
        response.delete_cookie("login_notice")
        from starlette.responses import Response
        response = RedirectResponse("/", status_code=303)
        # Session is set below using a signed session cookie.
        response.set_cookie("admin_login", "invalid", httponly=True)
        return response

    return HTMLResponse(page("""
    <div class="login">
        <h2>Incorrect password</h2>
        <p class="error">Please try again.</p>
        <a class="btn" href="/login">Back to login</a>
    </div>
    """, "Login Error"), status_code=401)

# Signed cookie session authentication
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="bizflow-auth")

def is_authenticated(request):
    token = request.cookies.get("bizflow_session")
    if not token:
        return False
    try:
        data = serializer.loads(token, max_age=60 * 60 * 12)
        return data.get("admin") is True
    except (BadSignature, SignatureExpired):
        return False

@app.post("/auth")
def authenticate(password: str = Form(...)):
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse(page("""
        <div class="login">
        <h2>Incorrect password</h2>
        <p class="error">Please try again.</p>
        <a class="btn" href="/login">Back</a>
        </div>
        """), status_code=401)

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "bizflow_session",
        serializer.dumps({"admin": True}),
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=43200
    )
    return response

@app.get("/login-new", response_class=HTMLResponse)
def login_new():
    return HTMLResponse(page("""
    <div class="login">
        <h1>BizFlow 360</h1>
        <p class="muted">Secure Admin Login</p>
        <form method="post" action="/auth">
            <label>Password</label>
            <input type="password" name="password" required autofocus>
            <button style="width:100%">Login</button>
        </form>
    </div>
    """))

# Use the signed authentication cookie for all protected pages.
def protect(request):
    return None if is_authenticated(request) else RedirectResponse("/login-new", status_code=303)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login-new", status_code=303)

    with get_db() as db:
        customers = db.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        products = db.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        orders = db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        revenue = db.execute(
            "SELECT COALESCE(SUM(total),0) FROM orders WHERE status='Completed'"
        ).fetchone()[0]
        recent = db.execute("""
            SELECT orders.*, customers.name AS customer, products.name AS product
            FROM orders
            LEFT JOIN customers ON customers.id=orders.customer_id
            LEFT JOIN products ON products.id=orders.product_id
            ORDER BY orders.id DESC LIMIT 8
        """).fetchall()

    rows = "".join(f"""
        <tr>
        <td>#{r['id']}</td>
        <td>{r['customer'] or 'Deleted customer'}</td>
        <td>{r['product'] or 'Deleted product'}</td>
        <td>{r['quantity']}</td>
        <td>{money(r['total'])}</td>
        <td><span class="badge">{r['status']}</span></td>
        </tr>
    """ for r in recent)

    return HTMLResponse(shell(f"""
    <h1>Dashboard</h1>
    <p class="muted">Welcome to your business overview.</p>
    <div class="grid">
        <div class="card">Customers<div class="number">{customers}</div></div>
        <div class="card">Products<div class="number">{products}</div></div>
        <div class="card">Orders<div class="number">{orders}</div></div>
        <div class="card">Completed Revenue<div class="number">{money(revenue)}</div></div>
    </div>
    <div class="card">
        <h2>Recent Orders</h2>
        <div class="table-wrap">
        <table>
        <tr><th>ID</th><th>Customer</th><th>Product</th><th>Qty</th><th>Total</th><th>Status</th></tr>
        {rows or '<tr><td colspan="6">No orders yet.</td></tr>'}
        </table>
        </div>
    </div>
    """, "Dashboard"))

@app.get("/customers", response_class=HTMLResponse)
def customers_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login-new", status_code=303)

    with get_db() as db:
        rows = db.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()

    html = "".join(f"""
    <tr>
    <td>{r['id']}</td><td>{r['name']}</td>
    <td>{r['email'] or '-'}</td><td>{r['phone'] or '-'}</td>
    <td><form method="post" action="/customers/delete/{r['id']}">
    <button class="danger">Delete</button></form></td>
    </tr>""" for r in rows)

    return HTMLResponse(shell(f"""
    <h1>Customers</h1>
    <div class="card form-card">
    <h2>Add Customer</h2>
    <form method="post" action="/customers/add">
    <label>Name</label><input name="name" required maxlength="120">
    <label>Email</label><input name="email" type="email" maxlength="150">
    <label>Phone</label><input name="phone" maxlength="40">
    <button>Add Customer</button>
    </form></div>
    <div class="card"><h2>Customer List</h2>
    <div class="table-wrap"><table>
    <tr><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Action</th></tr>
    {html or '<tr><td colspan="5">No customers yet.</td></tr>'}
    </table></div></div>
    """, "Customers"))

@app.post("/customers/add")
def add_customer(request: Request, name: str = Form(...),
                 email: str = Form(""), phone: str = Form("")):
    if not is_authenticated(request):
        return login_redirect()
    with get_db() as db:
        db.execute(
            "INSERT INTO customers(name,email,phone,created_at) VALUES(?,?,?,?)",
            (name.strip(), email.strip(), phone.strip(), datetime.now().isoformat())
        )
    return RedirectResponse("/customers", status_code=303)

@app.post("/customers/delete/{customer_id}")
def delete_customer(request: Request, customer_id: int):
    if not is_authenticated(request):
        return login_redirect()
    with get_db() as db:
        db.execute("DELETE FROM customers WHERE id=?", (customer_id,))
    return RedirectResponse("/customers", status_code=303)

@app.get("/products", response_class=HTMLResponse)
def products_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login-new", status_code=303)

    with get_db() as db:
        rows = db.execute("SELECT * FROM products ORDER BY id DESC").fetchall()

    html = "".join(f"""
    <tr><td>{r['id']}</td><td>{r['name']}</td>
    <td>{money(r['price'])}</td><td>{r['stock']}</td>
    <td><form method="post" action="/products/delete/{r['id']}">
    <button class="danger">Delete</button></form></td></tr>
    """ for r in rows)

    return HTMLResponse(shell(f"""
    <h1>Products & Inventory</h1>
    <div class="card form-card">
    <h2>Add Product</h2>
    <form method="post" action="/products/add">
    <label>Product Name</label><input name="name" required maxlength="120">
    <label>Price (PKR)</label><input name="price" type="number" min="0" step="0.01" required>
    <label>Stock Quantity</label><input name="stock" type="number" min="0" required>
    <button>Add Product</button>
    </form></div>
    <div class="card"><h2>Inventory</h2>
    <div class="table-wrap"><table>
    <tr><th>ID</th><th>Product</th><th>Price</th><th>Stock</th><th>Action</th></tr>
    {html or '<tr><td colspan="5">No products yet.</td></tr>'}
    </table></div></div>
    """, "Products"))

@app.post("/products/add")
def add_product(request: Request, name: str = Form(...),
                price: float = Form(...), stock: int = Form(...)):
    if not is_authenticated(request):
        return login_redirect()
    if price < 0 or stock < 0:
        return HTMLResponse("Invalid price or stock", status_code=400)
    with get_db() as db:
        db.execute(
            "INSERT INTO products(name,price,stock,created_at) VALUES(?,?,?,?)",
            (name.strip(), price, stock, datetime.now().isoformat())
        )
    return RedirectResponse("/products", status_code=303)

@app.post("/products/delete/{product_id}")
def delete_product(request: Request, product_id: int):
    if not is_authenticated(request):
        return login_redirect()
    with get_db() as db:
        db.execute("DELETE FROM products WHERE id=?", (product_id,))
    return RedirectResponse("/products", status_code=303)

@app.get("/orders", response_class=HTMLResponse)
def orders_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login-new", status_code=303)

    with get_db() as db:
        customers = db.execute("SELECT * FROM customers").fetchall()
        products = db.execute("SELECT * FROM products").fetchall()
        orders = db.execute("""
            SELECT orders.*, customers.name AS customer, products.name AS product
            FROM orders
            LEFT JOIN customers ON customers.id=orders.customer_id
            LEFT JOIN products ON products.id=orders.product_id
            ORDER BY orders.id DESC
        """).fetchall()

    customer_options = "".join(
        f'<option value="{r["id"]}">{r["name"]}</option>' for r in customers
    )
    product_options = "".join(
        f'<option value="{r["id"]}">{r["name"]} - {money(r["price"])} (Stock: {r["stock"]})</option>'
        for r in products if r["stock"] > 0
    )
    html = "".join(f"""
    <tr><td>#{r['id']}</td><td>{r['customer'] or '-'}</td>
    <td>{r['product'] or '-'}</td><td>{r['quantity']}</td>
    <td>{money(r['total'])}</td><td>{r['status']}</td>
    <td>
    <form method="post" action="/orders/status/{r['id']}">
    <select name="status">
    <option>Pending</option><option>Processing</option>
    <option>Completed</option><option>Cancelled</option>
    </select>
    <button>Update</button></form>
    </td></tr>""" for r in orders)

    return HTMLResponse(shell(f"""
    <h1>Orders</h1>
    <div class="card form-card">
    <h2>Create Order</h2>
    <form method="post" action="/orders/add">
    <label>Customer</label><select name="customer_id" required>
    <option value="">Select Customer</option>{customer_options}</select>
    <label>Product</label><select name="product_id" required>
    <option value="">Select Product</option>{product_options}</select>
    <label>Quantity</label><input type="number" name="quantity" min="1" required>
    <button>Create Order</button>
    </form></div>
    <div class="card"><h2>All Orders</h2>
    <div class="table-wrap"><table>
    <tr><th>ID</th><th>Customer</th><th>Product</th><th>Qty</th>
    <th>Total</th><th>Status</th><th>Update</th></tr>
    {html or '<tr><td colspan="7">No orders yet.</td></tr>'}
    </table></div></div>
    """, "Orders"))

@app.post("/orders/add")
def add_order(request: Request, customer_id: int = Form(...),
              product_id: int = Form(...), quantity: int = Form(...)):
    if not is_authenticated(request):
        return login_redirect()
    if quantity < 1:
        return HTMLResponse("Invalid quantity", status_code=400)

    with get_db() as db:
        product = db.execute(
            "SELECT * FROM products WHERE id=?", (product_id,)
        ).fetchone()
        customer = db.execute(
            "SELECT id FROM customers WHERE id=?", (customer_id,)
        ).fetchone()

        if not product or not customer:
            return HTMLResponse("Customer or product not found", status_code=404)
        if product["stock"] < quantity:
            return HTMLResponse("Not enough stock", status_code=400)

        total = product["price"] * quantity
        db.execute(
            """INSERT INTO orders(customer_id,product_id,quantity,total,status,created_at)
               VALUES(?,?,?,?,?,?)""",
            (customer_id, product_id, quantity, total, "Pending",
             datetime.now().isoformat())
        )
        db.execute(
            "UPDATE products SET stock=stock-? WHERE id=?",
            (quantity, product_id)
        )

    return RedirectResponse("/orders", status_code=303)

@app.post("/orders/status/{order_id}")
def update_order(request: Request, order_id: int, status: str = Form(...)):
    if not is_authenticated(request):
        return login_redirect()

    if status not in {"Pending", "Processing", "Completed", "Cancelled"}:
        return HTMLResponse("Invalid status", status_code=400)

    with get_db() as db:
        order = db.execute(
            "SELECT * FROM orders WHERE id=?", (order_id,)
        ).fetchone()

        if not order:
            return HTMLResponse("Order not found", status_code=404)

        old_status = order["status"]
        if old_status != status:
            if old_status == "Cancelled":
                return HTMLResponse(
                    "Cancelled orders cannot be changed in this version.",
                    status_code=400
                )
            if status == "Cancelled":
                db.execute(
                    "UPDATE products SET stock=stock+? WHERE id=?",
                    (order["quantity"], order["product_id"])
                )
            db.execute(
                "UPDATE orders SET status=? WHERE id=?",
                (status, order_id)
            )

    return RedirectResponse("/orders", status_code=303)

@app.get("/logout")
def logout():
    response = RedirectResponse("/login-new", status_code=303)
    response.delete_cookie("bizflow_session")
    return response

@app.get("/health")
def health():
    return {"status": "ok", "app": "BizFlow 360", "database": "SQLite"}
