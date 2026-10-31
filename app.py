
import os
import json
import hmac
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, ForeignKey, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel, Field


# ================= CONFIGURATION =================

# Local development: keep the SQLite database beside app.py.
# Vercel: use /tmp because the deployed project directory is read-only.
# IMPORTANT: Vercel /tmp storage is temporary and is not persistent.
BASE_DIR = Path(__file__).resolve().parent
if os.getenv("VERCEL"):
    DATABASE_FILE = Path("/tmp/bizflow.db")
else:
    DATABASE_FILE = BASE_DIR / "bizflow.db"

DATABASE_URL = f"sqlite:///{DATABASE_FILE.as_posix()}"

# Never write secret files into the deployed project directory.
# Set SECRET_KEY in Vercel Environment Variables for stable sessions.
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ahmed123")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# ================= DATABASE MODELS =================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, default="")
    phone = Column(String, default="")
    company = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    category = Column(String, default="General")
    price = Column(Float, default=0)
    stock = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=True)
    quantity = Column(Integer, default=1)
    total = Column(Float, default=0)
    status = Column(String, default="Pending")
    created_at = Column(DateTime, default=datetime.utcnow)


class AppSettings(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, default=1)
    business_name = Column(String, default="BizFlow Business")
    business_email = Column(String, default="")
    business_phone = Column(String, default="")
    business_address = Column(String, default="")
    currency = Column(String, default="PKR")
    low_stock_threshold = Column(Integer, default=5)
    default_order_status = Column(String, default="Pending")


def get_app_settings(db):
    settings = db.query(AppSettings).filter(
        AppSettings.id == 1
    ).first()

    if not settings:
        settings = AppSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    return settings


Base.metadata.create_all(bind=engine)

class SettingsData(BaseModel):
    business_name: str = Field(min_length=1, max_length=150)
    business_email: str = Field(default="", max_length=200)
    business_phone: str = Field(default="", max_length=50)
    business_address: str = Field(default="", max_length=300)
    currency: str = Field(default="PKR", pattern="^(PKR|USD|EUR|GBP)$")
    low_stock_threshold: int = Field(default=5, ge=0, le=10000)
    default_order_status: str = "Pending"


class CredentialData(BaseModel):
    current_password: str
    new_username: str = Field(min_length=3, max_length=50)
    new_password: str = Field(min_length=10, max_length=128)


# ================= PASSWORD SECURITY =================

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 310000
    ).hex()
    return f"{salt}${hashed}"


def verify_password(password, stored):
    try:
        salt, original = stored.split("$", 1)
        hashed = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 310000
        ).hex()
        return hmac.compare_digest(hashed, original)
    except (ValueError, AttributeError):
        return False


def initialize_admin():
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.username == ADMIN_USERNAME
        ).first()

        if not user:
            db.add(User(
                username=ADMIN_USERNAME,
                password_hash=hash_password(ADMIN_PASSWORD)
            ))
            db.commit()
    finally:
        db.close()


initialize_admin()


# ================= FASTAPI APPLICATION =================

app = FastAPI(
    title="BizFlow 360",
    description="Business Management Platform",
    version="1.0.0"
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=bool(os.getenv("VERCEL"))
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"]
)


# ================= DATABASE DEPENDENCY =================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_login(request: Request):
    if not request.session.get("user"):
        raise HTTPException(status_code=401, detail="Login required")


# ================= INPUT SCHEMAS =================

class LoginData(BaseModel):
    username: str
    password: str


class CustomerData(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    email: str = Field(default="", max_length=200)
    phone: str = Field(default="", max_length=50)
    company: str = Field(default="", max_length=150)


class ProductData(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    category: str = Field(default="General", max_length=100)
    price: float = Field(ge=0)
    stock: int = Field(ge=0)


class OrderData(BaseModel):
    customer_id: int
    product_id: int
    quantity: int = Field(ge=1, le=100000)


class StatusData(BaseModel):
    status: str


# ================= HELPERS =================

def customer_dict(c):
    return {
        "id": c.id,
        "name": c.name,
        "email": c.email,
        "phone": c.phone,
        "company": c.company,
        "created_at": c.created_at.isoformat()
    }


def product_dict(p):
    return {
        "id": p.id,
        "name": p.name,
        "category": p.category,
        "price": p.price,
        "stock": p.stock
    }


def order_dict(o, db):
    customer = db.query(Customer).filter(
        Customer.id == o.customer_id
    ).first()
    product = db.query(Product).filter(
        Product.id == o.product_id
    ).first()

    return {
        "id": o.id,
        "customer": customer.name if customer else "Deleted customer",
        "product": product.name if product else "Deleted product",
        "quantity": o.quantity,
        "total": o.total,
        "status": o.status,
        "created_at": o.created_at.isoformat()
    }


# ================= AUTHENTICATION =================

@app.get("/api/me")
def current_user(request: Request):
    if not request.session.get("user"):
        return {"authenticated": False}

    return {
        "authenticated": True,
        "username": request.session["user"]
    }


@app.post("/api/login")
def login(data: LoginData, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.username == data.username
    ).first()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    request.session.clear()
    request.session["user"] = user.username

    return {"success": True, "message": "Login successful"}


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"success": True}


# ================= DASHBOARD =================

@app.get("/api/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    customers = db.query(Customer).count()
    products = db.query(Product).count()
    orders = db.query(Order).count()

    revenue = db.query(func.sum(Order.total)).filter(
        Order.status != "Cancelled"
    ).scalar() or 0

    pending = db.query(Order).filter(
        Order.status == "Pending"
    ).count()

    settings = get_app_settings(db)
    low_stock = db.query(Product).filter(
        Product.stock <= settings.low_stock_threshold
    ).count()

    recent = db.query(Order).order_by(
        Order.created_at.desc()
    ).limit(5).all()

    monthly = db.query(
        func.strftime("%Y-%m", Order.created_at),
        func.sum(Order.total)
    ).filter(
        Order.status != "Cancelled"
    ).group_by(
        func.strftime("%Y-%m", Order.created_at)
    ).all() if DATABASE_URL.startswith("sqlite") else []

    return {
        "customers": customers,
        "products": products,
        "orders": orders,
        "revenue": round(revenue, 2),
        "pending": pending,
        "low_stock": low_stock,
        "recent": [order_dict(o, db) for o in recent],
        "monthly": [
            {"month": m, "revenue": float(v or 0)}
            for m, v in monthly if m
        ]
    }


# ================= CUSTOMERS =================

@app.get("/api/customers")
def get_customers(
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    return [
        customer_dict(c) for c in db.query(Customer).order_by(
            Customer.id.desc()
        ).all()
    ]


@app.post("/api/customers")
def add_customer(
    data: CustomerData,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    customer = Customer(**data.model_dump())
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer_dict(customer)


@app.put("/api/customers/{customer_id}")
def update_customer(
    customer_id: int,
    data: CustomerData,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    customer = db.query(Customer).filter(
        Customer.id == customer_id
    ).first()

    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    for key, value in data.model_dump().items():
        setattr(customer, key, value)

    db.commit()
    db.refresh(customer)
    return customer_dict(customer)


@app.delete("/api/customers/{customer_id}")
def delete_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    customer = db.query(Customer).filter(
        Customer.id == customer_id
    ).first()

    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    if db.query(Order).filter(Order.customer_id == customer_id).first():
        raise HTTPException(
            status_code=400,
            detail="Customer has orders. Keep this customer record."
        )

    db.delete(customer)
    db.commit()
    return {"success": True}


# ================= INVENTORY =================

@app.get("/api/products")
def get_products(
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    return [
        product_dict(p) for p in db.query(Product).order_by(
            Product.id.desc()
        ).all()
    ]


@app.post("/api/products")
def add_product(
    data: ProductData,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    product = Product(**data.model_dump())
    db.add(product)
    db.commit()
    db.refresh(product)
    return product_dict(product)


@app.put("/api/products/{product_id}")
def update_product(
    product_id: int,
    data: ProductData,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    product = db.query(Product).filter(
        Product.id == product_id
    ).first()

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    for key, value in data.model_dump().items():
        setattr(product, key, value)

    db.commit()
    db.refresh(product)
    return product_dict(product)


@app.delete("/api/products/{product_id}")
def delete_product(
    product_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    product = db.query(Product).filter(
        Product.id == product_id
    ).first()

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if db.query(Order).filter(Order.product_id == product_id).first():
        raise HTTPException(
            status_code=400,
            detail="Product has orders. Keep this product record."
        )

    db.delete(product)
    db.commit()
    return {"success": True}


# ================= ORDERS =================

@app.get("/api/orders")
def get_orders(
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    return [
        order_dict(o, db) for o in db.query(Order).order_by(
            Order.id.desc()
        ).all()
    ]


@app.post("/api/orders")
def add_order(
    data: OrderData,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    customer = db.query(Customer).filter(
        Customer.id == data.customer_id
    ).first()

    product = db.query(Product).filter(
        Product.id == data.product_id
    ).first()

    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if product.stock < data.quantity:
        raise HTTPException(status_code=400, detail="Insufficient stock")

    order = Order(
        customer_id=data.customer_id,
        product_id=data.product_id,
        quantity=data.quantity,
        total=round(product.price * data.quantity, 2),
        status=get_app_settings(db).default_order_status
    )

    product.stock -= data.quantity
    db.add(order)
    db.commit()
    db.refresh(order)

    return order_dict(order, db)


@app.put("/api/orders/{order_id}/status")
def update_order_status(
    order_id: int,
    data: StatusData,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    allowed = [
        "Pending", "Confirmed", "Processing",
        "Shipped", "Delivered", "Cancelled"
    ]

    if data.status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid status")

    order = db.query(Order).filter(Order.id == order_id).first()

    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.status == "Cancelled" and data.status != "Cancelled":
        raise HTTPException(
            status_code=400,
            detail="Cancelled orders cannot be reopened in this version."
        )

    if data.status == "Cancelled" and order.status != "Cancelled":
        product = db.query(Product).filter(
            Product.id == order.product_id
        ).first()

        if product:
            product.stock += order.quantity

    order.status = data.status
    db.commit()

    return order_dict(order, db)


# ================= INVOICES =================

@app.get("/api/invoices/{order_id}")
def get_invoice(
    order_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    order = db.query(Order).filter(Order.id == order_id).first()

    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    customer = db.query(Customer).filter(
        Customer.id == order.customer_id
    ).first()

    product = db.query(Product).filter(
        Product.id == order.product_id
    ).first()

    return {
        "invoice_number": f"BF-{order.id:05d}",
        "date": order.created_at.strftime("%d %b %Y"),
        "customer": customer.name if customer else "Deleted customer",
        "email": customer.email if customer else "",
        "product": product.name if product else "Deleted product",
        "quantity": order.quantity,
        "unit_price": round(order.total / order.quantity, 2),
        "total": order.total,
        "status": order.status
    }


# ================= ADMIN SETTINGS =================

@app.get("/api/settings")
def get_settings(
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    s = get_app_settings(db)

    return {
        "business_name": s.business_name,
        "business_email": s.business_email,
        "business_phone": s.business_phone,
        "business_address": s.business_address,
        "currency": s.currency,
        "low_stock_threshold": s.low_stock_threshold,
        "default_order_status": s.default_order_status
    }


@app.put("/api/settings")
def update_settings(
    data: SettingsData,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    allowed = [
        "Pending", "Confirmed", "Processing",
        "Shipped", "Delivered"
    ]

    if data.default_order_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid default order status"
        )

    s = get_app_settings(db)

    for key, value in data.model_dump().items():
        setattr(s, key, value)

    db.commit()

    return {"success": True, "message": "Settings saved successfully"}


@app.post("/api/settings/credentials")
def update_credentials(
    data: CredentialData,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(require_login)
):
    old_username = request.session.get("user")

    user = db.query(User).filter(
        User.username == old_username
    ).first()

    if not user or not verify_password(
        data.current_password, user.password_hash
    ):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )

    existing = db.query(User).filter(
        User.username == data.new_username,
        User.id != user.id
    ).first()

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    user.username = data.new_username
    user.password_hash = hash_password(data.new_password)
    db.commit()

    request.session.clear()
    request.session["user"] = data.new_username

    return {
        "success": True,
        "message": "Username and password updated successfully"
    }

# ================= FRONTEND =================

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BizFlow 360 | Business Management</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
--bg:#090b13;--panel:#111522;--panel2:#171d2d;
--border:#252d41;--text:#f4f5fa;--muted:#929bb1;
--purple:#8867ff;--blue:#48b7ff;--green:#35d69b;
--red:#ff6680;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,sans-serif}
button,input,select{font:inherit}
button{cursor:pointer}
.login-screen{min-height:100vh;display:grid;place-items:center;padding:20px}
.login-box{width:100%;max-width:420px;padding:35px;background:var(--panel);border:1px solid var(--border);border-radius:20px}
.logo{font-size:25px;font-weight:800;letter-spacing:-1px}
.logo span{color:var(--purple)}
.subtitle{color:var(--muted);font-size:13px;margin:9px 0 25px}
.field{width:100%;padding:13px 14px;margin:8px 0 15px;background:#0b1020;border:1px solid var(--border);border-radius:9px;color:white;outline:none}
.field:focus{border-color:var(--purple)}
.btn{border:0;border-radius:9px;padding:12px 17px;color:white;background:linear-gradient(120deg,#7555f5,#4a8dff);font-weight:600}
.btn:hover{filter:brightness(1.12)}
.btn.secondary{background:var(--panel2);border:1px solid var(--border)}
.btn.danger{background:#4b2430;color:#ff9aaa}
.full{width:100%}
.layout{display:none;min-height:100vh}
.sidebar{width:245px;background:#0d111d;border-right:1px solid var(--border);padding:25px 17px;position:fixed;inset:0 auto 0 0;z-index:5}
.brand{padding:5px 10px 32px}
.nav-label{color:#68728a;font-size:10px;font-weight:700;letter-spacing:1.5px;padding:15px 12px 8px}
.nav-btn{display:flex;align-items:center;gap:12px;width:100%;padding:13px 12px;margin:3px 0;border:0;border-radius:9px;background:transparent;color:#a6afc3;text-align:left;font-size:13px}
.nav-btn:hover,.nav-btn.active{background:#20203b;color:white}
.nav-btn.active{box-shadow:inset 3px 0 var(--purple)}
.sidebar-bottom{position:absolute;bottom:22px;left:17px;right:17px}
.main{margin-left:245px;padding:30px 35px;max-width:1600px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;gap:15px}
.topbar h1{font-size:25px;margin:0}
.topbar p{color:var(--muted);font-size:12px;margin:7px 0}
.user-pill{background:var(--panel);border:1px solid var(--border);padding:10px 14px;border-radius:10px;font-size:12px}
.page{display:none}.page.active{display:block}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px}
.stat-title{color:var(--muted);font-size:12px}
.stat-value{font-size:27px;font-weight:800;margin:13px 0 6px}
.stat-note{font-size:11px;color:var(--green)}
.content-grid{display:grid;grid-template-columns:1.6fr 1fr;gap:18px}
.card-heading{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;gap:10px}
.card-heading h3{font-size:14px;margin:0}
.card-heading span{color:var(--muted);font-size:11px}
.chart-wrap{height:260px}
.table-card{margin-top:18px;overflow:hidden}
.table-scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:600px}
th{text-align:left;color:#8993a9;font-size:11px;font-weight:500;padding:13px 15px;border-bottom:1px solid var(--border)}
td{padding:15px;font-size:12px;border-bottom:1px solid #202638}
.empty{text-align:center;color:var(--muted);padding:30px}
.status{display:inline-block;border-radius:20px;padding:6px 9px;font-size:10px;background:#263148;color:#b6c8ff}
.status.Completed,.status.Delivered{background:#14372f;color:#6fe5b5}
.status.Confirmed{background:#18354b;color:#83d5ff}
.status.Shipped{background:#49351e;color:#ffd18a}
.status.Cancelled{background:#482633;color:#ff9aaa}
.status.Processing{background:#3b3152;color:#d2b9ff}
.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap}
.toolbar h2{font-size:19px;margin:0}
.search{width:220px;max-width:100%;padding:11px;background:var(--panel);border:1px solid var(--border);color:white;border-radius:8px}
.modal{position:fixed;inset:0;background:#000b;display:none;place-items:center;padding:20px;z-index:20}
.modal.open{display:grid}
.modal-box{background:var(--panel);border:1px solid var(--border);border-radius:16px;width:100%;max-width:440px;padding:24px;max-height:90vh;overflow:auto}
.modal-head{display:flex;justify-content:space-between;align-items:center}
.modal-head h3{margin:0}
.close{background:none;border:0;color:white;font-size:22px}
.form-label{font-size:11px;color:var(--muted);display:block;margin-top:10px}
.actions{display:flex;gap:7px;flex-wrap:wrap}
.small{padding:7px 10px;font-size:10px}
.toast{position:fixed;right:20px;bottom:20px;background:#20283b;border:1px solid var(--border);padding:14px 18px;border-radius:10px;display:none;z-index:30;font-size:12px}
.mobile-menu{display:none}
@media(max-width:1000px){.stats{grid-template-columns:repeat(2,1fr)}.content-grid{grid-template-columns:1fr}}
@media(max-width:700px){
.sidebar{transform:translateX(-100%);transition:.25s;width:250px}
.sidebar.open{transform:translateX(0)}
.main{margin-left:0;padding:20px 14px}
.mobile-menu{display:block}
.topbar h1{font-size:20px}
.stats{gap:9px}
.card{padding:14px}
.stat-value{font-size:22px}
.user-pill{display:none}
}
</style>
</head>
<body>

<div class="login-screen" id="loginScreen">
<div class="login-box">
<div class="logo">BizFlow<span>360.</span></div>
<div class="subtitle">Your business. One intelligent workspace.</div>
<form id="loginForm">
<label class="form-label">Username</label>
<input class="field" name="username" placeholder="Enter username" required>
<label class="form-label">Password</label>
<input class="field" name="password" type="password" placeholder="Enter password" required>
<button class="btn full">Sign In →</button>
</form>
<p id="loginError" style="color:#ff8094;font-size:12px"></p>
</div>
</div>

<div class="layout" id="appLayout">
<aside class="sidebar" id="sidebar">
<div class="brand"><div class="logo">BizFlow<span>360.</span></div><div class="subtitle">BUSINESS MANAGEMENT</div></div>
<div class="nav-label">WORKSPACE</div>
<button class="nav-btn active" data-page="dashboard">▦ Dashboard</button>
<button class="nav-btn" data-page="customers">♙ Customers</button>
<button class="nav-btn" data-page="products">▣ Inventory</button>
<button class="nav-btn" data-page="orders">⇄ Orders</button>
<div class="nav-label">MANAGEMENT</div>
<button class="nav-btn" data-page="invoices">▤ Invoices</button>
<button class="nav-btn" data-page="settings">⚙ Settings</button>
<div class="sidebar-bottom">
<div class="subtitle">BizFlow 360 · Version 1.0</div>
<button class="nav-btn" id="logoutBtn">↪ Sign Out</button>
</div>
</aside>

<main class="main">
<header class="topbar">
<div>
<button class="btn secondary mobile-menu" id="menuBtn">☰</button>
<h1 id="pageTitle">Dashboard</h1>
<p>Welcome back! Here's your business overview.</p>
</div>
<div class="user-pill">● <span id="username">Admin</span></div>
</header>

<section class="page active" id="dashboard">
<div class="stats">
<div class="card"><div class="stat-title">Total Revenue</div><div class="stat-value" id="revenue">Rs 0</div><div class="stat-note">All non-cancelled orders</div></div>
<div class="card"><div class="stat-title">Total Orders</div><div class="stat-value" id="ordersCount">0</div><div class="stat-note">All recorded orders</div></div>
<div class="card"><div class="stat-title">Customers</div><div class="stat-value" id="customersCount">0</div><div class="stat-note">Registered customers</div></div>
<div class="card"><div class="stat-title">Products</div><div class="stat-value" id="productsCount">0</div><div class="stat-note">Inventory items</div></div>
</div>
<div class="stats">
<div class="card"><div class="stat-title">Pending Orders</div><div class="stat-value" id="pendingCount">0</div></div>
<div class="card"><div class="stat-title">Low Stock Items</div><div class="stat-value" id="lowStock">0</div></div>
</div>
<div class="content-grid">
<div class="card">
<div class="card-heading"><h3>Business Performance</h3><span>Monthly revenue</span></div>
<div class="chart-wrap"><canvas id="salesChart"></canvas></div>
</div>
<div class="card">
<div class="card-heading"><h3>Quick Actions</h3></div>
<button class="btn full" onclick="openModal('customer')">＋ Add Customer</button><br><br>
<button class="btn secondary full" onclick="openModal('product')">＋ Add Product</button><br><br>
<button class="btn secondary full" onclick="openModal('order')">＋ Create Order</button>
</div>
</div>
<div class="card table-card">
<div class="card-heading"><h3>Recent Orders</h3><span>Latest 5</span></div>
<div class="table-scroll"><table><thead><tr><th>ORDER</th><th>CUSTOMER</th><th>PRODUCT</th><th>TOTAL</th><th>STATUS</th></tr></thead><tbody id="recentOrders"></tbody></table></div>
</div>
</section>

<section class="page" id="customers">
<div class="toolbar"><h2>Customer Directory</h2><button class="btn" onclick="openModal('customer')">＋ Add Customer</button></div>
<div class="card table-card"><div class="table-scroll"><table><thead><tr><th>NAME</th><th>COMPANY</th><th>EMAIL</th><th>PHONE</th><th>ACTIONS</th></tr></thead><tbody id="customerRows"></tbody></table></div></div>
</section>

<section class="page" id="products">
<div class="toolbar"><h2>Inventory Management</h2><button class="btn" onclick="openModal('product')">＋ Add Product</button></div>
<div class="card table-card"><div class="table-scroll"><table><thead><tr><th>PRODUCT</th><th>CATEGORY</th><th>PRICE</th><th>STOCK</th><th>ACTIONS</th></tr></thead><tbody id="productRows"></tbody></table></div></div>
</section>

<section class="page" id="orders">
<div class="toolbar"><h2>Order Management</h2><button class="btn" onclick="openModal('order')">＋ Create Order</button></div>
<div class="card table-card"><div class="table-scroll"><table><thead><tr><th>ORDER</th><th>CUSTOMER</th><th>PRODUCT</th><th>QTY</th><th>TOTAL</th><th>STATUS</th><th>ACTIONS</th></tr></thead><tbody id="orderRows"></tbody></table></div></div>
</section>

<section class="page" id="invoices">
<div class="toolbar"><h2>Invoice Center</h2><span class="subtitle">Generate printable invoices from orders.</span></div>
<div class="card table-card"><div class="table-scroll"><table><thead><tr><th>INVOICE</th><th>CUSTOMER</th><th>PRODUCT</th><th>AMOUNT</th><th>STATUS</th><th>ACTIONS</th></tr></thead><tbody id="invoiceRows"></tbody></table></div></div>
</section>

<section class="page" id="settings">
<div class="toolbar">
    <h2>Admin Settings</h2>
    <span class="subtitle">Manage your business, preferences and account</span>
</div>
<div class="content-grid">
    <div class="card">
        <div class="card-heading"><h3>🏢 Business Profile</h3></div>
        <form id="businessForm">
            <label class="form-label">Business Name</label>
            <input class="field" name="business_name" maxlength="150" required>
            <label class="form-label">Business Email</label>
            <input class="field" name="business_email" type="email">
            <label class="form-label">Phone Number</label>
            <input class="field" name="business_phone">
            <label class="form-label">Business Address</label>
            <input class="field" name="business_address">
            <label class="form-label">Currency</label>
            <select class="field" name="currency">
                <option value="PKR">PKR - Pakistani Rupee</option>
                <option value="USD">USD - US Dollar</option>
                <option value="EUR">EUR - Euro</option>
                <option value="GBP">GBP - British Pound</option>
            </select>
            <button class="btn full">Save Business Profile</button>
        </form>
    </div>
    <div class="card">
        <div class="card-heading"><h3>⚙ Application Preferences</h3></div>
        <form id="preferencesForm">
            <label class="form-label">Low Stock Alert Threshold</label>
            <input class="field" name="low_stock_threshold" type="number" min="0" max="10000" required>
            <label class="form-label">Default Order Status</label>
            <select class="field" name="default_order_status">
                <option>Pending</option><option>Confirmed</option>
                <option>Processing</option><option>Shipped</option><option>Delivered</option>
            </select>
            <button class="btn full">Save Preferences</button>
        </form>
    </div>
    <div class="card">
        <div class="card-heading"><h3>🔐 Account Security</h3></div>
        <form id="credentialsForm">
            <label class="form-label">Current Password</label>
            <input class="field" name="current_password" type="password" autocomplete="current-password" required>
            <label class="form-label">New Username</label>
            <input class="field" name="new_username" minlength="3" maxlength="50" required>
            <label class="form-label">New Password (at least 10 characters)</label>
            <input class="field" name="new_password" type="password" minlength="10" maxlength="128" autocomplete="new-password" required>
            <button class="btn full">Update Login Details</button>
        </form>
        <p class="stat-title">Your current password is required before changing login details.</p>
    </div>
    <div class="card">
        <div class="card-heading"><h3>📊 System Information</h3></div>
        <p class="stat-title">Application: BizFlow 360</p>
        <p class="stat-title">Version: 1.1.0</p>
        <p class="stat-title">Database: Configured server database</p>
        <p class="stat-title">Total Customers: <b id="sysCustomers">0</b></p>
        <p class="stat-title">Total Products: <b id="sysProducts">0</b></p>
        <p class="stat-title">Total Orders: <b id="sysOrders">0</b></p>
        <button class="btn secondary full" type="button" onclick="loadSettings()">↻ Refresh Information</button>
    </div>
</div>
</section>
</main>
</div>

<div class="modal" id="modal">
<div class="modal-box">
<div class="modal-head"><h3 id="modalTitle">Add New</h3><button class="close" onclick="closeModal()">×</button></div>
<form id="modalForm"></form>
</div>
</div>
<div class="toast" id="toast"></div>

<script>
const $ = id => document.getElementById(id);
let customers=[], products=[], orders=[], chart=null;
let currentSettings = {};
let currentCurrency = "PKR";
let editId=null, modalType=null;

async function api(url, options={}) {
    const response=await fetch(url,{
        ...options,
        headers:{"Content-Type":"application/json",...(options.headers||{})}
    });
    const data=await response.json().catch(()=>({}));
    if(!response.ok) {
        if(response.status===401) showLogin();
        throw new Error(data.detail || "Something went wrong");
    }
    return data;
}

function notify(message) {
    $("toast").textContent=message;
    $("toast").style.display="block";
    setTimeout(()=>$("toast").style.display="none",2800);
}

function showLogin() {
    $("loginScreen").style.display="grid";
    $("appLayout").style.display="none";
}

function showApp(username) {
    $("loginScreen").style.display="none";
    $("appLayout").style.display="block";
    $("username").textContent=username;
    loadAll();
}

$("loginForm").onsubmit=async e=>{
    e.preventDefault();
    const form=new FormData(e.target);
    try {
        const result=await api("/api/login",{
            method:"POST",
            body:JSON.stringify({
                username:form.get("username"),
                password:form.get("password")
            })
        });
        showApp(form.get("username"));
    } catch(err) {
        $("loginError").textContent=err.message;
    }
};

$("logoutBtn").onclick=async()=>{
    await api("/api/logout",{method:"POST"});
    showLogin();
};

$("menuBtn").onclick=()=>$("sidebar").classList.toggle("open");

document.querySelectorAll(".nav-btn[data-page]").forEach(btn=>{
    btn.onclick=()=>{
        document.querySelectorAll(".nav-btn").forEach(b=>b.classList.remove("active"));
        btn.classList.add("active");
        document.querySelectorAll(".page").forEach(p=>p.classList.remove("active"));
        $(btn.dataset.page).classList.add("active");
        $("pageTitle").textContent=btn.textContent.trim();
        $("sidebar").classList.remove("open");
        if (btn.dataset.page === "settings") loadSettings();
    };
});

async function loadAll() {
    try {
        try {
            currentSettings = await api("/api/settings");
            currentCurrency = currentSettings.currency || "PKR";
        } catch (_) {}
        [customers,products,orders]=await Promise.all([
            api("/api/customers"),api("/api/products"),api("/api/orders")
        ]);
        renderCustomers();
        renderProducts();
        renderOrders();
        renderInvoices();
        await loadDashboard();
    } catch(e) { notify(e.message); }
}

function money(value) {
    return currentCurrency + " " + Number(value || 0).toLocaleString("en-PK", {
        maximumFractionDigits: 2
    });
}

function escapeHTML(value) {
    return String(value??"").replace(/[&<>"']/g,c=>({
        "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    }[c]));
}

function statusTag(status) {
    return `<span class="status ${escapeHTML(status)}">${escapeHTML(status)}</span>`;
}

async function loadDashboard() {
    const d=await api("/api/dashboard");
    $("revenue").textContent=money(d.revenue);
    $("ordersCount").textContent=d.orders;
    $("customersCount").textContent=d.customers;
    $("productsCount").textContent=d.products;
    $("pendingCount").textContent=d.pending;
    $("lowStock").textContent=d.low_stock;

    $("recentOrders").innerHTML=d.recent.length?d.recent.map(o=>`
        <tr><td>#${o.id}</td><td>${escapeHTML(o.customer)}</td>
        <td>${escapeHTML(o.product)}</td><td>${money(o.total)}</td>
        <td>${statusTag(o.status)}</td></tr>
    `).join(""):`<tr><td colspan="5" class="empty">No orders yet</td></tr>`;

    const labels=d.monthly.map(x=>x.month);
    const values=d.monthly.map(x=>x.revenue);
    if(chart) chart.destroy();
    chart=new Chart($("salesChart"),{
        type:"line",
        data:{
            labels,
            datasets:[{
                label:"Revenue",
                data:values,
                borderColor:"#8867ff",
                backgroundColor:"rgba(136,103,255,.15)",
                fill:true,
                tension:.4
            }]
        },
        options:{
            responsive:true,maintainAspectRatio:false,
            plugins:{legend:{display:false}},
            scales:{
                x:{ticks:{color:"#929bb1"},grid:{display:false}},
                y:{ticks:{color:"#929bb1"},grid:{color:"#252d41"}}
            }
        }
    });
}

function renderCustomers() {
    $("customerRows").innerHTML=customers.length?customers.map(c=>`
        <tr><td>${escapeHTML(c.name)}</td><td>${escapeHTML(c.company)}</td>
        <td>${escapeHTML(c.email)}</td><td>${escapeHTML(c.phone)}</td>
        <td><div class="actions">
        <button class="btn secondary small" onclick="editCustomer(${c.id})">Edit</button>
        <button class="btn danger small" onclick="deleteCustomer(${c.id})">Delete</button>
        </div></td></tr>
    `).join(""):`<tr><td colspan="5" class="empty">No customers added</td></tr>`;
}

function renderProducts() {
    $("productRows").innerHTML=products.length?products.map(p=>`
        <tr><td>${escapeHTML(p.name)}</td><td>${escapeHTML(p.category)}</td>
        <td>${money(p.price)}</td><td>${p.stock<=5?`<span style="color:#ff879b">${p.stock} Low stock</span>`:p.stock}</td>
        <td><div class="actions">
        <button class="btn secondary small" onclick="editProduct(${p.id})">Edit</button>
        <button class="btn danger small" onclick="deleteProduct(${p.id})">Delete</button>
        </div></td></tr>
    `).join(""):`<tr><td colspan="5" class="empty">No products added</td></tr>`;
}

function renderOrders() {
    $("orderRows").innerHTML=orders.length?orders.map(o=>`
        <tr><td>#${o.id}</td><td>${escapeHTML(o.customer)}</td>
        <td>${escapeHTML(o.product)}</td><td>${o.quantity}</td>
        <td>${money(o.total)}</td><td>${statusTag(o.status)}</td>
        <td><div class="actions">
        <button class="btn secondary small" onclick="changeStatus(${o.id})">Status</button>
        <button class="btn secondary small" onclick="printInvoice(${o.id})">Invoice</button>
        </div></td></tr>
    `).join(""):`<tr><td colspan="7" class="empty">No orders added</td></tr>`;
}

function renderInvoices() {
    $("invoiceRows").innerHTML=orders.length?orders.map(o=>`
        <tr><td>BF-${String(o.id).padStart(5,"0")}</td>
        <td>${escapeHTML(o.customer)}</td><td>${escapeHTML(o.product)}</td>
        <td>${money(o.total)}</td><td>${statusTag(o.status)}</td>
        <td><button class="btn secondary small" onclick="printInvoice(${o.id})">View / Print</button></td></tr>
    `).join(""):`<tr><td colspan="6" class="empty">Invoices will appear here</td></tr>`;
}

function openModal(type,id=null) {
    modalType=type;editId=id;
    $("modal").classList.add("open");
    const existing=type==="customer"?customers.find(x=>x.id===id):
        type==="product"?products.find(x=>x.id===id):null;

    const fields={
        customer:[
            ["name","Customer Name","text"],
            ["email","Email Address","email"],
            ["phone","Phone Number","text"],
            ["company","Company","text"]
        ],
        product:[
            ["name","Product Name","text"],
            ["category","Category","text"],
            ["price","Price (PKR)","number"],
            ["stock","Stock Quantity","number"]
        ]
    };

    $("modalTitle").textContent=id?"Edit "+type:"Add "+type;
    if(type==="order") {
        $("modalTitle").textContent="Create New Order";
        $("modalForm").innerHTML=`
            <label class="form-label">Customer</label>
            <select class="field" name="customer_id" required>
                ${customers.map(c=>`<option value="${c.id}">${escapeHTML(c.name)}</option>`).join("")}
            </select>
            <label class="form-label">Product</label>
            <select class="field" name="product_id" required>
                ${products.filter(p=>p.stock>0).map(p=>`<option value="${p.id}">${escapeHTML(p.name)} · ${money(p.price)} · Stock ${p.stock}</option>`).join("")}
            </select>
            <label class="form-label">Quantity</label>
            <input class="field" name="quantity" type="number" min="1" value="1" required>
            <button class="btn full">Create Order</button>`;
    } else {
        $("modalForm").innerHTML=fields[type].map(([name,label,inputType])=>`
            <label class="form-label">${label}</label>
            <input class="field" name="${name}" type="${inputType}"
            ${inputType==="number"?'min="0" step="0.01"':''}
            value="${escapeHTML(existing?.[name]??"")}" required>
        `).join("")+`<button class="btn full">${id?"Save Changes":"Add "+type}</button>`;
    }
    $("modalForm").onsubmit=submitModal;
}

async function submitModal(e) {
    e.preventDefault();
    const form=new FormData(e.target);
    const data=Object.fromEntries(form.entries());
    if(modalType==="product") {
        data.price=Number(data.price);data.stock=Number(data.stock);
    }
    if(modalType==="order") {
        data.customer_id=Number(data.customer_id);
        data.product_id=Number(data.product_id);
        data.quantity=Number(data.quantity);
    }

    try {
        const url=modalType==="order"?"/api/orders":
            ` /api/${modalType==="customer"?"customers":"products"}`.trim()+
            (editId?"/"+editId:"");
        await api(url,{
            method:modalType==="order"?"POST":editId?"PUT":"POST",
            body:JSON.stringify(data)
        });
        closeModal();notify("Saved successfully");await loadAll();
    } catch(err) {notify(err.message);}
}

function closeModal() {
    $("modal").classList.remove("open");
}

function editCustomer(id){openModal("customer",id)}
function editProduct(id){openModal("product",id)}

async function deleteCustomer(id) {
    if(!confirm("Delete this customer?"))return;
    try{await api("/api/customers/"+id,{method:"DELETE"});notify("Customer deleted");await loadAll();}
    catch(e){notify(e.message)}
}

async function deleteProduct(id) {
    if(!confirm("Delete this product?"))return;
    try{await api("/api/products/"+id,{method:"DELETE"});notify("Product deleted");await loadAll();}
    catch(e){notify(e.message)}
}


async function changeStatus(id) {
    const order = orders.find(o => o.id === id);
    if (!order) return;

    const statuses = ["Pending", "Confirmed", "Processing", "Shipped", "Delivered", "Cancelled"];
    const choice = prompt(
        "Select order status by number:\n" +
        statuses.map((status, index) => `${index + 1}. ${status}`).join("\n"),
        String(Math.max(0, statuses.indexOf(order.status)) + 1)
    );
    if (choice === null || choice.trim() === "") return;

    const index = Number(choice) - 1;
    if (!Number.isInteger(index) || index < 0 || index >= statuses.length) {
        notify("Please select a number from 1 to 6.");
        return;
    }

    try {
        await api(`/api/orders/${id}/status`, {
            method: "PUT",
            body: JSON.stringify({ status: statuses[index] })
        });
        notify("Order status updated!");
        await loadAll();
    } catch (e) {
        notify(e.message);
    }
}


async function printInvoice(id) {
    try {
        const i=await api("/api/invoices/"+id);
        const businessName = escapeHTML(currentSettings.business_name || "BizFlow 360");
        const w=window.open("","_blank");
        if(!w){notify("Allow pop-ups to print invoices");return;}
        w.document.write(`
        <!DOCTYPE html><html><head><title>${escapeHTML(i.invoice_number)}</title>
        <style>
        body{font-family:Arial,sans-serif;padding:45px;color:#222}
        h1{color:#6651d8}hr{border:0;border-top:1px solid #ddd;margin:25px 0}
        .row{display:flex;justify-content:space-between;margin:14px 0}
        .total{font-size:22px;font-weight:bold}
        </style></head><body>
        <h1>${businessName}</h1><p>BUSINESS INVOICE</p><hr>
        <div class="row"><b>Invoice</b><span>${escapeHTML(i.invoice_number)}</span></div>
        <div class="row"><b>Date</b><span>${escapeHTML(i.date)}</span></div>
        <div class="row"><b>Customer</b><span>${escapeHTML(i.customer)}</span></div>
        <div class="row"><b>Email</b><span>${escapeHTML(i.email)}</span></div>
        <hr><div class="row"><b>Product</b><span>${escapeHTML(i.product)}</span></div>
        <div class="row"><b>Quantity</b><span>${i.quantity}</span></div>
        <div class="row"><b>Unit price</b><span>${money(i.unit_price)}</span></div>
        <hr><div class="row total"><span>Total</span><span>${money(i.total)}</span></div>
        <p>Status: ${escapeHTML(i.status)}</p>
        <hr><p>Thank you for your business!</p>
        <script>window.onload=()=>window.print();<\/script>
        </body></html>`);
        w.document.close();
    }catch(e){notify(e.message)}
}

async function loadSettings() {
    try {
        currentSettings = await api("/api/settings");
        currentCurrency = currentSettings.currency || "PKR";

        const businessForm = $("businessForm");
        const preferencesForm = $("preferencesForm");
        for (const [key, value] of Object.entries(currentSettings)) {
            const field = businessForm.elements[key] || preferencesForm.elements[key];
            if (field) field.value = value;
        }

        $("sysCustomers").textContent = customers.length;
        $("sysProducts").textContent = products.length;
        $("sysOrders").textContent = orders.length;
    } catch (e) {
        notify(e.message);
    }
}

async function saveSettings(payload) {
    const complete = { ...currentSettings, ...payload };
    const result = await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify(complete)
    });
    currentSettings = complete;
    currentCurrency = complete.currency || "PKR";
    return result;
}

$("businessForm").onsubmit = async e => {
    e.preventDefault();
    try {
        const data = Object.fromEntries(new FormData(e.target).entries());
        await saveSettings(data);
        notify("Business profile saved!");
        await loadAll();
    } catch (err) { notify(err.message); }
};

$("preferencesForm").onsubmit = async e => {
    e.preventDefault();
    try {
        const data = Object.fromEntries(new FormData(e.target).entries());
        data.low_stock_threshold = Number(data.low_stock_threshold);
        await saveSettings(data);
        notify("Application preferences saved!");
        await loadAll();
    } catch (err) { notify(err.message); }
};

$("credentialsForm").onsubmit = async e => {
    e.preventDefault();
    if (!confirm("Change your admin username and password?")) return;
    try {
        const data = Object.fromEntries(new FormData(e.target).entries());
        await api("/api/settings/credentials", {
            method: "POST",
            body: JSON.stringify(data)
        });
        e.target.reset();
        $("username").textContent = data.new_username;
        notify("Login details updated successfully!");
    } catch (err) { notify(err.message); }
};

async function start() {
    try {
        const me=await api("/api/me");
        if(me.authenticated)showApp(me.username);
        else showLogin();
    } catch(e) {showLogin();}
}
start();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


@app.get("/health")
def health():
    return {"status": "ok", "app": "BizFlow 360"}
