# 🛒 E-Commerce API

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Django-5.0-green?logo=django" alt="Django">
  <img src="https://img.shields.io/badge/SQLite-Database-lightgrey?logo=sqlite" alt="SQLite">
  <!-- <img src="https://img.shields.io/badge/PostgreSQL-Database-blue?logo=postgresql" alt="PostgreSQL"> -->
  <img src="https://img.shields.io/badge/HTML-Templates-orange?logo=html5" alt="HTML">
  <img src="https://img.shields.io/badge/CSS-Styles-blue?logo=css3" alt="CSS">
  <img src="https://img.shields.io/badge/REST-API-yellow?logo=fastapi" alt="REST API">
</p>

An E-Commerce API project built using **Python** and **Django**, with HTML templates for page rendering.

> **🔧 Project Status:** Under Construction 🚧

## 📌 Current Features

### ✅ Completed

- Project structure setup with Django.
- Product management (Create – Update – Delete – View).
- Shopping cart and checkout system.
- Security improvements (JWT Auth).
- User registration & login system with email verification.
- Advanced dashboard for sellers and customers.
- Media management for product images via `media/products`.
- Email templates added under `templates/email`.
- SQLite database integration.
- Static files support via `static` folder.
- Add Sellers Applications System.
- Add Coupons and Ocassion System.
- Fully documented API using Postman.


### ⏳ Pending

- Postgress database integration.
- integration with delevry company
- Payment gateway integration (Paymob) (Now : On delevry).
- Security improvements (CSRF Protection).
- Full project testing and deployment to production.

## 📂 Project Structure

```bash
E-Commerce-API/
│
├── API/                  # API-related files
├── Ecommerce_API/        # Project settings and configurations
├── media/products/       # Product images
├── static/               # Static assets (CSS/JS/images)
├── templates/email/      # Email HTML templates
├── db.sqlite3            # Local SQLite database
└── manage.py             # Django management script
```

## 🚀 How to Run

1. Clone the repository:
   git clone https://github.com/DevMo7md/E-Commerce-API.git
   cd E-Commerce-API

2. Create a virtual environment and install dependencies:
   python -m venv venv
   source venv/bin/activate # For Linux/Mac
   venv\Scripts\activate # For Windows
   pip install -r requirements.txt

3. Apply migrations:
   python manage.py migrate

4. Start the local server:
   python manage.py runserver

## 🗺 Roadmap

| Status     | Feature                                                 |
| ---------- | ------------------------------------------------------- |
| ✅ Done    | Project structure setup with Django                     |
| ✅ Done    | Product management (CRUD)                               |
| ✅ Done    | Media management for products                           |
| ✅ Done    | User authentication with email verification             |
| ✅ Done    | Advanced dashboard for sellers & customers              |
| ✅ Done    | Shopping cart and checkout system                       |
| ✅ Done    | Security enhancements (JWT Auth)                        |
| ✅ Done    | Add Sellers Applications System.                        |
| ✅ Done    | Add Coupons and Ocassion System.                        |
| ✅ Done    | API documentation via Postman                           |
| ⏳ Pending | Postgress database integration.                         |
| ⏳ Pending | integration with delevry company                        |
| ⏳ Pending | Payment gateway integration (Paymob) (Now : On delevry) |
| ⏳ Pending | Security enhancements (CSRF)                            |
| ⏳ Pending | Full testing and production deployment                  |
