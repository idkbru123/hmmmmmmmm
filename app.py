import os
import sqlite3
import time
import secrets
import requests
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

# ====== CẤU HÌNH (lấy từ biến môi trường, xem README.md) ======
CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
REDIRECT_URI = os.environ["REDIRECT_URI"]  # vd: https://yourdomain.com/callback
VERIFIED_ROLE_ID = os.environ["VERIFIED_ROLE_ID"]
LOG_WEBHOOK_URL = os.environ.get("LOG_WEBHOOK_URL")  # webhook Discord để báo admin (không bắt buộc)
DB_PATH = os.environ.get("DB_PATH", "verify.db")

DISCORD_API = "https://discord.com/api/v10"

# ====== DATABASE ======
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS verifications (
            discord_id TEXT PRIMARY KEY,
            guild_id TEXT NOT NULL,
            username TEXT,
            ip TEXT NOT NULL,
            verified_at INTEGER NOT NULL
        )
    """)
    return conn

def get_real_ip():
    # Nếu chạy sau reverse proxy / platform hosting (Render, Railway, nginx...),
    # IP thật nằm trong header X-Forwarded-For. Nếu chạy trực tiếp thì dùng remote_addr.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

# ====== BƯỚC 1: User bấm nút trong Discord -> vào đây ======
@app.route("/verify")
def verify_start():
    guild_id = request.args.get("guild")
    if not guild_id:
        return "Thiếu tham số guild.", 400

    # state giúp mình biết request callback này thuộc guild nào + chống giả mạo (CSRF)
    state = f"{guild_id}:{secrets.token_urlsafe(16)}"

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
        "prompt": "none",
    }
    url = requests.Request("GET", f"{DISCORD_API}/oauth2/authorize", params=params).prepare().url
    return redirect(url)

# ====== BƯỚC 2: Discord gửi user quay lại đây sau khi họ bấm "Authorize" ======
@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state", "")
    if not code or ":" not in state:
        return render_result("❌ Yêu cầu không hợp lệ.", False)

    guild_id = state.split(":", 1)[0]

    # Đổi code lấy access token
    token_res = requests.post(
        f"{DISCORD_API}/oauth2/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if token_res.status_code != 200:
        return render_result("❌ Xác thực với Discord thất bại, thử lại.", False)
    access_token = token_res.json()["access_token"]

    # Lấy thông tin user Discord (identify)
    user_res = requests.get(
        f"{DISCORD_API}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if user_res.status_code != 200:
        return render_result("❌ Không lấy được thông tin tài khoản Discord.", False)
    user = user_res.json()
    discord_id = user["id"]
    username = f'{user["username"]}'

    ip = get_real_ip()
    now = int(time.time())

    conn = db()
    cur = conn.cursor()

    # Kiểm tra IP này đã từng verify cho 1 Discord ID KHÁC chưa
    cur.execute(
        "SELECT discord_id, username FROM verifications WHERE ip = ? AND discord_id != ?",
        (ip, discord_id),
    )
    alt_matches = cur.fetchall()

    # Lưu/ cập nhật record của chính user này
    cur.execute(
        """INSERT INTO verifications (discord_id, guild_id, username, ip, verified_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(discord_id) DO UPDATE SET
             guild_id=excluded.guild_id, username=excluded.username,
             ip=excluded.ip, verified_at=excluded.verified_at""",
        (discord_id, guild_id, username, ip, now),
    )
    conn.commit()
    conn.close()

    if alt_matches:
        # KHÔNG tự động cấp role khi nghi ngờ trùng IP — chỉ báo admin, để admin tự quyết định.
        # (Trùng IP có thể do dùng chung wifi/mạng di động, không chắc chắn 100% là alt.)
        notify_admin(guild_id, discord_id, username, ip, alt_matches)
        return render_result(
            "⚠️ Tài khoản của bạn đã được ghi nhận, nhưng hệ thống phát hiện IP này "
            "từng được dùng để verify cho tài khoản Discord khác. Quản trị viên server "
            "sẽ xem xét thủ công trước khi cấp quyền cho bạn.",
            False,
        )

    ok = assign_role(guild_id, discord_id)
    if not ok:
        return render_result(
            "⚠️ Xác thực thành công nhưng bot không gán được role (có thể bot thiếu quyền "
            "hoặc bạn đã rời server). Báo admin kiểm tra giúp.",
            False,
        )

    return render_result("✅ Xác thực thành công! Quay lại Discord, bạn đã được cấp quyền.", True)

def assign_role(guild_id, user_id):
    res = requests.put(
        f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}/roles/{VERIFIED_ROLE_ID}",
        headers={"Authorization": f"Bot {BOT_TOKEN}"},
    )
    return res.status_code == 204

def notify_admin(guild_id, discord_id, username, ip, alt_matches):
    if not LOG_WEBHOOK_URL:
        return
    alt_list = ", ".join(f"`{uid}` ({uname})" for uid, uname in alt_matches)
    content = (
        f"🚨 **Nghi ngờ Alt Account**\n"
        f"User mới verify: `{discord_id}` ({username})\n"
        f"IP trùng với: {alt_list}\n"
        f"Guild: `{guild_id}`"
    )
    try:
        requests.post(LOG_WEBHOOK_URL, json={"content": content}, timeout=5)
    except Exception:
        pass

def render_result(message, success):
    color = "#43b581" if success else "#f04747"
    return render_template_string(
        """
        <html><head><meta charset="utf-8"><title>Verification</title>
        <style>
        body{background:#2f3136;color:#fff;font-family:sans-serif;
             display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
        .box{background:#36393f;padding:32px 40px;border-radius:12px;max-width:420px;text-align:center}
        .box p{border-left:4px solid {{color}};padding-left:12px;text-align:left}
        </style></head>
        <body><div class="box"><h2>Discord Verification</h2><p>{{message}}</p></div></body></html>
        """,
        message=message, color=color,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
