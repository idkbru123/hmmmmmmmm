import os
import sqlite3
import time
import secrets
import requests
from flask import Flask, request, redirect, render_template_string, jsonify

app = Flask(__name__)

# ====== CẤU HÌNH (lấy từ biến môi trường) ======
CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
REDIRECT_URI = os.environ["REDIRECT_URI"]  # vd: https://yourdomain.com/callback
SETUP_SECRET = os.environ["SETUP_SECRET"]  # mật khẩu bí mật để bot gọi API set role, tự đặt tuỳ ý
LOG_WEBHOOK_URL = os.environ.get("LOG_WEBHOOK_URL")  # fallback nếu server không set webhook riêng
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS guild_settings (
            guild_id TEXT PRIMARY KEY,
            role_id TEXT NOT NULL,
            webhook_url TEXT
        )
    """)
    return conn

def get_real_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

def get_guild_settings(guild_id):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT role_id, webhook_url FROM guild_settings WHERE guild_id = ?", (guild_id,))
    row = cur.fetchone()
    conn.close()
    return row  # (role_id, webhook_url) hoặc None

# ====== API nội bộ: bot gọi vào đây để set role verify cho server của họ ======
# Dùng lệnh !setverifyrole trong bot.py (xem bot_snippet.py)
@app.route("/api/set-role", methods=["POST"])
def api_set_role():
    data = request.get_json(silent=True) or {}
    if data.get("secret") != SETUP_SECRET:
        return jsonify({"ok": False, "error": "sai secret"}), 403

    guild_id = str(data.get("guild_id", ""))
    role_id = str(data.get("role_id", ""))
    webhook_url = data.get("webhook_url")  # không bắt buộc
    if not guild_id or not role_id:
        return jsonify({"ok": False, "error": "thiếu guild_id/role_id"}), 400

    conn = db()
    conn.execute(
        """INSERT INTO guild_settings (guild_id, role_id, webhook_url)
           VALUES (?, ?, ?)
           ON CONFLICT(guild_id) DO UPDATE SET role_id=excluded.role_id,
             webhook_url=COALESCE(excluded.webhook_url, guild_settings.webhook_url)""",
        (guild_id, role_id, webhook_url),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ====== BƯỚC 1: User bấm nút trong Discord -> vào đây ======
@app.route("/verify")
def verify_start():
    guild_id = request.args.get("guild")
    if not guild_id:
        return "Thiếu tham số guild.", 400

    settings = get_guild_settings(guild_id)
    if not settings:
        return render_result(
            "⚠️ Server này chưa được cấu hình role verify. Admin cần gõ "
            "`!setverifyrole @role` trong Discord trước.",
            False,
        )

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

# ====== BƯỚC 2: Discord gửi user quay lại đây sau khi họ Authorize ======
@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state", "")
    if not code or ":" not in state:
        return render_result("❌ Yêu cầu không hợp lệ.", False)

    guild_id = state.split(":", 1)[0]
    settings = get_guild_settings(guild_id)
    if not settings:
        return render_result("❌ Server này chưa được cấu hình role verify.", False)
    role_id, guild_webhook = settings

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

    user_res = requests.get(
        f"{DISCORD_API}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if user_res.status_code != 200:
        return render_result("❌ Không lấy được thông tin tài khoản Discord.", False)
    user = user_res.json()
    discord_id = user["id"]
    username = user["username"]

    ip = get_real_ip()
    now = int(time.time())

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT discord_id, username FROM verifications WHERE ip = ? AND discord_id != ?",
        (ip, discord_id),
    )
    alt_matches = cur.fetchall()

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

    webhook = guild_webhook or LOG_WEBHOOK_URL

    if alt_matches:
        notify_admin(webhook, guild_id, discord_id, username, ip, alt_matches)
        return render_result(
            "⚠️ Tài khoản của bạn đã được ghi nhận, nhưng hệ thống phát hiện IP này "
            "từng được dùng để verify cho tài khoản Discord khác. Quản trị viên server "
            "sẽ xem xét thủ công trước khi cấp quyền cho bạn.",
            False,
        )

    ok = assign_role(guild_id, discord_id, role_id)
    if not ok:
        return render_result(
            "⚠️ Xác thực thành công nhưng bot không gán được role (có thể bot thiếu quyền, "
            "role cao hơn role của bot, hoặc bạn đã rời server). Báo admin kiểm tra giúp.",
            False,
        )

    return render_result("✅ Xác thực thành công! Quay lại Discord, bạn đã được cấp quyền.", True)

def assign_role(guild_id, user_id, role_id):
    res = requests.put(
        f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}/roles/{role_id}",
        headers={"Authorization": f"Bot {BOT_TOKEN}"},
    )
    return res.status_code == 204

def notify_admin(webhook_url, guild_id, discord_id, username, ip, alt_matches):
    if not webhook_url:
        return
    alt_list = ", ".join(f"`{uid}` ({uname})" for uid, uname in alt_matches)
    content = (
        f"🚨 **Nghi ngờ Alt Account**\n"
        f"User mới verify: `{discord_id}` ({username})\n"
        f"IP trùng với: {alt_list}\n"
        f"Guild: `{guild_id}`"
    )
    try:
        requests.post(webhook_url, json={"content": content}, timeout=5)
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
