#!/usr/bin/env python3
"""
MySQL General Log Generator — Realistic traffic with real SQLi attacks.
 
Generates a MySQL general query log file that the agent can tail.
Mixes normal webapp queries with actual SQL injection patterns
used in real-world attacks (OWASP Top 10, CTFs, bug bounties).
 
Usage:
    python3 generate_log.py                      # writes to /tmp/mysql_general.log
    python3 generate_log.py -o ./test.log        # custom output path
    python3 generate_log.py --speed fast         # fast mode (0.3s between queries)
    python3 generate_log.py --speed slow         # slow mode (3s between queries)
    python3 generate_log.py --sqli-ratio 0.5     # 50% of queries are SQLi
"""
 
import argparse
import random
import time
import os
from datetime import datetime, timezone
 
# ── Attacker + Legit IPs ──────────────────────────────
 
LEGIT_USERS = [
    {"thread": 1, "ip": "192.168.1.10",  "user": "webapp",  "db": "ecommerce"},
    {"thread": 2, "ip": "192.168.1.20",  "user": "api_svc", "db": "ecommerce"},
    {"thread": 3, "ip": "10.0.0.5",      "user": "admin",   "db": "ecommerce"},
    {"thread": 4, "ip": "192.168.1.30",  "user": "reports", "db": "analytics"},
    {"thread": 5, "ip": "10.0.0.15",     "user": "crm_app", "db": "customers"},
]
 
ATTACKERS = [
    {"thread": 10, "ip": "45.33.32.156",   "user": "webapp",  "db": "ecommerce"},   # Nmap's scanme
    {"thread": 11, "ip": "185.220.101.34",  "user": "webapp",  "db": "ecommerce"},   # Tor exit
    {"thread": 12, "ip": "103.224.182.250", "user": "api_svc", "db": "ecommerce"},   # Sketchy VPS
    {"thread": 13, "ip": "91.240.118.172",  "user": "webapp",  "db": "ecommerce"},   # Known scanner
]
 
# ── Normal Queries (realistic webapp traffic) ─────────
 
NORMAL_QUERIES = [
    # Auth & sessions
    "SELECT id, username, email, role FROM users WHERE id = 1042",
    "SELECT session_token, expires_at FROM sessions WHERE user_id = 1042 AND active = 1",
    "UPDATE sessions SET last_seen = NOW() WHERE session_token = 'abc123def456'",
    "INSERT INTO login_attempts (user_id, ip, success, ts) VALUES (1042, '192.168.1.10', 1, NOW())",
 
    # Product browsing
    "SELECT p.id, p.name, p.price, p.stock, c.name AS category FROM products p JOIN categories c ON p.category_id = c.id WHERE p.active = 1 ORDER BY p.created_at DESC LIMIT 20",
    "SELECT * FROM products WHERE category_id = 7 AND price BETWEEN 10.00 AND 50.00 ORDER BY price ASC",
    "SELECT p.id, p.name, AVG(r.rating) as avg_rating FROM products p LEFT JOIN reviews r ON p.id = r.product_id GROUP BY p.id HAVING avg_rating >= 4.0 LIMIT 10",
    "SELECT id, name, description, price, image_url FROM products WHERE id = 2847",
    "SELECT name, rating, comment, created_at FROM reviews WHERE product_id = 2847 ORDER BY created_at DESC LIMIT 5",
 
    # Shopping cart
    "SELECT ci.product_id, ci.quantity, p.name, p.price FROM cart_items ci JOIN products p ON ci.product_id = p.id WHERE ci.cart_id = 'cart_8f3a2b'",
    "INSERT INTO cart_items (cart_id, product_id, quantity) VALUES ('cart_8f3a2b', 2847, 1)",
    "UPDATE cart_items SET quantity = 2 WHERE cart_id = 'cart_8f3a2b' AND product_id = 2847",
    "DELETE FROM cart_items WHERE cart_id = 'cart_8f3a2b' AND product_id = 1523",
 
    # Orders
    "INSERT INTO orders (user_id, total, status, shipping_address, created_at) VALUES (1042, 89.97, 'pending', '123 Main St, Colombo', NOW())",
    "SELECT o.id, o.total, o.status, o.created_at FROM orders o WHERE o.user_id = 1042 ORDER BY o.created_at DESC LIMIT 10",
    "UPDATE orders SET status = 'shipped', tracking_number = 'LK1234567890' WHERE id = 50321",
    "SELECT oi.product_id, oi.quantity, oi.unit_price, p.name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = 50321",
 
    # Search
    "SELECT id, name, price FROM products WHERE name LIKE '%wireless headphones%' LIMIT 20",
    "SELECT id, name, price FROM products WHERE MATCH(name, description) AGAINST('bluetooth speaker' IN BOOLEAN MODE) LIMIT 15",
 
    # Admin / internal
    "SELECT COUNT(*) as total_orders FROM orders WHERE DATE(created_at) = CURDATE()",
    "SELECT status, COUNT(*) as cnt FROM orders GROUP BY status",
    "SELECT u.username, COUNT(o.id) as order_count, SUM(o.total) as revenue FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.id ORDER BY revenue DESC LIMIT 10",
    "SHOW TABLES",
    "SELECT COUNT(*) FROM users WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
 
    # CRM
    "SELECT id, name, email, phone, company FROM contacts WHERE assigned_to = 15 ORDER BY last_contact DESC",
    "UPDATE contacts SET last_contact = NOW(), notes = 'Follow up call completed' WHERE id = 892",
    "INSERT INTO activity_log (contact_id, action, details, ts) VALUES (892, 'call', 'Discussed renewal pricing', NOW())",
]
 
# ── Real SQL Injection Payloads ───────────────────────
 
SQLI_ATTACKS = [
    # ── Authentication Bypass ──
    "SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'anything'",
    "SELECT * FROM users WHERE username = '' OR 1=1 -- ' AND password = ''",
    "SELECT * FROM users WHERE username = 'admin'-- ' AND password = 'x'",
    "SELECT * FROM users WHERE username = '' OR ''='' AND password = '' OR ''=''",
    "SELECT * FROM users WHERE username = 'admin' OR 1=1 LIMIT 1 -- ",
    "SELECT id FROM users WHERE email = 'test@test.com' OR 1=1; --' AND password = MD5('pass')",
 
    # ── UNION-Based Data Extraction ──
    "SELECT name, price FROM products WHERE id = 1 UNION SELECT username, password FROM users --",
    "SELECT name, price FROM products WHERE id = -1 UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema = database() --",
    "SELECT name, price FROM products WHERE id = -1 UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users' --",
    "SELECT name, price FROM products WHERE id = 0 UNION SELECT CONCAT(username,':',password), email FROM users --",
    "SELECT name FROM products WHERE id = 1 UNION SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables --",
    "SELECT id, name FROM products WHERE category_id = 7 UNION ALL SELECT credit_card_number, cvv FROM payment_info --",
 
    # ── Blind SQLi (Boolean-based) ──
    "SELECT * FROM products WHERE id = 1 AND (SELECT LENGTH(password) FROM users WHERE username='admin') > 5",
    "SELECT * FROM products WHERE id = 1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin') = 'a'",
    "SELECT * FROM products WHERE id = 1 AND (SELECT COUNT(*) FROM users WHERE role='admin') > 0 --",
    "SELECT * FROM users WHERE id = 1 AND 1=1",
    "SELECT * FROM users WHERE id = 1 AND 1=2",
 
    # ── Time-Based Blind SQLi ──
    "SELECT * FROM products WHERE id = 1; IF(1=1, WAITFOR DELAY '0:0:5', 0) --",
    "SELECT * FROM products WHERE id = 1 AND SLEEP(5) --",
    "SELECT * FROM users WHERE username = 'admin' AND IF(SUBSTRING(database(),1,1)='e', SLEEP(5), 0) --",
    "SELECT * FROM products WHERE id = 1 UNION SELECT SLEEP(5),2,3,4 --",
    "SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --",
 
    # ── Stacked Queries / Destructive ──
    "SELECT * FROM products WHERE id = 1; DROP TABLE users --",
    "SELECT * FROM products WHERE id = 1; INSERT INTO users (username, password, role) VALUES ('hacker', 'owned', 'admin') --",
    "SELECT * FROM products WHERE id = 1; UPDATE users SET password = 'hacked123' WHERE username = 'admin' --",
    "SELECT * FROM products WHERE id = 1; DELETE FROM orders --",
 
    # ── Error-Based SQLi ──
    "SELECT * FROM products WHERE id = 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) --",
    "SELECT * FROM products WHERE id = 1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    "SELECT * FROM products WHERE id = 1 AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1) --",
 
    # ── Second Order / Encoded ──
    "SELECT * FROM users WHERE username = CHAR(97,100,109,105,110) OR 1=1 --",
    "SELECT * FROM products WHERE id = 1 UNION SELECT 0x61646D696E, 0x70617373776F7264 --",
    "SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('whoami') --",
    "SELECT * FROM users WHERE id = 1; EXEC master..xp_cmdshell 'net user hacker P@ss123 /add' --",
 
    # ── WAF Evasion Techniques ──
    "SELECT * FROM users WHERE username = 'admin'/**/OR/**/1=1 --",
    "SELECT * FROM products WHERE id = 1 /*!UNION*/ /*!SELECT*/ username, password FROM users --",
    "SELECT * FROM users WHERE id = 1 uNiOn SeLeCt username, password FROM users --",
    "SELECT * FROM products WHERE id = 1 UNION%20SELECT%20username,password%20FROM%20users --",
 
    # ── Out-of-Band (OOB) ──
    "SELECT * FROM products WHERE id = 1 UNION SELECT LOAD_FILE('/etc/passwd'),2,3,4 --",
    "SELECT * FROM products WHERE id = 1 INTO OUTFILE '/tmp/dump.txt' --",
]
 
# ── Log Line Generator ────────────────────────────────
 
def timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
 
def connect_line(user):
    return f"{timestamp()}    {user['thread']} Connect    {user['user']}@{user['ip']} on {user['db']} using TCP/IP"
 
def query_line(thread_id, sql):
    return f"{timestamp()}    {thread_id} Query    {sql}"
 
def generate_traffic(log_path, speed, sqli_ratio):
    speeds = {"fast": 0.3, "normal": 1.0, "slow": 3.0, "realtime": 0.5}
    interval = speeds.get(speed, 1.0)
 
    print(f"""
╔══════════════════════════════════════════════════╗
║        MySQL Log Traffic Generator               ║
║        QueryGuard Testing Tool                   ║
╠══════════════════════════════════════════════════╣
║  Output:     {log_path:<35s}║
║  Speed:      {speed:<35s}║
║  SQLi Ratio: {sqli_ratio:<35.0%}║
║  Ctrl+C to stop                                  ║
╚══════════════════════════════════════════════════╝
    """)
 
    # Create or truncate the log file
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
 
    with open(log_path, "w") as f:
        # Write initial connect events for all users
        all_users = LEGIT_USERS + ATTACKERS
        for user in all_users:
            line = connect_line(user)
            f.write(line + "\n")
            f.flush()
 
        print("[*] Connect events written for all threads")
        time.sleep(1)
 
        query_count = 0
        sqli_count = 0
 
        try:
            while True:
                # Re-send connect events every 20 queries so agent always has mappings
                if query_count % 20 == 0:
                    for user in all_users:
                        line = connect_line(user)
                        f.write(line + "\n")
                    f.flush()
 
                is_attack = random.random() < sqli_ratio
 
                if is_attack:
                    # Pick an attacker thread and a real SQLi payload
                    attacker = random.choice(ATTACKERS)
                    sql = random.choice(SQLI_ATTACKS)
                    line = query_line(attacker["thread"], sql)
                    sqli_count += 1
                    marker = "🔴 ATTACK"
                else:
                    # Pick a legit user and normal query
                    user = random.choice(LEGIT_USERS)
                    sql = random.choice(NORMAL_QUERIES)
                    line = query_line(user["thread"], sql)
                    marker = "🟢 NORMAL"
 
                f.write(line + "\n")
                f.flush()
 
                query_count += 1
                short_sql = sql[:80] + "..." if len(sql) > 80 else sql
                print(f"  [{query_count:04d}] {marker}  {short_sql}")
 
                # Vary timing slightly for realism
                jitter = random.uniform(0.7, 1.3)
                time.sleep(interval * jitter)
 
        except KeyboardInterrupt:
            print(f"\n[*] Stopped. Generated {query_count} queries ({sqli_count} SQLi attacks)")
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MySQL General Log Traffic Generator")
    parser.add_argument("-o", "--output", default="/tmp/mysql_general.log", help="Output log file path")
    parser.add_argument("--speed", default="normal", choices=["fast", "normal", "slow", "realtime"], help="Query generation speed")
    parser.add_argument("--sqli-ratio", type=float, default=0.3, help="Ratio of SQLi attacks (0.0 to 1.0)")
    args = parser.parse_args()
 
    generate_traffic(args.output, args.speed, args.sqli_ratio)
 