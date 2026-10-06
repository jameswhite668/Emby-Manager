# Emby Manager - Emby用户管理系统

一个基于 Flask + SQLite 的 Emby 用户管理系统，支持激活码注册、用户续期、观看记录同步、工单系统、客户端下载等功能。

## 功能特性

### 用户管理
- **多角色支持**：管理员和普通用户角色分离
- **激活码系统**：生成和管理激活码，支持多种时长类型（小时/天/周/月/年/永久）
- **到期提醒**：自动检查并禁用到期用户
- **登录安全**：登录失败限制、CSRF防护、密码加密存储

### Emby集成
- **服务器绑定**：绑定Emby服务器，自动同步用户状态
- **观看记录**：同步用户观看历史，支持剧集信息展示
- **媒体库管理**：管理用户可访问的媒体库权限
- **自动禁用**：到期自动禁用Emby用户访问权限

### 支付与财务
- **支付审核**：管理员审核用户支付订单
- **退款处理**：支持上传退款收款码，处理退款请求
- **金币系统**：金币充值、套餐购买
- **订单管理**：完整的订单生命周期管理

### 客户端支持
- **客户端下载**：管理各类客户端（Android/iOS/Windows/Mac/Linux）
- **多格式支持**：支持APK、IPA、EXE、DMG、DEB等多种格式
- **下载统计**：记录客户端下载次数

### 工单系统
- **在线客服**：用户与管理员实时沟通
- **图片支持**：支持粘贴截图和上传图片
- **消息已读**：实时显示消息已读状态
- **工单分类**：账号问题、技术问题、其他问题

### 系统优化
- **生产环境支持**：支持6000并发用户架构设计
- **性能优化**：数据库连接池、缓存层、多进程部署
- **安全防护**：文件上传校验、登录限制、SQL注入防护
- **定时任务**：每日零时自动同步观看记录

## 快速开始

### 环境要求

- Python 3.8+
- pip 包管理器

### 安装步骤

#### 方式1：使用启动脚本（推荐）

```bash
# 1. 安装依赖
python start_production.py --install

# 2. 启动服务器
python start_production.py --waitress
```

#### 方式2：手动安装

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动开发服务器
python app.py

# 或启动生产服务器（推荐）
python start_production.py --waitress
```

### 访问地址

- 首页：`http://localhost:5001/`
- 登录页面：`http://localhost:5001/login`
- 注册页面：`http://localhost:5001/register`
- 管理后台：`http://localhost:5001/admin/dashboard`
- 用户中心：`http://localhost:5001/user/dashboard`

## 默认账号

系统初始化时会自动创建默认管理员账号：

- **用户名**：`admin`
- **密码**：`123`

**注意**：首次登录后请立即修改默认密码！

## 目录结构

```
V16/
├── app.py                      # 主应用文件
├── start_production.py         # 生产环境启动脚本
├── requirements.txt            # Python依赖
├── README.md                   # 项目说明
├── gunicorn.conf.py           # Gunicorn配置（Linux/Mac）
├── production_config.py       # 生产环境配置
├── nginx.conf                 # Nginx反向代理配置
├── DEPLOYMENT.md              # 部署文档
│
├── database/
│   ├── models.py              # 数据库模型
│   └── emby_manager.db        # SQLite数据库（自动创建）
│
├── templates/
│   ├── index.html             # 首页
│   ├── login.html             # 登录页
│   ├── register.html          # 注册页
│   ├── admin/                 # 管理员页面
│   │   ├── dashboard.html
│   │   ├── users.html
│   │   ├── activation.html
│   │   ├── bind.html
│   │   ├── payment_audit.html
│   │   ├── client_downloads.html
│   │   ├── tickets.html
│   │   └── profile.html
│   └── user/                  # 用户页面
│       ├── base.html
│       ├── dashboard.html
│       ├── history.html
│       ├── profile.html
│       ├── payment.html
│       ├── recharge.html
│       ├── server.html
│       ├── client_downloads.html
│       └── tickets.html
│
├── static/
│   ├── css/                   # 样式文件
│   ├── js/                    # JavaScript文件
│   ├── images/                # 图片资源
│   │   ├── refund_qrcodes/   # 退款收款码
│   │   └── clients/          # 客户端图标
│   └── downloads/            # 客户端下载文件
│       └── clients/
│
├── logs/                     # 日志文件
├── cache/                    # 缓存文件
└── sessions/                 # 会话文件
```

## 使用说明

### 管理员操作

1. **登录后台**：使用默认账号 `admin/123` 登录
2. **生成激活码**：在"激活码管理"页面生成不同类型的激活码
3. **管理用户**：在"用户管理"页面查看、续期、禁用/启用用户
4. **绑定Emby**：在"绑定媒体库"页面配置服务器地址和API密钥
5. **支付审核**：在"支付审核"页面审核用户支付订单
6. **客户端管理**：在"客户端管理"页面上传和管理客户端
7. **工单处理**：在"工单管理"页面处理用户工单

### 普通用户操作

1. **注册账号**：使用管理员生成的激活码进行注册
2. **登录系统**：使用注册的账号密码登录
3. **查看信息**：在个人中心查看账户状态和到期时间
4. **续期账户**：使用新的激活码或在线支付进行续期
5. **观看记录**：在"观看历史"页面查看同步的观看记录
6. **下载客户端**：在"客户端下载"页面下载各类客户端
7. **提交工单**：在"我的工单"页面提交问题反馈

## API接口

### 认证相关
- `POST /api/login` - 用户登录
- `POST /api/logout` - 用户登出
- `POST /api/register` - 用户注册
- `POST /api/change-password` - 修改密码
- `GET /api/check-session` - 检查登录状态

### 管理员接口
- `GET /api/admin/users` - 获取用户列表
- `POST /api/admin/users/delete` - 删除用户
- `POST /api/admin/users/renew` - 用户续期
- `POST /api/admin/users/toggle` - 切换用户状态
- `GET /api/admin/codes` - 获取激活码列表
- `POST /api/admin/codes/generate` - 生成激活码
- `POST /api/admin/codes/delete` - 删除激活码
- `POST /api/admin/emby/bind` - 绑定Emby服务器
- `GET /api/admin/stats` - 获取统计数据
- `GET /api/admin/payment-orders` - 获取支付订单
- `POST /api/admin/payment-orders/batch-process` - 批量处理订单
- `GET /api/admin/client-downloads` - 获取客户端列表
- `POST /api/admin/client-downloads` - 添加客户端
- `GET /api/admin/tickets` - 获取工单列表
- `POST /api/admin/tickets/<id>/reply` - 回复工单

### 用户接口
- `GET /api/user/profile` - 获取个人信息
- `GET /api/user/history` - 获取观看记录
- `POST /api/user/sync-history` - 同步观看记录
- `POST /api/user/renew` - 使用激活码续期
- `GET /api/user/payment-orders` - 获取支付订单
- `POST /api/user/payment-orders` - 创建支付订单
- `POST /api/user/payment-order/<order_no>/refund-qrcode` - 上传退款收款码
- `GET /api/user/client-downloads` - 获取客户端列表
- `GET /api/user/tickets` - 获取工单列表
- `POST /api/user/tickets` - 创建工单
- `POST /api/user/tickets/<id>/reply` - 回复工单

## 生产环境部署

### 系统要求

- **最低配置**（支持1000并发）：
  - CPU: 4核
  - 内存: 8GB
  - 磁盘: 50GB SSD

- **推荐配置**（支持6000并发）：
  - CPU: 16核+
  - 内存: 32GB+
  - 磁盘: 200GB SSD
  - 网络: 1Gbps

### 部署步骤

1. **安装依赖**
```bash
python start_production.py --install
```

2. **配置Nginx**（推荐）
```bash
# Linux
sudo cp nginx.conf /etc/nginx/nginx.conf
sudo systemctl restart nginx
```

3. **启动服务**
```bash
# Windows
python start_production.py --waitress

# Linux/Mac
python start_production.py --gunicorn
```

详细部署文档请参考 [DEPLOYMENT.md](DEPLOYMENT.md)

## 安全特性

- **密码安全**：使用Werkzeug进行密码哈希存储
- **登录保护**：登录失败5次封禁5分钟
- **CSRF防护**：表单提交验证CSRF Token
- **文件上传安全**：扩展名白名单 + 文件魔数校验
- **SQL注入防护**：使用SQLAlchemy ORM，参数化查询
- **XSS防护**：模板自动转义，防止跨站脚本攻击
- **会话安全**：随机SECRET_KEY，会话过期机制

## 技术栈

- **后端**：Flask + SQLAlchemy + SQLite
- **前端**：HTML5 + CSS3 + Vanilla JavaScript
- **样式**：自定义粉色少女心主题
- **图表**：Chart.js（用于统计数据展示）
- **服务器**：Waitress(Windows) / Gunicorn(Linux/Mac)
- **反向代理**：Nginx

## 更新日志

### v1.0.0
- 基础用户管理功能
- Emby服务器集成
- 激活码系统

### v2.0.0
- 支付审核系统
- 客户端下载管理
- 工单系统
- 观看记录同步
- 生产环境优化

## 感谢支持
<img width="1122" height="1527" alt="24d2dba27e55124441b990463772d168" src="https://github.com/user-attachments/assets/d019ab6f-26f4-4a80-96af-34a8daf8a7a4" />


## 许可证

MIT License

## 注意事项

1. 首次运行时会自动创建数据库和默认管理员账号
2. 建议立即修改默认管理员密码
3. 绑定Emby服务器后可同步用户状态和观看记录
4. 系统会每分钟自动检查并禁用到期用户
5. 每日零时自动同步未过期用户的观看记录
6. 过期用户无法访问媒体库地址页面和客户端下载页面
