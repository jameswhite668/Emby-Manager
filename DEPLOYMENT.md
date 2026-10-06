# 生产环境部署指南 - 支持6000并发用户

## 系统架构概述

本系统经过优化，可以支持6000并发用户访问。主要优化包括：

1. **数据库连接池优化** - 支持高并发数据库访问
2. **多进程/多线程服务器** - 使用Gunicorn（Linux/Mac）或Waitress（Windows）
3. **缓存层** - 内存+文件系统双级缓存
4. **反向代理** - Nginx负载均衡和静态文件服务
5. **性能监控** - 完整的性能测试工具

## 硬件要求

### 最低配置（支持1000并发）
- CPU: 4核
- 内存: 8GB
- 磁盘: 50GB SSD
- 网络: 100Mbps

### 推荐配置（支持6000并发）
- CPU: 16核+
- 内存: 32GB+
- 磁盘: 200GB SSD
- 网络: 1Gbps

## 软件依赖

```bash
# 基础依赖
pip install flask sqlalchemy werkzeug requests

# 生产环境依赖
pip install gunicorn waitress flask-compress flask-limiter

# 性能测试依赖
pip install aiohttp requests

# 可选：Redis缓存
pip install redis

# 可选：MySQL数据库
pip install pymysql
```

## 部署步骤

### 1. 基础配置

```bash
# 克隆或复制项目到服务器
cd /path/to/emby_manager

# 创建必要的目录
mkdir -p logs cache sessions static/downloads/clients

# 设置环境变量
export FLASK_ENV=production
export SECRET_KEY=your-secret-key-here
```

### 2. 数据库优化（推荐升级到MySQL）

#### SQLite配置（适合小型部署）
已内置优化配置，无需额外操作。

#### MySQL配置（推荐用于6000并发）

```sql
-- 创建数据库
CREATE DATABASE emby_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 创建用户
CREATE USER 'emby_manager'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON emby_manager.* TO 'emby_manager'@'localhost';
FLUSH PRIVILEGES;
```

修改 `app.py` 中的数据库连接：

```python
# MySQL配置示例
engine = create_engine(
    'mysql+pymysql://emby_manager:your_password@localhost/emby_manager',
    pool_size=50,
    max_overflow=100,
    pool_timeout=30,
    pool_recycle=3600,
    pool_pre_ping=True,
)
```

### 3. 启动应用服务器

#### Windows（使用Waitress）

```bash
python start_production.py --waitress
```

#### Linux/Mac（使用Gunicorn）

```bash
# 方式1：使用配置文件
gunicorn -c gunicorn.conf.py app:app

# 方式2：使用启动脚本
python start_production.py --gunicorn
```

#### 多实例部署（推荐用于6000并发）

启动多个应用实例，配合Nginx负载均衡：

```bash
# 实例1
gunicorn -c gunicorn.conf.py --bind 0.0.0.0:5001 app:app

# 实例2
gunicorn -c gunicorn.conf.py --bind 0.0.0.0:5002 app:app

# 实例3
gunicorn -c gunicorn.conf.py --bind 0.0.0.0:5003 app:app
```

### 4. 配置Nginx反向代理

```bash
# 复制配置文件
sudo cp nginx.conf /etc/nginx/nginx.conf

# 测试配置
sudo nginx -t

# 重启Nginx
sudo systemctl restart nginx
```

### 5. 系统优化

#### Linux系统优化

```bash
# 修改文件描述符限制
sudo vim /etc/security/limits.conf

# 添加以下内容
* soft nofile 65535
* hard nofile 65535

# 修改内核参数
sudo vim /etc/sysctl.conf

# 添加以下内容
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 16384 4194304
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 1024 65535

# 应用配置
sudo sysctl -p
```

## 性能测试

### 快速测试

```bash
# 测试100个顺序请求
python performance_test.py --url http://localhost:5001 --users 100 --quick
```

### 并发测试

```bash
# 测试1000并发用户
python performance_test.py --url http://localhost:5001 --users 1000 --requests 10

# 测试6000并发用户（需要较长时间）
python performance_test.py --url http://localhost:5001 --users 6000 --requests 10 --save
```

### 测试结果分析

- **RPS（每秒请求数）**: 目标 > 1000
- **平均响应时间**: 目标 < 1秒
- **成功率**: 目标 > 99%

## 监控和维护

### 日志监控

```bash
# 查看应用日志
tail -f logs/emby_manager.log

# 查看Gunicorn访问日志
tail -f logs/gunicorn_access.log

# 查看Gunicorn错误日志
tail -f logs/gunicorn_error.log

# 查看Nginx日志
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

### 性能监控

```bash
# 查看系统资源使用
top
htop

# 查看网络连接
netstat -an | grep :5001 | wc -l
ss -an | grep :5001 | wc -l

# 查看数据库连接
lsof -i :5001 | wc -l
```

### 定期维护

```bash
# 清理日志（每周）
find logs/ -name "*.log" -type f -mtime +7 -delete

# 清理缓存（每天）
find cache/ -name "*.cache" -type f -mtime +1 -delete

# 数据库优化（每月）
sqlite3 database/emby_manager.db "VACUUM;"
```

## 故障排除

### 1. 连接数过多

**症状**: 无法建立新连接，返回502错误

**解决**:
```bash
# 增加文件描述符限制
ulimit -n 65535

# 重启应用服务器
pkill gunicorn
gunicorn -c gunicorn.conf.py app:app
```

### 2. 内存不足

**症状**: 系统变慢，OOM错误

**解决**:
- 减少Gunicorn工作进程数
- 增加服务器内存
- 启用Swap分区

### 3. 数据库锁定（SQLite）

**症状**: 数据库锁定错误

**解决**:
- 升级到MySQL/PostgreSQL
- 减少并发写入操作
- 增加连接池大小

### 4. 响应时间过长

**症状**: 页面加载缓慢

**解决**:
- 启用缓存
- 优化数据库查询
- 增加服务器资源
- 使用CDN加速静态资源

## 安全建议

1. **使用HTTPS**: 配置SSL证书
2. **限制访问**: 配置防火墙规则
3. **定期备份**: 数据库和配置文件
4. **更新依赖**: 定期更新Python包
5. **监控日志**: 及时发现异常访问

## 扩展建议

### 水平扩展

当单台服务器无法支撑时，考虑：

1. **多服务器部署**: 使用负载均衡器分发请求
2. **数据库分离**: 独立数据库服务器
3. **缓存服务器**: 使用Redis集群
4. **CDN加速**: 静态资源使用CDN

### 云服务部署

**AWS**:
- EC2: 计算实例
- RDS: 托管数据库
- ElastiCache: Redis缓存
- CloudFront: CDN加速

**阿里云**:
- ECS: 计算实例
- RDS: 托管数据库
- Redis: 缓存服务
- CDN: 内容分发

## 联系支持

如有问题，请查看：
- 日志文件: `logs/`
- 配置文件: `production_config.py`
- 性能测试: `performance_test.py`
