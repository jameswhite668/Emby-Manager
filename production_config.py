"""
生产环境配置 - 支持6000并发用户
"""
import os
import multiprocessing

# ============== 基础配置 ==============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============== 数据库配置 ==============
# 生产环境建议使用MySQL或PostgreSQL
# 这里提供SQLite的优化配置（适合中小型部署）
DATABASE_CONFIG = {
    'SQLITE': {
        'pool_size': 20,  # 连接池大小
        'max_overflow': 40,  # 最大溢出连接
        'pool_timeout': 30,  # 连接池超时
        'pool_recycle': 3600,  # 连接回收时间
        'pool_pre_ping': True,  # 连接前ping测试
    },
    # MySQL配置示例（推荐用于6000并发）
    'MYSQL': {
        'host': 'localhost',
        'port': 3306,
        'database': 'emby_manager',
        'user': 'emby_manager',
        'password': 'your_password',
        'pool_size': 50,
        'max_overflow': 100,
        'pool_timeout': 30,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
    }
}

# ============== Gunicorn配置 ==============
# 计算工作进程数：通常 (2 * CPU核心数) + 1
CPU_COUNT = multiprocessing.cpu_count()
WORKERS = (2 * CPU_COUNT) + 1  # 例如：8核CPU = 17个工作进程

GUNICORN_CONFIG = {
    'bind': '0.0.0.0:5001',
    'workers': WORKERS,
    'worker_class': 'gthread',  # 使用线程工作类
    'threads': 20,  # 每个工作进程的线程数
    'worker_connections': 2000,  # 每个工作进程的最大连接数
    'max_requests': 10000,  # 每个工作进程处理的最大请求数后重启
    'max_requests_jitter': 1000,  # 随机抖动，防止所有工作进程同时重启
    'timeout': 120,  # 超时时间
    'graceful_timeout': 30,  # 优雅关闭超时
    'keepalive': 5,  # Keep-Alive连接超时
    'preload_app': True,  # 预加载应用，节省内存
    'accesslog': os.path.join(BASE_DIR, 'logs', 'gunicorn_access.log'),
    'errorlog': os.path.join(BASE_DIR, 'logs', 'gunicorn_error.log'),
    'loglevel': 'info',
    'capture_output': True,
    'enable_stdio_inheritance': True,
}

# ============== 缓存配置 ==============
CACHE_CONFIG = {
    'CACHE_TYPE': 'filesystem',  # 文件系统缓存
    'CACHE_DIR': os.path.join(BASE_DIR, 'cache'),
    'CACHE_THRESHOLD': 10000,  # 最大缓存条目数
    'CACHE_DEFAULT_TIMEOUT': 300,  # 默认缓存时间5分钟
}

# Redis缓存配置（推荐用于6000并发）
REDIS_CONFIG = {
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_HOST': 'localhost',
    'CACHE_REDIS_PORT': 6379,
    'CACHE_REDIS_DB': 0,
    'CACHE_REDIS_PASSWORD': None,
    'CACHE_DEFAULT_TIMEOUT': 300,
}

# ============== 会话配置 ==============
SESSION_CONFIG = {
    'SESSION_TYPE': 'filesystem',  # 文件系统存储会话
    'SESSION_FILE_DIR': os.path.join(BASE_DIR, 'sessions'),
    'SESSION_PERMANENT': True,
    'PERMANENT_SESSION_LIFETIME': 86400,  # 24小时
    'SESSION_USE_SIGNER': True,
    'SESSION_KEY_PREFIX': 'emby_manager_',
}

# ============== 限流配置 ==============
RATELIMIT_CONFIG = {
    'RATELIMIT_ENABLED': True,
    'RATELIMIT_STORAGE_URL': 'memory://',  # 内存存储
    'RATELIMIT_STRATEGY': 'fixed-window',
    'RATELIMIT_DEFAULT': "100/minute",  # 默认每分钟100请求
    'RATELIMIT_HEADERS_ENABLED': True,
}

# ============== 性能优化配置 ==============
PERFORMANCE_CONFIG = {
    'COMPRESS_MIN_SIZE': 500,  # 最小压缩大小（字节）
    'COMPRESS_LEVEL': 6,  # 压缩级别
    'COMPRESS_MIMETYPES': [
        'text/html',
        'text/css',
        'text/xml',
        'application/json',
        'application/javascript',
    ],
    'SEND_FILE_MAX_AGE_DEFAULT': 86400,  # 静态文件缓存时间
}

# ============== 安全配置 ==============
SECURITY_CONFIG = {
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production'),
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'PERMANENT_SESSION_LIFETIME': 86400,
}

# ============== 6000并发推荐配置 ==============
HIGH_CONCURRENCY_CONFIG = {
    # 数据库连接池
    'DB_POOL_SIZE': 50,
    'DB_MAX_OVERFLOW': 100,
    
    # Gunicorn
    'WORKERS': WORKERS,
    'THREADS': 20,
    'WORKER_CONNECTIONS': 2000,
    
    # 系统限制
    'MAX_OPEN_FILES': 65535,  # 最大打开文件数
    'BACKLOG': 2048,  # 连接队列大小
}

def print_config():
    """打印当前配置"""
    print("=" * 60)
    print("生产环境配置 - 6000并发用户")
    print("=" * 60)
    print(f"\nCPU核心数: {CPU_COUNT}")
    print(f"Gunicorn工作进程数: {WORKERS}")
    print(f"每个工作进程线程数: 20")
    print(f"总并发处理能力: {WORKERS * 20 * 10} (估算)")
    print("\n建议:")
    print("1. 使用MySQL/PostgreSQL替代SQLite")
    print("2. 使用Redis缓存")
    print("3. 配置Nginx反向代理")
    print("4. 增加服务器内存（建议16GB+）")
    print("=" * 60)

if __name__ == '__main__':
    print_config()
