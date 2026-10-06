"""
Gunicorn配置文件 - 支持6000并发用户
使用方式: gunicorn -c gunicorn.conf.py app:app
"""
import os
import multiprocessing

# 基础路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============== 服务器配置 ==============
bind = "0.0.0.0:5001"  # 绑定地址和端口

# ============== 工作进程配置 ==============
# 计算工作进程数：(2 * CPU核心数) + 1
workers = (2 * multiprocessing.cpu_count()) + 1

# 工作进程类型
def get_worker_class():
    """根据平台选择工作进程类型"""
    import sys
    if sys.platform == 'win32':
        # Windows不支持gthread，使用sync
        return 'sync'
    else:
        # Linux/Mac使用gthread（基于线程的异步工作模式）
        return 'gthread'

worker_class = get_worker_class()

# 每个工作进程的线程数（仅gthread有效）
threads = 20

# 每个工作进程的最大并发连接数（仅gthread有效）
worker_connections = 2000

# ============== 请求处理配置 ==============
# 每个工作进程处理的最大请求数后重启（防止内存泄漏）
max_requests = 10000

# 随机抖动，防止所有工作进程同时重启
max_requests_jitter = 1000

# 超时时间（秒）
timeout = 120

# 优雅关闭超时（秒）
graceful_timeout = 30

# Keep-Alive连接超时（秒）
keepalive = 5

# ============== 预加载配置 ==============
# 预加载应用，节省内存
preload_app = True

# ============== 日志配置 ==============
accesslog = os.path.join(BASE_DIR, 'logs', 'gunicorn_access.log')
errorlog = os.path.join(BASE_DIR, 'logs', 'gunicorn_error.log')
loglevel = 'info'

# 捕获输出
capture_output = True
enable_stdio_inheritance = True

# ============== 进程名称 ==============
proc_name = 'emby_manager'

# ============== 服务器钩子 ==============
def on_starting(server):
    """服务器启动时调用"""
    print(f"Gunicorn服务器正在启动...")
    print(f"工作进程数: {workers}")
    print(f"工作进程类型: {worker_class}")
    print(f"线程数: {threads}")
    print(f"监听地址: {bind}")

def on_reload(server):
    """重新加载配置时调用"""
    print("Gunicorn配置已重新加载")

def when_ready(server):
    """服务器就绪时调用（主进程）"""
    print("Gunicorn服务器已就绪，开始接受请求")
    # 在主进程中初始化数据库并启动定时任务
    try:
        import app
        app.init_db()
        app.start_scheduler()
        print("定时任务已在主进程启动")
    except Exception as e:
        print(f"启动定时任务失败: {e}")

def post_fork(server, worker):
    """工作进程启动后调用"""
    print(f"工作进程 {worker.pid} 已启动")

def worker_int(worker):
    """工作进程收到SIGINT或SIGQUIT时调用"""
    print(f"工作进程 {worker.pid} 正在关闭...")

def worker_abort(worker):
    """工作进程收到SIGABRT时调用"""
    print(f"工作进程 {worker.pid} 异常中止")

# ============== 性能调优说明 ==============
"""
6000并发用户配置说明：

1. 工作进程数 = (2 * CPU核心数) + 1
   - 例如：8核CPU = 17个工作进程
   - 每个工作进程独立处理请求

2. 线程数 = 20（仅gthread模式）
   - 每个工作进程可以并发处理20个请求
   - 总并发能力 = 工作进程数 * 线程数

3. worker_connections = 2000
   - 每个工作进程最多保持2000个连接
   - 总连接能力 = 工作进程数 * worker_connections

4. 预估并发能力：
   - 8核CPU：17工作进程 * 20线程 = 340并发
   - 配合Nginx反向代理和负载均衡可以达到更高并发

5. 要达到6000并发，建议：
   - 使用多服务器部署（横向扩展）
   - 配置Nginx负载均衡到多个Gunicorn实例
   - 使用MySQL/PostgreSQL替代SQLite
   - 使用Redis缓存和会话存储
   - 增加服务器配置（16核+，32GB内存）
"""
