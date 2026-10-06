"""
生产环境启动脚本 - 支持6000并发用户
使用方法:
    1. 安装依赖: python start_production.py --install
    2. 启动服务器: python start_production.py --waitress
"""
import os
import sys
import subprocess
import multiprocessing
import argparse

def install_dependencies():
    """自动安装所有依赖"""
    print("=" * 60)
    print("正在安装依赖...")
    print("=" * 60)
    
    # 检查requirements.txt是否存在
    req_file = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if not os.path.exists(req_file):
        print("错误: 未找到 requirements.txt 文件")
        print("请确保 requirements.txt 与 start_production.py 在同一目录")
        return False
    
    try:
        # 安装依赖
        print("\n1. 安装核心依赖...")
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '-r', req_file],
            capture_output=True,
            text=True,
            check=True
        )
        print(result.stdout)
        
        if result.stderr:
            print("安装日志:", result.stderr)
        
        print("\n2. 验证安装...")
        # 验证关键包
        packages = ['flask', 'sqlalchemy', 'werkzeug', 'requests', 'waitress']
        for pkg in packages:
            try:
                __import__(pkg.replace('-', '_'))
                print(f"  ✓ {pkg}")
            except ImportError:
                print(f"  ✗ {pkg} 安装失败")
        
        print("\n" + "=" * 60)
        print("依赖安装完成！")
        print("=" * 60)
        print("\n现在可以启动服务器：")
        print("  python start_production.py --waitress")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"安装失败: {e}")
        print(f"错误输出: {e.stderr}")
        return False
    except Exception as e:
        print(f"安装出错: {e}")
        return False

def check_dependencies():
    """检查必要的依赖"""
    # 核心依赖（必须）
    core_packages = [
        'flask',
        'sqlalchemy',
        'werkzeug',
        'requests',
    ]
    
    # 可选依赖（根据平台）
    optional_packages = [
        'gunicorn',
        'waitress',
    ]
    
    missing_core = []
    for package in core_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_core.append(package)
    
    if missing_core:
        print("=" * 60)
        print("缺少以下核心依赖包：")
        for pkg in missing_core:
            print(f"  - {pkg}")
        print("\n请运行以下命令安装依赖：")
        print("  python start_production.py --install")
        print("=" * 60)
        return False
    
    # 检查可选依赖
    missing_optional = []
    for package in optional_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_optional.append(package)
    
    if missing_optional:
        print(f"注意：缺少可选依赖 {missing_optional}，某些功能可能不可用")
        print("建议运行: python start_production.py --install")
    
    return True

def setup_environment():
    """设置生产环境"""
    # 创建必要的目录
    dirs = ['logs', 'cache', 'sessions', 'static/downloads/clients']
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    
    # 设置环境变量
    os.environ['FLASK_ENV'] = 'production'
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    
    # 打印系统信息
    print("=" * 60)
    print("生产环境启动配置")
    print("=" * 60)
    print(f"Python版本: {sys.version}")
    print(f"CPU核心数: {multiprocessing.cpu_count()}")
    print(f"工作进程数: {(2 * multiprocessing.cpu_count()) + 1}")
    print("=" * 60)

def start_with_gunicorn():
    """使用Gunicorn启动（推荐用于Linux/Mac）"""
    import platform
    
    if platform.system() == 'Windows':
        print("警告：Gunicorn不支持Windows系统")
        print("请使用 waitress 或其他WSGI服务器")
        return start_with_waitress()
    
    print("\n使用Gunicorn启动服务器...")
    print("配置文件: gunicorn.conf.py")
    
    cmd = [
        'gunicorn',
        '-c', 'gunicorn.conf.py',
        'app:app'
    ]
    
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"启动失败: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("未找到gunicorn命令，请先安装: pip install gunicorn")
        sys.exit(1)

def start_with_waitress():
    """使用Waitress启动（Windows推荐）"""
    print("\n使用Waitress启动服务器...")
    
    try:
        from waitress import serve
        import app
        
        # 初始化数据库并启动定时任务
        app.init_db()
        app.start_scheduler()
        
        # 计算工作线程数
        threads = 20
        
        print(f"监听地址: 0.0.0.0:5001")
        print(f"工作线程数: {threads}")
        print(f"连接队列: 2048")
        
        serve(
            app.app,
            host='0.0.0.0',
            port=5001,
            threads=threads,
            connection_limit=2000,
            channel_timeout=120,
            expose_tracebacks=False,
        )
    except ImportError:
        print("未找到waitress，请先安装: pip install waitress")
        sys.exit(1)

def start_development():
    """开发环境启动（不推荐用于生产）"""
    print("\n警告：正在使用开发服务器启动（不推荐用于生产环境）")
    print("生产环境请使用Gunicorn或Waitress\n")
    
    import app
    # 初始化数据库并启动定时任务
    app.init_db()
    app.start_scheduler()
    
    app.app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)

def show_help():
    """显示帮助信息"""
    print("""
生产环境启动脚本 - 支持6000并发用户

使用方法:
    1. 首次使用 - 安装依赖:
       python start_production.py --install
    
    2. 启动服务器:
       python start_production.py --waitress    (Windows推荐)
       python start_production.py --gunicorn    (Linux/Mac推荐)

选项:
    --install       自动安装所有依赖
    --gunicorn      使用Gunicorn启动（Linux/Mac推荐）
    --waitress      使用Waitress启动（Windows推荐）
    --dev           使用开发服务器启动（不推荐用于生产）
    --help          显示此帮助信息

快速开始:
    python start_production.py --install
    python start_production.py --waitress

性能优化建议:
    1. 使用MySQL/PostgreSQL替代SQLite
    2. 配置Nginx反向代理
    3. 使用Redis缓存
    4. 增加服务器配置（16核+，32GB内存）
    5. 考虑多服务器负载均衡

6000并发配置:
    - 工作进程数: (2 * CPU核心数) + 1
    - 线程数: 20
    - 数据库连接池: 50
    - 建议服务器配置: 16核32GB+
    """)

def main():
    parser = argparse.ArgumentParser(description='生产环境启动脚本')
    parser.add_argument('--install', action='store_true', help='自动安装所有依赖')
    parser.add_argument('--gunicorn', action='store_true', help='使用Gunicorn启动')
    parser.add_argument('--waitress', action='store_true', help='使用Waitress启动')
    parser.add_argument('--dev', action='store_true', help='使用开发服务器启动')
    
    args = parser.parse_args()
    
    # 安装依赖
    if args.install:
        if install_dependencies():
            sys.exit(0)
        else:
            sys.exit(1)
    
    # 检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    # 设置环境
    setup_environment()
    
    # 根据参数启动
    if args.gunicorn:
        start_with_gunicorn()
    elif args.waitress:
        start_with_waitress()
    elif args.dev:
        start_development()
    else:
        # 自动选择
        import platform
        if platform.system() == 'Windows':
            start_with_waitress()
        else:
            start_with_gunicorn()

if __name__ == '__main__':
    main()
