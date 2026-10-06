#!/usr/bin/env python3
"""
用户密码重置脚本（管理员使用）
使用方法: python reset_user_password.py <用户名> [新密码]

示例:
    python reset_user_password.py user001          # 重置为默认密码 123456
    python reset_user_password.py user001 abc123   # 重置为指定密码 abc123
    python reset_user_password.py --list           # 列出所有用户

注意:
1. 此脚本只能由管理员在服务器本地运行
2. 重置后密码将同步到Emby服务器（如果已绑定）
3. 重置后请通知用户修改密码
"""

import sys
import os
from werkzeug.security import generate_password_hash

# 添加项目目录到路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

def reset_user_password(username, new_password='123456'):
    """重置指定用户密码"""
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from database.models import User
        from app import EmbyAPI
        
        # 数据库路径
        db_path = os.path.join(BASE_DIR, 'database', 'emby_manager.db')
        
        if not os.path.exists(db_path):
            print(f"错误: 数据库文件不存在: {db_path}")
            return False
        
        # 连接数据库
        engine = create_engine(f'sqlite:///{db_path}')
        Session = sessionmaker(bind=engine)
        db = Session()
        
        try:
            # 查找用户
            user = db.query(User).filter_by(username=username).first()
            
            if not user:
                print(f"错误: 未找到用户 '{username}'")
                return False
            
            # 更新本地密码
            user.password_hash = generate_password_hash(new_password)
            
            # 同步更新Emby密码（如果已绑定）
            if user.emby_user_id and EmbyAPI.is_configured():
                try:
                    EmbyAPI.reset_password(user.emby_user_id, new_password)
                    print(f"Emby密码已同步更新")
                except Exception as e:
                    print(f"警告: Emby密码同步失败: {e}")
                    print("用户可能需要手动修改Emby密码")
            
            db.commit()
            
            print("=" * 60)
            print("用户密码重置成功！")
            print("=" * 60)
            print(f"用户名: {username}")
            print(f"新密码: {new_password}")
            print(f"用户角色: {user.role}")
            print(f"用户状态: {'启用' if user.is_active else '禁用'}")
            if user.expiry_date:
                print(f"到期时间: {user.expiry_date}")
            print("=" * 60)
            print("重要提示:")
            print("1. 请将此密码安全地告知用户")
            print("2. 建议用户登录后立即修改密码")
            print("3. 如果用户绑定了Emby，Emby密码也已同步更新")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            db.rollback()
            print(f"重置密码时出错: {e}")
            return False
        finally:
            db.close()
            
    except ImportError as e:
        print(f"导入模块失败: {e}")
        print("请确保已安装依赖: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"发生错误: {e}")
        return False

def list_users():
    """列出所有用户"""
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from database.models import User
        
        db_path = os.path.join(BASE_DIR, 'database', 'emby_manager.db')
        engine = create_engine(f'sqlite:///{db_path}')
        Session = sessionmaker(bind=engine)
        db = Session()
        
        try:
            users = db.query(User).all()
            
            print("=" * 80)
            print(f"{'用户名':<20} {'角色':<10} {'状态':<8} {'到期时间':<20}")
            print("=" * 80)
            
            for user in users:
                status = "启用" if user.is_active else "禁用"
                expiry = str(user.expiry_date)[:19] if user.expiry_date else "永不过期"
                print(f"{user.username:<20} {user.role:<10} {status:<8} {expiry:<20}")
            
            print("=" * 80)
            print(f"共 {len(users)} 个用户")
            
        finally:
            db.close()
            
    except Exception as e:
        print(f"获取用户列表失败: {e}")

def main():
    # 显示帮助
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help', 'help']:
        print("=" * 60)
        print("用户密码重置工具")
        print("=" * 60)
        print("\n使用方法:")
        print("  python reset_user_password.py <用户名> [新密码]")
        print("\n示例:")
        print("  python reset_user_password.py user001          # 重置为默认密码 123456")
        print("  python reset_user_password.py user001 abc123   # 重置为指定密码 abc123")
        print("  python reset_user_password.py --list           # 列出所有用户")
        print("\n注意:")
        print("  - 此操作不可撤销")
        print("  - 如果用户绑定了Emby，Emby密码也会同步更新")
        print("=" * 60)
        sys.exit(0)
    
    # 列出用户
    if sys.argv[1] == '--list':
        list_users()
        sys.exit(0)
    
    # 获取参数
    username = sys.argv[1]
    
    if len(sys.argv) > 2:
        new_password = sys.argv[2]
    else:
        new_password = '123456'
        print(f"未提供新密码，使用默认密码: {new_password}")
    
    # 确认提示
    print("=" * 60)
    print("用户密码重置工具")
    print("=" * 60)
    print(f"将把用户 '{username}' 的密码重置为: {new_password}")
    print("此操作不可撤销！")
    print("=" * 60)
    
    # 安全确认
    confirm = input("确认重置密码? (输入 'yes' 确认): ")
    if confirm.lower() != 'yes':
        print("操作已取消")
        sys.exit(0)
    
    # 执行重置
    if reset_user_password(username, new_password):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
