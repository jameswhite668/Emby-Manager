#!/usr/bin/env python3
"""
管理员密码重置脚本
使用方法: python reset_admin_password.py [新密码]

示例:
    python reset_admin_password.py           # 重置为默认密码 123456
    python reset_admin_password.py abc123    # 重置为指定密码 abc123
    python reset_admin_password.py --help    # 显示帮助信息

注意:
1. 此脚本需要直接访问数据库文件
2. 只能在服务器本地运行
3. 密码长度至少6位
4. 重置后请立即修改密码
"""

import sys
import os
from werkzeug.security import generate_password_hash

# 添加项目目录到路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

def reset_admin_password(new_password='123456'):
    """重置管理员密码"""
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from database.models import User, UserRole
        
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
            # 查找管理员用户（使用正确的枚举类型）
            admin = db.query(User).filter_by(role=UserRole.ADMIN).first()
            
            if not admin:
                print("错误: 未找到管理员用户")
                return False
            
            # 记录旧信息（不显示密码）
            old_username = admin.username
            
            # 重置密码
            admin.password_hash = generate_password_hash(new_password)
            db.commit()
            
            print("=" * 60)
            print("管理员密码重置成功！")
            print("=" * 60)
            print(f"用户名: {old_username}")
            print(f"新密码: {new_password}")
            print("=" * 60)
            print("重要提示:")
            print("1. 请立即使用新密码登录系统")
            print("2. 登录后请立即修改为更安全的密码")
            print("3. 建议密码长度至少8位，包含字母和数字")
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

def main():
    # 显示帮助
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        print("=" * 60)
        print("管理员密码重置工具")
        print("=" * 60)
        print("\n使用方法:")
        print("  python reset_admin_password.py [新密码]")
        print("\n示例:")
        print("  python reset_admin_password.py           # 重置为默认密码 123456")
        print("  python reset_admin_password.py abc123    # 重置为指定密码 abc123")
        print("\n注意:")
        print("  - 此操作不可撤销")
        print("  - 重置后请立即登录并修改为更安全的密码")
        print("=" * 60)
        sys.exit(0)
    
    # 获取新密码参数
    if len(sys.argv) > 1:
        new_password = sys.argv[1]
    else:
        new_password = '123456'
        print("未提供新密码，使用默认密码: 123456")
    
    # 确认提示
    print("=" * 60)
    print("管理员密码重置工具")
    print("=" * 60)
    print(f"将把管理员密码重置为: {new_password}")
    print("此操作不可撤销！")
    print("=" * 60)
    
    # 安全确认
    confirm = input("确认重置密码? (输入 'yes' 确认): ")
    if confirm.lower() != 'yes':
        print("操作已取消")
        sys.exit(0)
    
    # 执行重置
    if reset_admin_password(new_password):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
