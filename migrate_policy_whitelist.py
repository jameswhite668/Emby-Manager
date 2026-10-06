"""
Emby策略巡查白名单表迁移脚本
创建 policy_whitelist 表
"""

import os
import sys
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()


def migrate():
    """执行迁移"""
    # 数据库路径
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'emby_manager.db')

    if not os.path.exists(db_path):
        print(f"数据库文件不存在: {db_path}")
        print("请确保数据库文件存在后再运行此脚本")
        return False

    print(f"正在连接数据库: {db_path}")

    # 创建引擎
    engine = create_engine(f'sqlite:///{db_path}')

    # 创建表
    try:
        # 检查表是否已存在
        from sqlalchemy import inspect
        inspector = inspect(engine)

        if 'policy_whitelist' in inspector.get_table_names():
            print("policy_whitelist 表已存在，跳过创建")
        else:
            print("创建 policy_whitelist 表...")

            # 定义表结构（与 models.py 中的 PolicyWhitelist 一致）
            from sqlalchemy import Table, MetaData

            metadata = MetaData()

            policy_whitelist_table = Table(
                'policy_whitelist', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('user_id', Integer, nullable=False, unique=True, index=True),
                Column('added_by', Integer, nullable=False),
                Column('reason', Text, nullable=True),
                Column('created_at', DateTime, default=datetime.utcnow, nullable=False)
            )

            policy_whitelist_table.create(engine)
            print("policy_whitelist 表创建成功")

        print("\n迁移完成！")
        print("现在可以启动应用使用白名单功能了")
        return True

    except Exception as e:
        print(f"迁移失败: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)
