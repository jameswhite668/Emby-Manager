#!/usr/bin/env python3
"""
测试数据库写入
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'database', 'emby_manager.db')
engine = create_engine(f'sqlite:///{DATABASE_PATH}', echo=False)
SessionLocal = sessionmaker(bind=engine)

# 测试直接SQL写入
print("=" * 60)
print("测试直接SQL写入:")
print("=" * 60)

with engine.connect() as conn:
    # 先查询当前值
    result = conn.execute(text("SELECT id, username, is_active FROM users WHERE id=2"))
    row = result.fetchone()
    print(f"写入前: {row}")
    
    # 更新值
    conn.execute(text("UPDATE users SET is_active = 0 WHERE id=2"))
    conn.commit()
    print("已执行 UPDATE users SET is_active = 0 WHERE id=2")
    
    # 再查询
    result = conn.execute(text("SELECT id, username, is_active FROM users WHERE id=2"))
    row = result.fetchone()
    print(f"写入后: {row}")

# 再测试 SQLAlchemy ORM 写入
print("\n" + "=" * 60)
print("测试 SQLAlchemy ORM 写入:")
print("=" * 60)

# 重新查询确认
with engine.connect() as conn:
    result = conn.execute(text("SELECT id, username, is_active FROM users WHERE id=2"))
    row = result.fetchone()
    print(f"直接SQL查询: {row}")

# 使用 ORM
from app import get_db, User, UserRole
db = get_db()
try:
    user = db.query(User).get(2)
    print(f"ORM查询: 用户 {user.username}, is_active={user.is_active}")
    
    # 修改值
    user.is_active = False
    print(f"已设置 is_active=False")
    
    # 提交
    db.commit()
    print("已执行 db.commit()")
    
    # 重新查询
    db2 = get_db()
    user2 = db2.query(User).get(2)
    print(f"新会话查询: 用户 {user2.username}, is_active={user2.is_active}")
    db2.close()
    
finally:
    db.close()

# 最后用直接SQL确认
print("\n" + "=" * 60)
print("最终确认:")
print("=" * 60)
with engine.connect() as conn:
    result = conn.execute(text("SELECT id, username, is_active FROM users WHERE id=2"))
    row = result.fetchone()
    print(f"直接SQL查询: {row}")
