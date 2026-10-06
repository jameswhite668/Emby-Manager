"""
工单系统数据库迁移脚本
创建tickets和ticket_messages表
"""

import os
import sys
from sqlalchemy import create_engine, inspect, text

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'emby_manager.db')

def migrate():
    """执行数据库迁移"""
    print("开始工单系统数据库迁移...")
    
    engine = create_engine(f'sqlite:///{DATABASE_PATH}')
    inspector = inspect(engine)
    
    # 检查tickets表是否存在
    if 'tickets' not in inspector.get_table_names():
        print("创建tickets表...")
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title VARCHAR(200) NOT NULL,
                    type VARCHAR(20) DEFAULT 'other' NOT NULL,
                    priority VARCHAR(20) DEFAULT 'medium' NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    closed_at DATETIME,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """))
            conn.execute(text("CREATE INDEX idx_tickets_user_id ON tickets (user_id)"))
        print("tickets表创建成功")
    else:
        print("tickets表已存在，跳过创建")
    
    # 检查ticket_messages表是否存在
    if 'ticket_messages' not in inspector.get_table_names():
        print("创建ticket_messages表...")
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE ticket_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER NOT NULL,
                    sender_id INTEGER NOT NULL,
                    sender_type VARCHAR(10) NOT NULL,
                    content TEXT NOT NULL,
                    is_read BOOLEAN DEFAULT 0 NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
                    FOREIGN KEY (sender_id) REFERENCES users (id)
                )
            """))
            conn.execute(text("CREATE INDEX idx_ticket_messages_ticket_id ON ticket_messages (ticket_id)"))
        print("ticket_messages表创建成功")
    else:
        print("ticket_messages表已存在，跳过创建")
    
    print("工单系统数据库迁移完成！")

if __name__ == '__main__':
    migrate()
