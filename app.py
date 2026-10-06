"""
Emby Manager - 完整的后端应用
使用 Flask + SQLite + SQLAlchemy
"""

import os
import sys
import json
import random
import string
import logging
import secrets
import hashlib
import requests
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread
import time

from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Enum, Numeric, and_, or_, func, select, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, scoped_session
from functools import lru_cache
import enum
import hashlib
import pickle
import threading
import re

# ============== HTML净化工具 ==============

def sanitize_html(html_content):
    """
    净化HTML内容，防止XSS攻击
    保留正常功能按钮的事件，只过滤最危险的XSS向量
    """
    if not html_content:
        return ''

    # 只过滤最危险的XSS攻击向量，保留正常的交互功能
    
    # 1. 移除JavaScript伪协议（这是最常见的XSS攻击方式）
    js_protocol_pattern = re.compile(r'javascript:', re.IGNORECASE)
    html_content = js_protocol_pattern.sub('', html_content)
    
    # 2. 移除vbscript:伪协议（IE浏览器）
    vbscript_pattern = re.compile(r'vbscript:', re.IGNORECASE)
    html_content = vbscript_pattern.sub('', html_content)
    
    # 3. 移除data:text/html等危险协议
    data_protocol_pattern = re.compile(r'data:text/html', re.IGNORECASE)
    html_content = data_protocol_pattern.sub('', html_content)
    
    # 4. 只移除最危险的几个事件处理器（这些通常用于自动执行攻击代码）
    # 保留 onclick, onchange 等用户交互事件，这些需要用户主动触发
    most_dangerous_events = [
        'onerror',      # 图片/脚本加载错误时触发，常用于自动执行
        'onload',       # 页面/元素加载完成时自动触发
        'onunload',     # 页面卸载时触发
        'onpageshow',   # 页面显示时触发
        'onpagehide',   # 页面隐藏时触发
        'onhashchange', # URL hash变化时触发
        'onpopstate',   # 浏览器历史记录变化时触发
        'onreadystatechange',  # 文档就绪状态变化
        'onbeforeunload',      # 页面卸载前触发
    ]
    
    for event in most_dangerous_events:
        # 匹配 onxxx= 或 onxxx = 后面跟着引号或没有引号的内容
        pattern = re.compile(r'\s+' + event + r'\s*=\s*["\']?[^"\'>]*["\']?', re.IGNORECASE)
        html_content = pattern.sub('', html_content)
    
    # 5. 移除expression() (CSS表达式，IE特有，可执行代码)
    expression_pattern = re.compile(r'expression\s*\([^)]*\)', re.IGNORECASE)
    html_content = expression_pattern.sub('', html_content)
    
    # 6. 移除behavior: url() (CSS行为，IE特有)
    behavior_pattern = re.compile(r'behavior\s*:\s*url\s*\([^)]*\)', re.IGNORECASE)
    html_content = behavior_pattern.sub('', html_content)
    
    # 7. 移除CSS中的@import (可能导入恶意CSS)
    import_pattern = re.compile(r'@import\s+', re.IGNORECASE)
    html_content = import_pattern.sub('', html_content)
    
    # 8. 移除eval()函数调用
    eval_pattern = re.compile(r'eval\s*\(', re.IGNORECASE)
    html_content = eval_pattern.sub('(', html_content)
    
    # 9. 移除Function()构造函数
    function_pattern = re.compile(r'new\s+Function\s*\(', re.IGNORECASE)
    html_content = function_pattern.sub('(', html_content)
    
    # 10. 移除setTimeout和setInterval的字符串参数（可能执行代码）
    # 保留函数引用形式的调用
    settimeout_pattern = re.compile(r'setTimeout\s*\(\s*["\']', re.IGNORECASE)
    html_content = settimeout_pattern.sub('setTimeout(function(){}, 0) // ', html_content)
    setinterval_pattern = re.compile(r'setInterval\s*\(\s*["\']', re.IGNORECASE)
    html_content = setinterval_pattern.sub('setInterval(function(){}, 0) // ', html_content)

    return html_content


# ============== 全局变量 ==============
_scheduler_started = False
_scheduler_lock = threading.Lock()

# ============== 配置 ==============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'emby_manager.db')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
LOG_FILE = os.path.join(LOGS_DIR, 'emby_manager.log')
CLIENT_DOWNLOADS_DIR = os.path.join(BASE_DIR, 'static', 'downloads', 'clients')

# 确保目录存在
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(CLIENT_DOWNLOADS_DIR, exist_ok=True)

# ============== 缓存配置 ==============
CACHE_DIR = os.path.join(BASE_DIR, 'cache')
os.makedirs(CACHE_DIR, exist_ok=True)

class SimpleCache:
    """简单的文件缓存实现"""
    def __init__(self, cache_dir=CACHE_DIR, default_timeout=300):
        self.cache_dir = cache_dir
        self.default_timeout = default_timeout
        self._memory_cache = {}
        self._memory_cache_time = {}
    
    def _get_cache_path(self, key):
        """获取缓存文件路径"""
        hash_key = hashlib.md5(key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{hash_key}.cache")
    
    def get(self, key):
        """获取缓存"""
        # 先检查内存缓存
        if key in self._memory_cache:
            cache_time = self._memory_cache_time.get(key, 0)
            if time.time() - cache_time < self.default_timeout:
                return self._memory_cache[key]
            else:
                # 过期，删除
                del self._memory_cache[key]
                del self._memory_cache_time[key]
        
        # 检查文件缓存
        cache_path = self._get_cache_path(key)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'rb') as f:
                    data = pickle.load(f)
                    # 放入内存缓存
                    self._memory_cache[key] = data
                    self._memory_cache_time[key] = time.time()
                    return data
            except Exception:
                pass
        return None
    
    def set(self, key, value, timeout=None):
        """设置缓存"""
        if timeout is None:
            timeout = self.default_timeout
        
        # 存入内存缓存
        self._memory_cache[key] = value
        self._memory_cache_time[key] = time.time()
        
        # 存入文件缓存
        cache_path = self._get_cache_path(key)
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(value, f)
        except Exception as e:
            logger.warning(f"缓存写入失败: {e}")
    
    def delete(self, key):
        """删除缓存"""
        if key in self._memory_cache:
            del self._memory_cache[key]
            del self._memory_cache_time[key]
        
        cache_path = self._get_cache_path(key)
        if os.path.exists(cache_path):
            try:
                os.remove(cache_path)
            except Exception:
                pass
    
    def clear(self):
        """清空缓存"""
        self._memory_cache.clear()
        self._memory_cache_time.clear()
        
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.cache'):
                try:
                    os.remove(os.path.join(self.cache_dir, filename))
                except Exception:
                    pass

# 创建全局缓存实例
cache = SimpleCache(default_timeout=300)

# ============== 日志配置 ==============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ============== 数据库模型 ==============
Base = declarative_base()

class UserRole(enum.Enum):
    ADMIN = "admin"
    USER = "user"

class DurationType(enum.Enum):
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"
    PERMANENT = "permanent"

class DocPlatform(enum.Enum):
    """使用文档平台类型枚举"""
    ANDROID = "android"
    IOS = "ios"
    TV = "tv"
    PC = "pc"
    MAC = "mac"
    LINUX = "linux"

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_manually_disabled = Column(Boolean, default=False, nullable=False)  # 手动禁用标记
    expiry_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    emby_user_id = Column(String(100), nullable=True, unique=True)
    coins = Column(Integer, default=0, nullable=False)
    email = Column(String(100), nullable=True, unique=True)
    email_verified = Column(Boolean, default=False)
    emby_access_disabled = Column(Boolean, default=False, nullable=False)  # Emby访问是否因过期被系统自动禁用

    watch_history = relationship("WatchHistory", back_populates="user", cascade="all, delete-orphan")
    login_logs = relationship("LoginLog", back_populates="user", cascade="all, delete-orphan")
    used_activation_codes = relationship("ActivationCode", back_populates="used_by_user")
    coin_transactions = relationship("CoinTransaction", back_populates="user", cascade="all, delete-orphan", foreign_keys="CoinTransaction.user_id")
    policy_whitelist_entries = relationship("PolicyWhitelist", back_populates="user", cascade="all, delete-orphan", foreign_keys="PolicyWhitelist.user_id")
    webdav_assignments = relationship("UserWebDAVAssignment", back_populates="user", cascade="all, delete-orphan")

    def is_expired(self):
        if self.expiry_date is None:
            return False
        return datetime.now() > self.expiry_date

    def to_dict(self):
        # 获取最近登录时间
        last_login = None
        try:
            # 尝试从login_logs关系中获取最近登录时间
            if self.login_logs:
                # 查找最新的成功登录记录
                successful_logins = [log for log in self.login_logs if log.success]
                if successful_logins:
                    latest_login = max(successful_logins, key=lambda x: x.login_time)
                    last_login = latest_login.login_time.isoformat() if latest_login.login_time else None
        except Exception:
            # 如果会话已关闭或其他错误，返回None
            last_login = None
        
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role.value,
            'is_active': self.is_active,
            'is_manually_disabled': self.is_manually_disabled,
            'is_expired': self.is_expired(),
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': last_login,
            'emby_user_id': self.emby_user_id,
            'coins': self.coins,
            'email': self.email,
            'email_verified': self.email_verified,
            'emby_access_disabled': bool(self.emby_access_disabled)
        }

class ActivationCode(Base):
    __tablename__ = 'activation_codes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(100), unique=True, nullable=False, index=True)
    duration_type = Column(Enum(DurationType), nullable=False)
    duration_seconds = Column(Integer, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    used_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    used_by_user = relationship("User", back_populates="used_activation_codes")

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'duration_type': self.duration_type.value,
            'duration_seconds': self.duration_seconds,
            'is_used': self.is_used,
            'used_by': self.used_by,
            'used_at': self.used_at.isoformat() if self.used_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class WatchHistory(Base):
    __tablename__ = 'watch_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    item_name = Column(String(255), nullable=False)
    item_id = Column(String(100), nullable=True)
    item_type = Column(String(50), nullable=True)  # Movie, Episode, Series
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    duration = Column(Integer, nullable=True)
    play_count = Column(Integer, default=0)  # 播放次数
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    user = relationship("User", back_populates="watch_history")

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'item_name': self.item_name,
            'item_id': self.item_id,
            'item_type': self.item_type,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'play_count': self.play_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class SystemConfig(Base):
    __tablename__ = 'system_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value
        }

class LoginLog(Base):
    """登录日志表"""
    __tablename__ = 'login_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    login_time = Column(DateTime, default=datetime.now, nullable=False)
    user_agent = Column(Text, nullable=True)
    success = Column(Integer, default=1, nullable=False)  # 使用Integer代替Boolean，SQLite兼容性更好

    # 关系
    user = relationship("User", back_populates="login_logs")

    def to_dict(self):
        # 处理各种可能的 success 值类型
        success_val = self.success
        if isinstance(success_val, bool):
            success_bool = success_val
        elif isinstance(success_val, int):
            success_bool = success_val == 1
        elif isinstance(success_val, str):
            success_bool = success_val.lower() in ['1', 'true', 'yes']
        else:
            success_bool = bool(success_val)
        
        result = {
            'id': self.id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'login_time': self.login_time.isoformat() if self.login_time else None,
            'user_agent': self.user_agent,
            'success': success_bool
        }
        logger.info(f"LoginLog.to_dict() - id={self.id}, success原始值={self.success}(类型:{type(self.success).__name__}), 转换后={success_bool}")
        return result


class PolicyWhitelist(Base):
    """Emby策略巡查白名单表"""
    __tablename__ = 'policy_whitelist'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, unique=True, index=True)
    added_by = Column(Integer, ForeignKey('users.id'), nullable=False)  # 添加者（管理员）
    reason = Column(Text, nullable=True)  # 添加原因
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    # 关系
    user = relationship("User", foreign_keys=[user_id], back_populates="policy_whitelist_entries")
    admin = relationship("User", foreign_keys=[added_by])

    def __repr__(self):
        return f"<PolicyWhitelist(id={self.id}, user_id={self.user_id}, added_by={self.added_by})>"

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'added_by': self.added_by,
            'reason': self.reason,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Announcement(Base):
    """公告表"""
    __tablename__ = 'announcements'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    start_time = Column(DateTime, nullable=True)  # 公告开始显示时间
    end_time = Column(DateTime, nullable=True)   # 公告结束时间
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'is_active': self.is_active,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class UserAnnouncement(Base):
    """用户公告阅读记录表"""
    __tablename__ = 'user_announcements'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    announcement_id = Column(Integer, ForeignKey('announcements.id'), nullable=False, index=True)
    is_read = Column(Boolean, default=False, nullable=False)
    dont_show_today = Column(Boolean, default=False, nullable=False)
    read_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'announcement_id': self.announcement_id,
            'is_read': self.is_read,
            'dont_show_today': self.dont_show_today,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class LegalPage(Base):
    """法律条款页面表（服务条款、隐私政策）"""
    __tablename__ = 'legal_pages'

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_type = Column(String(50), nullable=False, unique=True, index=True)  # 'terms' 或 'privacy'
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'page_type': self.page_type,
            'title': self.title,
            'content': self.content,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class EmbyUserPolicy(Base):
    """Emby用户规则设置表"""
    __tablename__ = 'emby_user_policies'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enable_download = Column(Boolean, default=True, nullable=False)
    enable_transcoding = Column(Boolean, default=True, nullable=False)
    max_active_devices = Column(Integer, default=3, nullable=False)
    allowed_library_ids = Column(Text, nullable=True)
    is_default = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'enable_download': self.enable_download,
            'enable_transcoding': self.enable_transcoding,
            'max_active_devices': self.max_active_devices,
            'allowed_library_ids': self.allowed_library_ids,
            'is_default': self.is_default,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class CoinPackage(Base):
    """金币套餐表"""
    __tablename__ = 'coin_packages'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    duration_type = Column(Enum(DurationType), nullable=False)
    duration_days = Column(Integer, nullable=False)
    coin_amount = Column(Integer, nullable=False)
    price_yuan = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_recommended = Column(Boolean, default=False, nullable=False)
    is_gift_card = Column(Boolean, default=False, nullable=False)
    sort_order = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    def to_dict(self, db_session=None):
        tags_data = []
        if db_session:
            try:
                tags = db_session.query(PackageTag).filter_by(package_id=self.id).all()
                tags_data = [tag.to_dict() for tag in tags]
            except:
                pass
        
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'duration_type': self.duration_type.value,
            'duration_days': self.duration_days,
            'coin_amount': self.coin_amount,
            'price_yuan': self.price_yuan,
            'is_active': self.is_active,
            'is_recommended': self.is_recommended,
            'is_gift_card': self.is_gift_card,
            'sort_order': self.sort_order,
            'tags': tags_data,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class PackageTag(Base):
    """套餐标签表"""
    __tablename__ = 'package_tags'

    id = Column(Integer, primary_key=True, autoincrement=True)
    package_id = Column(Integer, ForeignKey('coin_packages.id'), nullable=False, index=True)
    tag_text = Column(String(50), nullable=False)
    tag_color = Column(String(20), default='#FF69B4', nullable=False)
    sort_order = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'package_id': self.package_id,
            'tag_text': self.tag_text,
            'tag_color': self.tag_color,
            'sort_order': self.sort_order,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class CouponBeneficiary(enum.Enum):
    """优惠码受益人规则枚举"""
    ALL = "all"
    NEW_USER = "new_user"
    SPECIFIC = "specific"


class CouponCode(Base):
    """优惠码表"""
    __tablename__ = 'coupon_codes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(50), unique=True, nullable=False, index=True)
    discount_percent = Column(Integer, nullable=False)
    max_uses = Column(Integer, nullable=False)
    current_uses = Column(Integer, default=0, nullable=False)
    beneficiary_type = Column(Enum(CouponBeneficiary), default=CouponBeneficiary.ALL, nullable=False)
    beneficiary_user_ids = Column(Text, nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)

    usage_records = relationship("CouponUsageRecord", back_populates="coupon", cascade="all, delete-orphan")

    def is_valid(self):
        if not self.is_active:
            return False
        if self.current_uses >= self.max_uses:
            return False
        now = datetime.now()
        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_until and now > self.valid_until:
            return False
        return True

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'discount_percent': self.discount_percent,
            'max_uses': self.max_uses,
            'current_uses': self.current_uses,
            'beneficiary_type': self.beneficiary_type.value,
            'beneficiary_user_ids': json.loads(self.beneficiary_user_ids) if self.beneficiary_user_ids else [],
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'is_active': self.is_active,
            'is_valid': self.is_valid(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by
        }


class CouponUsageRecord(Base):
    """优惠码使用记录表"""
    __tablename__ = 'coupon_usage_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    coupon_id = Column(Integer, ForeignKey('coupon_codes.id'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    order_no = Column(String(50), nullable=False, index=True)
    original_amount = Column(Numeric(10, 2), nullable=False)  # 原始金额（元），保留两位小数
    discount_amount = Column(Numeric(10, 2), nullable=False)  # 优惠金额（元），保留两位小数
    final_amount = Column(Numeric(10, 2), nullable=False)  # 最终金额（元），保留两位小数
    used_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    coupon = relationship("CouponCode", back_populates="usage_records")
    user = relationship("User")

    def to_dict(self):
        return {
            'id': self.id,
            'coupon_id': self.coupon_id,
            'user_id': self.user_id,
            'order_no': self.order_no,
            'original_amount': float(self.original_amount) if self.original_amount is not None else None,
            'discount_amount': float(self.discount_amount) if self.discount_amount is not None else None,
            'final_amount': float(self.final_amount) if self.final_amount is not None else None,
            'used_at': self.used_at.isoformat() if self.used_at else None
        }


class PaymentOrder(Base):
    """支付订单表"""
    __tablename__ = 'payment_orders'

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_no = Column(String(50), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    amount = Column(Numeric(10, 2), nullable=False)  # 支付金额（元），保留两位小数
    coin_amount = Column(Integer, nullable=False)  # 获得金币数量
    payment_method = Column(String(20), nullable=False)  # wechat/alipay
    status = Column(String(20), default='pending', nullable=False)  # pending/paid/approved/rejected/cancelled/refunding/refunded
    refund_qrcode_path = Column(String(255), nullable=True)  # 用户上传的退款收款码
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    paid_at = Column(DateTime, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    cancelled_at = Column(DateTime, nullable=True)  # 用户撤销时间
    refund_status = Column(String(20), nullable=True)  # 退款状态：pending/refunded/rejected
    refund_processed_at = Column(DateTime, nullable=True)  # 退款处理时间
    refund_processed_by = Column(Integer, ForeignKey('users.id'), nullable=True)  # 处理退款的管理员
    
    # 优惠码相关字段
    coupon_code = Column(String(50), nullable=True)  # 使用的优惠码
    original_amount = Column(Numeric(10, 2), nullable=True)  # 原始金额（优惠前），保留两位小数
    discount_amount = Column(Numeric(10, 2), nullable=True)  # 优惠金额，保留两位小数
    coupon_id = Column(Integer, ForeignKey('coupon_codes.id'), nullable=True)  # 关联的优惠码ID

    user = relationship("User", foreign_keys=[user_id])
    approver = relationship("User", foreign_keys=[approved_by])
    refund_processor = relationship("User", foreign_keys=[refund_processed_by])
    coupon = relationship("CouponCode")

    def to_dict(self):
        return {
            'id': self.id,
            'order_no': self.order_no,
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else None,
            'amount': float(self.amount) if self.amount is not None else None,
            'coin_amount': self.coin_amount,
            'payment_method': self.payment_method,
            'status': self.status,
            'refund_qrcode_path': self.refund_qrcode_path,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'paid_at': self.paid_at.isoformat() if self.paid_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'approved_by': self.approved_by,
            'cancelled_at': self.cancelled_at.isoformat() if self.cancelled_at else None,
            'refund_status': self.refund_status,
            'refund_processed_at': self.refund_processed_at.isoformat() if self.refund_processed_at else None,
            'refund_processed_by': self.refund_processed_by,
            'coupon_code': self.coupon_code,
            'original_amount': float(self.original_amount) if self.original_amount is not None else None,
            'discount_amount': float(self.discount_amount) if self.discount_amount is not None else None,
            'coupon_id': self.coupon_id
        }

class SubscriptionRecord(Base):
    """开通套餐记录表"""
    __tablename__ = 'subscription_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    package_id = Column(Integer, ForeignKey('coin_packages.id'), nullable=False)
    order_no = Column(String(50), unique=True, nullable=False, index=True)
    coin_spent = Column(Integer, nullable=False)
    duration_days = Column(Integer, nullable=False)
    status = Column(String(20), default='success', nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")
    package = relationship("CoinPackage")

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'package_id': self.package_id,
            'order_no': self.order_no,
            'coin_spent': self.coin_spent,
            'duration_days': self.duration_days,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# ============== 数据库管理 ==============
class CoinTransaction(Base):
    """金币交易记录表"""
    __tablename__ = 'coin_transactions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    amount = Column(Integer, nullable=False)
    type = Column(String(20), nullable=False)
    reason = Column(String(500), nullable=True)
    gift_card_code = Column(String(100), nullable=True)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    user = relationship("User", back_populates="coin_transactions", foreign_keys=[user_id])
    creator = relationship("User", foreign_keys=[created_by])

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'amount': self.amount,
            'type': self.type,
            'reason': self.reason,
            'gift_card_code': self.gift_card_code,
            'created_by': self.created_by,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class GiftCardPurchaseRecord(Base):
    """礼品卡购买记录表"""
    __tablename__ = 'gift_card_purchase_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    package_id = Column(Integer, ForeignKey('coin_packages.id'), nullable=True, index=True)
    order_no = Column(String(50), unique=True, nullable=False, index=True)
    coin_spent = Column(Integer, nullable=False)
    activation_code_id = Column(Integer, ForeignKey('activation_codes.id'), nullable=True)
    code = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    user = relationship("User", foreign_keys=[user_id])
    package = relationship("CoinPackage", foreign_keys=[package_id])
    activation_code = relationship("ActivationCode", foreign_keys=[activation_code_id])

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'package_id': self.package_id,
            'order_no': self.order_no,
            'coin_spent': self.coin_spent,
            'activation_code_id': self.activation_code_id,
            'code': self.code,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class UserCoin(Base):
    """用户金币余额表"""
    __tablename__ = 'user_coins'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, unique=True, index=True)
    balance = Column(Integer, default=0, nullable=False)
    total_recharged = Column(Integer, default=0, nullable=False)
    total_spent = Column(Integer, default=0, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User")

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'balance': self.balance,
            'total_recharged': self.total_recharged,
            'total_spent': self.total_spent,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class RechargeRecord(Base):
    """充值记录表"""
    __tablename__ = 'recharge_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    order_no = Column(String(50), unique=True, nullable=False, index=True)
    amount_yuan = Column(Numeric(10, 2), nullable=False)  # 实际支付金额（元），保留两位小数
    coin_amount = Column(Integer, nullable=False)
    status = Column(String(20), default='pending', nullable=False)
    pay_method = Column(String(50), nullable=True)
    pay_time = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # 优惠码相关字段
    coupon_code = Column(String(50), nullable=True)  # 使用的优惠码
    original_amount_yuan = Column(Numeric(10, 2), nullable=True)  # 原始金额（优惠前），保留两位小数
    discount_amount_yuan = Column(Numeric(10, 2), nullable=True)  # 优惠金额，保留两位小数
    coupon_id = Column(Integer, ForeignKey('coupon_codes.id'), nullable=True)  # 关联的优惠码ID

    user = relationship("User")
    coupon = relationship("CouponCode")

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'order_no': self.order_no,
            'amount_yuan': float(self.amount_yuan) if self.amount_yuan is not None else None,
            'coin_amount': self.coin_amount,
            'status': self.status,
            'pay_method': self.pay_method,
            'pay_time': self.pay_time.isoformat() if self.pay_time else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'coupon_code': self.coupon_code,
            'original_amount_yuan': float(self.original_amount_yuan) if self.original_amount_yuan is not None else None,
            'discount_amount_yuan': float(self.discount_amount_yuan) if self.discount_amount_yuan is not None else None,
            'coupon_id': self.coupon_id
        }

class EmailVerificationCode(Base):
    """邮箱验证码表"""
    __tablename__ = 'email_verification_codes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    email = Column(String(100), nullable=False, index=True)
    code = Column(String(10), nullable=False)
    purpose = Column(String(50), nullable=False)  # 用途：register, reset_password, bind_email, etc.
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime, nullable=True)
    ip_address = Column(String(45), nullable=True)

    user = relationship("User")

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'email': self.email,
            'code': self.code,
            'purpose': self.purpose,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_used': self.is_used,
            'used_at': self.used_at.isoformat() if self.used_at else None,
            'ip_address': self.ip_address
        }

class EmailSendLog(Base):
    """邮件发送日志表"""
    __tablename__ = 'email_send_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    email = Column(String(100), nullable=False, index=True)
    send_type = Column(String(50), nullable=False)  # 发送类型：verification_code, notification, etc.
    content = Column(Text, nullable=True)
    code = Column(String(10), nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    is_expired = Column(Boolean, default=False, nullable=False)
    is_success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)

    user = relationship("User")

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'email': self.email,
            'send_type': self.send_type,
            'content': self.content,
            'code': self.code,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_used': self.is_used,
            'is_expired': self.is_expired,
            'is_success': self.is_success,
            'error_message': self.error_message
        }

class EmailConfig(Base):
    """邮件配置表"""
    __tablename__ = 'email_configs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    provider = Column(String(50), default='resend')  # 邮件服务商: resend, smtp
    system_email = Column(String(100), nullable=True)  # 发件邮箱地址
    resend_api_key = Column(String(255), nullable=True)  # Resend API Key
    smtp_server = Column(String(100), nullable=True)  # SMTP服务器
    smtp_port = Column(Integer, default=587)  # SMTP端口
    smtp_password = Column(String(255), nullable=True)  # SMTP密码
    sender_name = Column(String(100), default='Emby Manager')  # 发件人名称
    email_template = Column(Text, nullable=True)  # 邮件内容模板
    email_subject = Column(String(200), default='验证码通知')  # 邮件主题
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'provider': self.provider,
            'system_email': self.system_email,
            'resend_api_key': self.resend_api_key,
            'smtp_server': self.smtp_server,
            'smtp_port': self.smtp_port,
            'smtp_password': self.smtp_password,
            'sender_name': self.sender_name,
            'email_template': self.email_template,
            'email_subject': self.email_subject,
            'is_enabled': self.is_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ClientType(enum.Enum):
    """客户端类型枚举"""
    ANDROID = "android"
    PC = "pc"
    TV = "tv"
    MACOS = "macos"
    LINUX = "linux"
    IOS = "ios"

class ClientDownload(Base):
    """客户端下载表"""
    __tablename__ = 'client_downloads'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)  # 客户端名称
    client_type = Column(Enum(ClientType), nullable=False)  # 客户端类型
    description = Column(Text, nullable=True)  # 功能描述
    version = Column(String(50), nullable=True)  # 版本号
    file_path = Column(String(255), nullable=True)  # 文件路径（iOS类型为空）
    original_filename = Column(String(255), nullable=True)  # 原始文件名
    download_url = Column(String(500), nullable=True)  # 外部下载链接（可选）
    app_store_url = Column(String(500), nullable=True)  # App Store链接（仅iOS类型）
    file_size = Column(Integer, default=0)  # 文件大小（字节）
    download_count = Column(Integer, default=0)  # 下载次数
    is_active = Column(Boolean, default=True, nullable=False)  # 是否启用
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'client_type': self.client_type.value,
            'description': self.description,
            'version': self.version,
            'file_path': self.file_path,
            'original_filename': self.original_filename,
            'download_url': self.download_url,
            'app_store_url': self.app_store_url,
            'file_size': self.file_size,
            'file_size_display': self.get_file_size_display(),
            'download_count': self.download_count,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def get_file_size_display(self):
        """获取格式化的文件大小"""
        if self.file_size < 1024:
            return f"{self.file_size} B"
        elif self.file_size < 1024 * 1024:
            return f"{self.file_size / 1024:.2f} KB"
        elif self.file_size < 1024 * 1024 * 1024:
            return f"{self.file_size / (1024 * 1024):.2f} MB"
        else:
            return f"{self.file_size / (1024 * 1024 * 1024):.2f} GB"

    def get_icon_class(self):
        """获取客户端类型对应的图标类"""
        icon_map = {
            ClientType.ANDROID: 'fab fa-android',
            ClientType.PC: 'fab fa-windows',
            ClientType.TV: 'fas fa-tv',
            ClientType.MACOS: 'fas fa-desktop',
            ClientType.LINUX: 'fab fa-linux',
            ClientType.IOS: 'fab fa-apple'
        }
        return icon_map.get(self.client_type, 'fas fa-download')

    def get_type_display(self):
        """获取客户端类型的中文显示"""
        type_map = {
            ClientType.ANDROID: '安卓端',
            ClientType.PC: 'PC端',
            ClientType.TV: '电视TV端',
            ClientType.MACOS: 'macOS端',
            ClientType.LINUX: 'Linux端',
            ClientType.IOS: 'iOS端'
        }
        return type_map.get(self.client_type, '未知')


class DanmakuAPI(Base):
    """弹幕API配置表"""
    __tablename__ = 'danmaku_apis'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)  # API名称
    url = Column(String(500), nullable=False)   # API地址
    description = Column(Text, nullable=True)   # 描述
    is_default = Column(Boolean, default=False) # 是否为默认
    is_active = Column(Boolean, default=True)   # 是否启用
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<DanmakuAPI(id={self.id}, name='{self.name}', url='{self.url}')>"

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'description': self.description,
            'is_default': self.is_default,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class WebDAVServer(Base):
    """WebDAV 服务器配置表"""
    __tablename__ = 'webdav_servers'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)  # 显示名称
    server_url = Column(String(500), nullable=False)  # WebDAV 根地址
    server_type = Column(String(50), default='generic', nullable=False)  # generic / alist / nextcloud
    admin_username = Column(String(100), nullable=True)  # 管理员/服务账号
    admin_password = Column(String(255), nullable=True)  # 管理员密码或 API Token
    root_path = Column(String(500), default='', nullable=False)  # 用户目录根前缀
    default_quota_bytes = Column(Integer, nullable=True)  # 默认容量（字节）
    is_active = Column(Boolean, default=True, nullable=False)  # 是否启用
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    assignments = relationship("UserWebDAVAssignment", back_populates="server", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<WebDAVServer(id={self.id}, name='{self.name}', type='{self.server_type}')>"

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'server_url': self.server_url,
            'server_type': self.server_type,
            'admin_username': self.admin_username,
            'admin_password': '***' if self.admin_password else None,
            'root_path': self.root_path,
            'default_quota_bytes': self.default_quota_bytes,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class UserWebDAVAssignment(Base):
    """用户 WebDAV 分配表"""
    __tablename__ = 'user_webdav_assignments'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    server_id = Column(Integer, ForeignKey('webdav_servers.id'), nullable=False, index=True)
    assigned_path = Column(String(500), nullable=False)  # 该用户在该服务器上的目录
    quota_bytes = Column(Integer, nullable=True)  # 管理员为该用户设置的容量
    is_active = Column(Boolean, default=True, nullable=False)  # 是否启用
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    user = relationship("User", back_populates="webdav_assignments")
    server = relationship("WebDAVServer", back_populates="assignments")

    __table_args__ = (
        UniqueConstraint('server_id', 'assigned_path', name='uix_webdav_server_path'),
    )

    def __repr__(self):
        return f"<UserWebDAVAssignment(id={self.id}, user_id={self.user_id}, server_id={self.server_id})>"

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'server_id': self.server_id,
            'assigned_path': self.assigned_path,
            'quota_bytes': self.quota_bytes,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'server': self.server.to_dict() if self.server else None
        }


class UserGuideDoc(Base):
    """用户使用文档表"""
    __tablename__ = 'user_guide_docs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform = Column(Enum(DocPlatform), nullable=False, index=True)  # 平台类型
    title = Column(String(200), nullable=False)  # 文档标题
    content_type = Column(String(20), default='html', nullable=False)  # 内容类型：html, link
    content = Column(Text, nullable=True)  # HTML内容（当content_type为html时）
    link_url = Column(String(500), nullable=True)  # 外部链接（当content_type为link时）
    is_active = Column(Boolean, default=True, nullable=False)  # 是否启用
    sort_order = Column(Integer, default=0, nullable=False)  # 排序顺序
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    def __repr__(self):
        return f"<UserGuideDoc(id={self.id}, platform='{self.platform.value}', title='{self.title}')>"

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'platform': self.platform.value,
            'title': self.title,
            'content_type': self.content_type,
            'content': self.content,
            'link_url': self.link_url,
            'is_active': self.is_active,
            'sort_order': self.sort_order,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def get_platform_display(self):
        """获取平台类型的中文显示"""
        platform_map = {
            DocPlatform.ANDROID: '安卓端',
            DocPlatform.IOS: 'iOS端',
            DocPlatform.TV: '电视TV端',
            DocPlatform.PC: 'PC端',
            DocPlatform.MAC: 'Mac端',
            DocPlatform.LINUX: 'Linux端'
        }
        return platform_map.get(self.platform, '未知')

    def get_platform_icon(self):
        """获取平台类型对应的图标类"""
        icon_map = {
            DocPlatform.ANDROID: 'fab fa-android',
            DocPlatform.IOS: 'fab fa-apple',
            DocPlatform.TV: 'fas fa-tv',
            DocPlatform.PC: 'fab fa-windows',
            DocPlatform.MAC: 'fab fa-apple',
            DocPlatform.LINUX: 'fab fa-linux'
        }
        return icon_map.get(self.platform, 'fas fa-file-alt')


# ============== 工单系统模型 ==============

class TicketType(enum.Enum):
    """工单类型枚举"""
    BUG = "bug"           # 故障修复
    REFUND = "refund"     # 申请退款
    FEATURE = "feature"   # 功能建议
    OTHER = "other"       # 其他

class TicketPriority(enum.Enum):
    """工单优先级枚举"""
    LOW = "low"       # 低
    MEDIUM = "medium" # 中
    HIGH = "high"     # 高

class TicketStatus(enum.Enum):
    """工单状态枚举"""
    PENDING = "pending"       # 未处理
    PROCESSING = "processing" # 处理中
    COMPLETED = "completed"   # 已完成

class Ticket(Base):
    """工单表"""
    __tablename__ = 'tickets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    title = Column(String(200), nullable=False)  # 工单标题
    type = Column(Enum(TicketType), default=TicketType.OTHER, nullable=False)  # 工单类型
    priority = Column(Enum(TicketPriority), default=TicketPriority.MEDIUM, nullable=False)  # 优先级
    status = Column(Enum(TicketStatus), default=TicketStatus.PENDING, nullable=False)  # 状态
    content = Column(Text, nullable=False)  # 工单内容
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    closed_at = Column(DateTime, nullable=True)  # 关闭时间

    # 关系
    user = relationship("User", back_populates="tickets")
    messages = relationship("TicketMessage", back_populates="ticket", cascade="all, delete-orphan", order_by="TicketMessage.created_at")

    def to_dict(self, include_messages=False):
        """转换为字典"""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else None,
            'title': self.title,
            'type': self.type.value,
            'type_display': self.get_type_display(),
            'priority': self.priority.value,
            'priority_display': self.get_priority_display(),
            'status': self.status.value,
            'status_display': self.get_status_display(),
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'message_count': len(self.messages) if self.messages else 0,
            'unread_count': sum(1 for m in self.messages if not m.is_read and m.sender_type == 'admin') if self.messages else 0
        }
        if include_messages:
            data['messages'] = [msg.to_dict() for msg in self.messages]
        return data

    def get_type_display(self):
        """获取工单类型中文显示"""
        type_map = {
            TicketType.BUG: '故障修复',
            TicketType.REFUND: '申请退款',
            TicketType.FEATURE: '功能建议',
            TicketType.OTHER: '其他'
        }
        return type_map.get(self.type, '其他')

    def get_priority_display(self):
        """获取优先级中文显示"""
        priority_map = {
            TicketPriority.LOW: '低',
            TicketPriority.MEDIUM: '中',
            TicketPriority.HIGH: '高'
        }
        return priority_map.get(self.priority, '中')

    def get_status_display(self):
        """获取状态中文显示"""
        status_map = {
            TicketStatus.PENDING: '未处理',
            TicketStatus.PROCESSING: '处理中',
            TicketStatus.COMPLETED: '已完成'
        }
        return status_map.get(self.status, '未处理')

    def get_type_icon(self):
        """获取工单类型图标"""
        icon_map = {
            TicketType.BUG: 'fas fa-wrench',
            TicketType.REFUND: 'fas fa-wallet',
            TicketType.FEATURE: 'fas fa-lightbulb',
            TicketType.OTHER: 'fas fa-question-circle'
        }
        return icon_map.get(self.type, 'fas fa-ticket-alt')


class TicketMessage(Base):
    """工单消息表"""
    __tablename__ = 'ticket_messages'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ticket_id = Column(Integer, ForeignKey('tickets.id'), nullable=False, index=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    sender_type = Column(String(10), nullable=False)  # 'user' 或 'admin'
    content = Column(Text, nullable=False)  # 消息内容
    is_read = Column(Boolean, default=False, nullable=False)  # 是否已读
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # 关系
    ticket = relationship("Ticket", back_populates="messages")
    sender = relationship("User")

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'ticket_id': self.ticket_id,
            'sender_id': self.sender_id,
            'sender_name': self.sender.username if self.sender else '未知用户',
            'sender_type': self.sender_type,
            'content': self.content,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# 添加User模型的反向关系
User.tickets = relationship("Ticket", back_populates="user", cascade="all, delete-orphan")


# ============== 数据库管理 ==============
# 生产环境优化配置 - 支持高并发
# SQLite不支持连接池参数，使用NullPool
from sqlalchemy.pool import NullPool

engine = create_engine(
    f'sqlite:///{DATABASE_PATH}',
    echo=False,
    poolclass=NullPool,  # SQLite使用NullPool
    connect_args={'timeout': 30, 'check_same_thread': False},
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=True)
DBSession = scoped_session(SessionLocal)

def init_db():
    Base.metadata.create_all(engine)
    
    # 数据库迁移：检查并添加缺失的列
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('users')]
    
    # 添加 disabled_at 列（如果不存在）
    if 'disabled_at' not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN disabled_at DATETIME"))
        logger.info("数据库迁移：添加 disabled_at 列")

    # 添加 emby_access_disabled 列（如果不存在）
    if 'emby_access_disabled' not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN emby_access_disabled BOOLEAN NOT NULL DEFAULT 0"))
        logger.info("数据库迁移：添加 emby_access_disabled 列")

    # 添加 coins 列（如果不存在）
    if 'coins' not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN coins INTEGER NOT NULL DEFAULT 0"))
        logger.info("数据库迁移：添加 coins 列")
    
    # 删除旧的列（如果存在）
    if 'is_manually_disabled' in columns:
        # SQLite 不支持直接删除列，需要重建表
        logger.info("数据库迁移：检测到旧列 is_manually_disabled，建议删除数据库重新创建")
    
    if 'is_manually_enabled' in columns:
        logger.info("数据库迁移：检测到旧列 is_manually_enabled，建议删除数据库重新创建")
    
    # 检查并创建 coin_transactions 表（如果不存在）
    tables = inspector.get_table_names()
    if 'coin_transactions' not in tables:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS coin_transactions (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    type VARCHAR(20) NOT NULL,
                    reason VARCHAR(500),
                    created_by INTEGER,
                    is_read BOOLEAN NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users (id),
                    FOREIGN KEY(created_by) REFERENCES users (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_coin_transactions_user_id ON coin_transactions (user_id)"))
        logger.info("数据库迁移：创建 coin_transactions 表")
    
    # 检查并添加 coin_transactions.gift_card_code 列（如果不存在）
    if 'coin_transactions' in tables:
        coin_tx_columns = [col['name'] for col in inspector.get_columns('coin_transactions')]
        if 'gift_card_code' not in coin_tx_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE coin_transactions ADD COLUMN gift_card_code VARCHAR(100)"))
            logger.info("数据库迁移：添加 coin_transactions.gift_card_code 列")
    
    # 检查并添加 login_logs.success 列（如果不存在）
    login_log_columns = [col['name'] for col in inspector.get_columns('login_logs')]
    if 'success' not in login_log_columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE login_logs ADD COLUMN success BOOLEAN NOT NULL DEFAULT 1"))
        logger.info("数据库迁移：添加 login_logs.success 列")
    
    # 检查并迁移 coin_packages 表
    if 'coin_packages' in tables:
        coin_pkg_columns = [col['name'] for col in inspector.get_columns('coin_packages')]
        if 'description' not in coin_pkg_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE coin_packages ADD COLUMN description TEXT"))
            logger.info("数据库迁移：添加 coin_packages.description 列")
        if 'is_recommended' not in coin_pkg_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE coin_packages ADD COLUMN is_recommended BOOLEAN NOT NULL DEFAULT 0"))
            logger.info("数据库迁移：添加 coin_packages.is_recommended 列")
        if 'sort_order' not in coin_pkg_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE coin_packages ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0"))
            logger.info("数据库迁移：添加 coin_packages.sort_order 列")
        if 'is_gift_card' not in coin_pkg_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE coin_packages ADD COLUMN is_gift_card BOOLEAN NOT NULL DEFAULT 0"))
            logger.info("数据库迁移：添加 coin_packages.is_gift_card 列")
    
    # 创建 package_tags 表（如果不存在）
    if 'package_tags' not in tables:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS package_tags (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    package_id INTEGER NOT NULL,
                    tag_text VARCHAR(50) NOT NULL,
                    tag_color VARCHAR(20) NOT NULL DEFAULT '#FF69B4',
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(package_id) REFERENCES coin_packages (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_package_tags_package_id ON package_tags (package_id)"))
        logger.info("数据库迁移：创建 package_tags 表")
    
    # 创建 gift_card_purchase_records 表（如果不存在）
    if 'gift_card_purchase_records' not in tables:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS gift_card_purchase_records (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    package_id INTEGER,
                    order_no VARCHAR(50) NOT NULL UNIQUE,
                    coin_spent INTEGER NOT NULL,
                    activation_code_id INTEGER,
                    code VARCHAR(100) NOT NULL,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users (id),
                    FOREIGN KEY(package_id) REFERENCES coin_packages (id),
                    FOREIGN KEY(activation_code_id) REFERENCES activation_codes (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_gift_card_purchase_records_user_id ON gift_card_purchase_records (user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_gift_card_purchase_records_order_no ON gift_card_purchase_records (order_no)"))
        logger.info("数据库迁移：创建 gift_card_purchase_records 表")
    
    # 创建 payment_orders 表（如果不存在）
    if 'payment_orders' not in tables:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS payment_orders (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    order_no VARCHAR(50) NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL,
                    amount NUMERIC(10, 2) NOT NULL,
                    coin_amount INTEGER NOT NULL,
                    payment_method VARCHAR(20) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    refund_qrcode_path VARCHAR(255),
                    created_at DATETIME NOT NULL,
                    paid_at DATETIME,
                    approved_at DATETIME,
                    approved_by INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users (id),
                    FOREIGN KEY(approved_by) REFERENCES users (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_orders_user_id ON payment_orders (user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_orders_status ON payment_orders (status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_orders_order_no ON payment_orders (order_no)"))
        logger.info("数据库迁移：创建 payment_orders 表")
    
    # 检查并添加 client_downloads.original_filename 列（如果不存在）
    client_downloads_columns = [col['name'] for col in inspector.get_columns('client_downloads')]
    if 'original_filename' not in client_downloads_columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE client_downloads ADD COLUMN original_filename VARCHAR(255)"))
        logger.info("数据库迁移：添加 client_downloads.original_filename 列")
    
    # 检查并添加 client_downloads.download_url 列（如果不存在）
    if 'download_url' not in client_downloads_columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE client_downloads ADD COLUMN download_url VARCHAR(500)"))
        logger.info("数据库迁移：添加 client_downloads.download_url 列")

    # 创建 coupon_codes 表（如果不存在）
    if 'coupon_codes' not in tables:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS coupon_codes (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    code VARCHAR(50) NOT NULL UNIQUE,
                    discount_percent INTEGER NOT NULL,
                    max_uses INTEGER NOT NULL,
                    current_uses INTEGER NOT NULL DEFAULT 0,
                    beneficiary_type VARCHAR(20) NOT NULL DEFAULT 'all',
                    beneficiary_user_ids TEXT,
                    valid_from DATETIME,
                    valid_until DATETIME,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL,
                    created_by INTEGER,
                    FOREIGN KEY(created_by) REFERENCES users (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_coupon_codes_code ON coupon_codes (code)"))
        logger.info("数据库迁移：创建 coupon_codes 表")

    # 创建 coupon_usage_records 表（如果不存在）
    if 'coupon_usage_records' not in tables:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS coupon_usage_records (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    coupon_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    order_no VARCHAR(50) NOT NULL,
                    original_amount NUMERIC(10, 2) NOT NULL,
                    discount_amount NUMERIC(10, 2) NOT NULL,
                    final_amount NUMERIC(10, 2) NOT NULL,
                    used_at DATETIME NOT NULL,
                    FOREIGN KEY(coupon_id) REFERENCES coupon_codes (id),
                    FOREIGN KEY(user_id) REFERENCES users (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_coupon_usage_records_coupon_id ON coupon_usage_records (coupon_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_coupon_usage_records_user_id ON coupon_usage_records (user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_coupon_usage_records_order_no ON coupon_usage_records (order_no)"))
        logger.info("数据库迁移：创建 coupon_usage_records 表")

    # 检查并添加 recharge_records 的优惠码相关列
    if 'recharge_records' in tables:
        recharge_columns = [col['name'] for col in inspector.get_columns('recharge_records')]
        if 'coupon_code' not in recharge_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE recharge_records ADD COLUMN coupon_code VARCHAR(50)"))
                conn.execute(text("ALTER TABLE recharge_records ADD COLUMN original_amount_yuan NUMERIC(10, 2)"))
                conn.execute(text("ALTER TABLE recharge_records ADD COLUMN discount_amount_yuan NUMERIC(10, 2)"))
                conn.execute(text("ALTER TABLE recharge_records ADD COLUMN coupon_id INTEGER"))
            logger.info("数据库迁移：添加 recharge_records 优惠码相关列")

    # 检查并添加 payment_orders 的优惠码相关列
    if 'payment_orders' in tables:
        payment_columns = [col['name'] for col in inspector.get_columns('payment_orders')]
        if 'coupon_code' not in payment_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE payment_orders ADD COLUMN coupon_code VARCHAR(50)"))
                conn.execute(text("ALTER TABLE payment_orders ADD COLUMN original_amount NUMERIC(10, 2)"))
                conn.execute(text("ALTER TABLE payment_orders ADD COLUMN discount_amount NUMERIC(10, 2)"))
                conn.execute(text("ALTER TABLE payment_orders ADD COLUMN coupon_id INTEGER"))
            logger.info("数据库迁移：添加 payment_orders 优惠码相关列")

    db = DBSession()
    try:
        # 检查是否已有管理员
        admin = db.query(User).filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password_hash=generate_password_hash('123'),
                role=UserRole.ADMIN,
                is_active=True,
                expiry_date=None
            )
            db.add(admin)
            logger.info("创建默认管理员账号: admin / 123")
        
        # 初始化系统配置
        configs = [
            ('emby_server_url', ''),
            ('emby_api_key', ''),
            ('site_name', 'Emby Manager'),
            ('register_enabled', 'true'),
        ]
        for key, value in configs:
            existing = db.query(SystemConfig).filter_by(key=key).first()
            if not existing:
                db.add(SystemConfig(key=key, value=value))
        
        # 初始化邮件配置
        email_config = db.query(EmailConfig).first()
        if not email_config:
            default_template = """<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <p>亲爱的 {{username}}，您好！</p>
    
    <p>您的验证码是：</p>
    <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; font-weight: bold; color: #ff6b9d; margin: 20px 0;">
        {{code}}
    </div>
    
    <p>该验证码将在 <strong>{{expire_minutes}} 分钟</strong>后过期，请尽快使用。</p>
    
    <p>如非本人操作，请忽略此邮件。</p>
    
    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="color: #999; font-size: 12px;">{{site_name}} 团队</p>
</div>"""
            email_config = EmailConfig(
                system_email='',
                email_template=default_template,
                is_enabled=True
            )
            db.add(email_config)
            logger.info("初始化默认邮件配置")
        
        db.commit()
        logger.info("数据库初始化完成")
    except Exception as e:
        db.rollback()
        logger.error(f"数据库初始化失败: {e}")
    finally:
        db.close()

# ============== Flask 应用 ==============
app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# 登录失败限制配置
login_attempts = {}  # 记录登录尝试
MAX_LOGIN_ATTEMPTS = 5  # 最大尝试次数
LOGIN_BLOCK_TIME = 300  # 封禁时间（5分钟）

# 密码修改安全检测配置
password_change_attempts = {}  # 记录用户密码修改次数 {user_id: [timestamp1, timestamp2, ...]}
password_change_ip_attempts = {}  # 记录IP地址的密码修改行为 {ip: {'user_ids': set(), 'timestamps': []}}
password_change_failures = {}  # 记录用户连续失败次数 {user_id: {'count': 0, 'last_time': timestamp}}
PASSWORD_CHANGE_HOUR_LIMIT = 5  # 1小时内最大修改次数
PASSWORD_CHANGE_IP_MINUTES = 10  # IP检测时间窗口（分钟）
PASSWORD_CHANGE_IP_USER_LIMIT = 3  # 同一IP在时间内最大不同用户数
PASSWORD_CHANGE_FAILURE_LIMIT = 3  # 连续失败次数限制

# Emby用户策略巡查相关内存数据结构
emby_policy_snapshots = {}  # {emby_user_id: {'policy_hash': str, 'timestamp': datetime, 'policy_data': dict}}
emby_policy_change_attempts = {}  # {emby_user_id: [timestamp1, timestamp2, ...]}
emby_policy_last_system_update = {}  # {emby_user_id: datetime}
EMBY_POLICY_CHANGE_HOUR_LIMIT = 3  # 1小时内最大策略变更次数，超过则封禁

# Emby策略巡查智能检测增强 - 新增内存数据结构
emby_policy_whitelist = {}  # {user_id: True} 可信管理员白名单（从数据库加载）
emby_policy_grace_period = {}  # {emby_user_id: {'first_change_time': datetime, 'change_count': int, 'is_elevation': bool}} 缓冲期信息
GRACE_PERIOD_MINUTES = 30  # 缓冲期时长（分钟）


def load_policy_whitelist_from_db():
    """从数据库加载白名单到内存（系统启动时调用）"""
    global emby_policy_whitelist
    try:
        db = get_db()
        try:
            whitelist_entries = db.query(PolicyWhitelist).all()
            emby_policy_whitelist = {}
            for entry in whitelist_entries:
                emby_policy_whitelist[entry.user_id] = True
            logger.info(f"从数据库加载白名单完成，共 {len(emby_policy_whitelist)} 个用户")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"从数据库加载白名单失败: {e}")
        emby_policy_whitelist = {}

# 添加缓存控制，防止浏览器缓存重定向
@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# CSRF保护 - 生成和验证token
def generate_csrf_token():
    """生成CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def verify_csrf_token(token):
    """验证CSRF token"""
    return token and token == session.get('csrf_token')

@app.context_processor
def inject_csrf_token():
    """将CSRF token注入到所有模板"""
    return dict(csrf_token=generate_csrf_token())

# ============== 工具函数 ==============
def get_db():
    return DBSession()

def ban_user_for_suspicious_activity(user_id, reason):
    """封禁用户并记录日志（同步禁用Emby用户）"""
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if user:
            # 禁用本地用户
            user.is_active = False
            db.commit()
            logger.warning(f"用户因可疑活动被封禁 - 用户ID: {user_id}, 用户名: {user.username}, 原因: {reason}")

            # 同步禁用Emby用户
            if user.emby_user_id and EmbyAPI.is_configured():
                try:
                    emby_result = EmbyAPI.disable_user(user.emby_user_id)
                    if emby_result:
                        logger.info(f"Emby用户已同步禁用: {user.username} (Emby ID: {user.emby_user_id})")
                    else:
                        logger.warning(f"Emby用户禁用失败: {user.username} (Emby ID: {user.emby_user_id})")
                except Exception as e:
                    logger.error(f"同步禁用Emby用户失败: {e}")
                    # Emby禁用失败不影响本地封禁结果

            return True
        return False
    except Exception as e:
        db.rollback()
        logger.error(f"封禁用户失败 - 用户ID: {user_id}, 错误: {e}")
        return False
    finally:
        db.close()

def monitor_emby_policies():
    """Emby用户策略自动巡查函数（智能检测增强版）

    定期检查所有绑定Emby的用户的策略状态，按优先级检测异常变更：
    1. 白名单检查 - 可信管理员跳过所有检测
    2. 频率检测 - 1小时内策略变更≥3次 → 封禁
    3. 首次提权缓冲期 - 检测到提权后进入30分钟缓冲期，缓冲期内再次变更→封禁
    4. 缓冲期清理 - 超过30分钟无异常则确认合法授权

    注意：对于系统创建前就存在的Emby原生管理员，首次巡查时会记录其状态，不会封禁
    """
    global emby_policy_snapshots, emby_policy_change_attempts, emby_policy_last_system_update
    global emby_policy_whitelist, emby_policy_grace_period

    # 检查Emby是否已配置
    if not EmbyAPI.is_configured():
        logger.debug("Emby未配置，跳过策略巡查")
        return

    db = get_db()
    try:
        # 获取所有绑定Emby的用户（emby_user_id不为空）
        users = db.query(User).filter(User.emby_user_id.isnot(None)).all()

        if not users:
            logger.debug("没有绑定Emby的用户，跳过策略巡查")
            return

        logger.info(f"开始Emby用户策略巡查，共 {len(users)} 个用户")

        current_time = datetime.now()
        hour_ago = current_time - timedelta(hours=1)
        grace_period_ago = current_time - timedelta(minutes=GRACE_PERIOD_MINUTES)

        for user in users:
            emby_user_id = user.emby_user_id
            if not emby_user_id:
                continue

            try:
                # 获取当前策略
                current_policy = EmbyAPI.get_user_policy(emby_user_id)
                if current_policy is None:
                    logger.warning(f"无法获取用户策略: {user.username} (Emby ID: {emby_user_id})")
                    continue

                # ========== 1. 白名单检查（最高优先级） ==========
                if user.id in emby_policy_whitelist:
                    logger.info(f"白名单用户策略变更，跳过检测: {user.username}")
                    # 更新快照但不检测
                    current_hash = EmbyAPI.calculate_policy_hash(current_policy)
                    if current_hash:
                        emby_policy_snapshots[emby_user_id] = {
                            'policy_hash': current_hash,
                            'timestamp': current_time,
                            'policy_data': EmbyAPI.get_critical_policy_fields(current_policy)
                        }
                    continue

                # 计算当前策略哈希
                current_hash = EmbyAPI.calculate_policy_hash(current_policy)
                if not current_hash:
                    logger.warning(f"无法计算策略哈希: {user.username}")
                    continue

                current_is_admin = current_policy.get('IsAdministrator', False)

                # ========== 首次巡查处理 ==========
                if emby_user_id not in emby_policy_snapshots:
                    # 首次巡查发现是管理员，记录为原生管理员
                    if current_is_admin:
                        logger.info(f"首次巡查发现用户是管理员，记录为原生管理员: {user.username} (Emby ID: {emby_user_id})")
                        emby_policy_snapshots[emby_user_id] = {
                            'policy_hash': current_hash,
                            'timestamp': current_time,
                            'policy_data': EmbyAPI.get_critical_policy_fields(current_policy),
                            'is_native_admin': True
                        }
                    else:
                        # 首次巡查，保存快照
                        emby_policy_snapshots[emby_user_id] = {
                            'policy_hash': current_hash,
                            'timestamp': current_time,
                            'policy_data': EmbyAPI.get_critical_policy_fields(current_policy)
                        }
                        logger.debug(f"首次保存策略快照: {user.username}")
                    continue

                # 获取上次快照
                last_snapshot = emby_policy_snapshots[emby_user_id]
                last_hash = last_snapshot['policy_hash']
                last_policy_data = last_snapshot.get('policy_data', {})
                was_admin = last_policy_data.get('IsAdministrator', False)
                is_native_admin = last_snapshot.get('is_native_admin', False)

                # 如果策略没有变化，检查缓冲期是否需要清理
                if current_hash == last_hash:
                    # 检查是否在缓冲期内且已超过缓冲期时间
                    if emby_user_id in emby_policy_grace_period:
                        grace_info = emby_policy_grace_period[emby_user_id]
                        if grace_info['first_change_time'] < grace_period_ago:
                            # 缓冲期结束，确认合法授权
                            del emby_policy_grace_period[emby_user_id]
                            logger.info(f"缓冲期结束，确认为合法授权: {user.username}")
                    continue

                # ========== 检测到策略变更 ==========
                logger.warning(f"检测到Emby用户策略变更: {user.username} (Emby ID: {emby_user_id})")

                # 检查是否是系统触发的变更
                last_system_update = emby_policy_last_system_update.get(emby_user_id)
                if last_system_update and last_system_update > last_snapshot['timestamp']:
                    logger.info(f"系统触发的策略变更，更新快照: {user.username}")
                    emby_policy_snapshots[emby_user_id] = {
                        'policy_hash': current_hash,
                        'timestamp': current_time,
                        'policy_data': EmbyAPI.get_critical_policy_fields(current_policy)
                    }
                    continue

                # ========== 2. 频率检测 ==========
                if emby_user_id not in emby_policy_change_attempts:
                    emby_policy_change_attempts[emby_user_id] = []
                emby_policy_change_attempts[emby_user_id].append(current_time)

                # 清理超过1小时的记录
                emby_policy_change_attempts[emby_user_id] = [
                    ts for ts in emby_policy_change_attempts[emby_user_id] if ts > hour_ago
                ]

                change_count = len(emby_policy_change_attempts[emby_user_id])
                if change_count >= EMBY_POLICY_CHANGE_HOUR_LIMIT:
                    logger.error(f"策略变更频率超限: {user.username}, 1小时内变更次数: {change_count}")
                    ban_user_for_suspicious_activity(
                        user.id,
                        f"频繁修改Emby用户策略"
                    )
                    # 清理记录
                    if emby_user_id in emby_policy_snapshots:
                        del emby_policy_snapshots[emby_user_id]
                    if emby_user_id in emby_policy_change_attempts:
                        del emby_policy_change_attempts[emby_user_id]
                    if emby_user_id in emby_policy_grace_period:
                        del emby_policy_grace_period[emby_user_id]
                    continue

                # ========== 3. 首次提权缓冲期检测 ==========
                # 检测是否从非管理员变为管理员
                if current_is_admin and not was_admin and not is_native_admin:
                    # 检查是否已在缓冲期内
                    if emby_user_id not in emby_policy_grace_period:
                        # 首次提权，进入缓冲期
                        emby_policy_grace_period[emby_user_id] = {
                            'first_change_time': current_time,
                            'change_count': 1,
                            'is_elevation': True
                        }
                        logger.warning(f"首次检测到提权，进入缓冲期: {user.username}, 缓冲期{GRACE_PERIOD_MINUTES}分钟")
                        # 更新快照
                        emby_policy_snapshots[emby_user_id] = {
                            'policy_hash': current_hash,
                            'timestamp': current_time,
                            'policy_data': EmbyAPI.get_critical_policy_fields(current_policy)
                        }
                        continue
                    else:
                        # 已在缓冲期内，检查是否超时
                        grace_info = emby_policy_grace_period[emby_user_id]
                        if grace_info['first_change_time'] >= grace_period_ago:
                            # 缓冲期内再次变更
                            grace_info['change_count'] += 1
                            if grace_info['change_count'] >= 2:
                                logger.error(f"缓冲期内多次策略变更: {user.username}, 变更次数: {grace_info['change_count']}")
                                ban_user_for_suspicious_activity(
                                    user.id,
                                    f"缓冲期内多次策略变更"
                                )
                                # 清理记录
                                if emby_user_id in emby_policy_snapshots:
                                    del emby_policy_snapshots[emby_user_id]
                                if emby_user_id in emby_policy_change_attempts:
                                    del emby_policy_change_attempts[emby_user_id]
                                if emby_user_id in emby_policy_grace_period:
                                    del emby_policy_grace_period[emby_user_id]
                                continue
                            else:
                                logger.error(f"缓冲期内策略变更: {user.username}, 当前变更次数: {grace_info['change_count']}")
                        else:
                            # 缓冲期已过期，重新计算
                            del emby_policy_grace_period[emby_user_id]
                            logger.info(f"缓冲期结束，确认为合法授权: {user.username}")

                # 更新快照
                emby_policy_snapshots[emby_user_id] = {
                    'policy_hash': current_hash,
                    'timestamp': current_time,
                    'policy_data': EmbyAPI.get_critical_policy_fields(current_policy)
                }
                logger.info(f"策略快照已更新: {user.username}, 1小时内变更次数: {change_count}")

            except Exception as e:
                logger.error(f"巡查用户策略时出错: {user.username}, 错误: {e}")
                continue

        # ========== 4. 缓冲期清理 ==========
        # 清理超过缓冲期且无异常的用户
        for emby_user_id in list(emby_policy_grace_period.keys()):
            try:
                grace_info = emby_policy_grace_period[emby_user_id]
                if grace_info['first_change_time'] < grace_period_ago:
                    # 查找用户名用于日志
                    user = db.query(User).filter_by(emby_user_id=emby_user_id).first()
                    username = user.username if user else emby_user_id
                    del emby_policy_grace_period[emby_user_id]
                    logger.info(f"缓冲期结束，确认为合法授权: {username}")
            except Exception as e:
                logger.debug(f"清理缓冲期记录时出错: {e}")

        logger.info("Emby用户策略巡查完成")

    except Exception as e:
        logger.error(f"Emby策略巡查失败: {e}")
    finally:
        db.close()


def cleanup_policy_monitor_data():
    """清理Emby策略监控数据（智能检测增强版）

    1. 清理超过1小时的emby_policy_change_attempts记录
    2. 清理超过30分钟的emby_policy_grace_period记录
    3. 清理已不存在用户的快照和记录
    4. 清理不存在的用户的emby_policy_whitelist记录
    """
    global emby_policy_snapshots, emby_policy_change_attempts, emby_policy_last_system_update
    global emby_policy_whitelist, emby_policy_grace_period

    current_time = datetime.now()
    hour_ago = current_time - timedelta(hours=1)
    grace_period_ago = current_time - timedelta(minutes=GRACE_PERIOD_MINUTES)

    # 清理超过1小时的变更尝试记录
    for emby_user_id in list(emby_policy_change_attempts.keys()):
        emby_policy_change_attempts[emby_user_id] = [
            ts for ts in emby_policy_change_attempts[emby_user_id] if ts > hour_ago
        ]
        if not emby_policy_change_attempts[emby_user_id]:
            del emby_policy_change_attempts[emby_user_id]

    # 清理已不存在用户的快照和记录
    db = get_db()
    try:
        # 获取所有有效的emby_user_id
        valid_emby_ids = {u.emby_user_id for u in db.query(User).filter(User.emby_user_id.isnot(None)).all()}

        # 清理无效的快照
        for emby_user_id in list(emby_policy_snapshots.keys()):
            if emby_user_id not in valid_emby_ids:
                del emby_policy_snapshots[emby_user_id]
                logger.debug(f"清理无效用户的策略快照: {emby_user_id}")

        # 清理无效的变更尝试记录
        for emby_user_id in list(emby_policy_change_attempts.keys()):
            if emby_user_id not in valid_emby_ids:
                del emby_policy_change_attempts[emby_user_id]

        # 清理无效的系统更新记录
        for emby_user_id in list(emby_policy_last_system_update.keys()):
            if emby_user_id not in valid_emby_ids:
                del emby_policy_last_system_update[emby_user_id]

        # 清理超过缓冲期的grace_period记录
        for emby_user_id in list(emby_policy_grace_period.keys()):
            grace_info = emby_policy_grace_period[emby_user_id]
            if grace_info['first_change_time'] < grace_period_ago:
                # 查找用户名用于日志
                user = db.query(User).filter_by(emby_user_id=emby_user_id).first()
                username = user.username if user else emby_user_id
                del emby_policy_grace_period[emby_user_id]
                logger.info(f"缓冲期结束，确认为合法授权: {username}")

        # 清理无效的grace_period记录（用户不存在）
        for emby_user_id in list(emby_policy_grace_period.keys()):
            if emby_user_id not in valid_emby_ids:
                del emby_policy_grace_period[emby_user_id]
                logger.debug(f"清理无效用户的缓冲期记录: {emby_user_id}")

        # 清理不存在的用户的白名单记录
        valid_user_ids = {u.id for u in db.query(User).all()}
        for user_id in list(emby_policy_whitelist.keys()):
            if user_id not in valid_user_ids:
                del emby_policy_whitelist[user_id]
                logger.debug(f"清理无效用户的白名单记录: {user_id}")

    except Exception as e:
        logger.error(f"清理策略监控数据失败: {e}")
    finally:
        db.close()


def cleanup_password_attempts():
    """清理过期的密码修改记录"""
    current_time = datetime.now()
    hour_ago = current_time - timedelta(hours=1)
    ten_minutes_ago = current_time - timedelta(minutes=PASSWORD_CHANGE_IP_MINUTES)

    # 清理用户修改记录（保留1小时内的）
    for user_id in list(password_change_attempts.keys()):
        password_change_attempts[user_id] = [
            ts for ts in password_change_attempts[user_id] if ts > hour_ago
        ]
        if not password_change_attempts[user_id]:
            del password_change_attempts[user_id]

    # 清理IP记录（保留10分钟内的）
    for ip in list(password_change_ip_attempts.keys()):
        ip_data = password_change_ip_attempts[ip]
        ip_data['timestamps'] = [
            ts for ts in ip_data['timestamps'] if ts > ten_minutes_ago
        ]
        # 清理不再活跃的用户ID
        if not ip_data['timestamps']:
            del password_change_ip_attempts[ip]
    
    # 清理过期的失败记录（保留1小时内的）
    for user_id in list(password_change_failures.keys()):
        if password_change_failures[user_id]['last_time'] < hour_ago:
            del password_change_failures[user_id]

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': '请先登录'}), 401
            return redirect(url_for('login_page'))
        
        # 检查用户是否被禁用（is_active完全手动控制）
        db = get_db()
        try:
            user = db.query(User).get(session['user_id'])
            if user and not user.is_active:
                # 被禁用的用户无法访问
                if request.is_json:
                    return jsonify({'success': False, 'message': '账号已被禁用'}), 403
                return redirect(url_for('login_page'))
        finally:
            db.close()
        
        return f(*args, **kwargs)
    return decorated_function

def login_required_allow_expired(f):
    """允许过期用户登录（用于续期页面）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': '请先登录'}), 401
            return redirect(url_for('login_page'))
        
        # 检查用户是否被禁用（is_active完全手动控制）
        db = get_db()
        try:
            user = db.query(User).get(session['user_id'])
            if user and not user.is_active:
                if request.is_json:
                    return jsonify({'success': False, 'message': '账号已被禁用'}), 403
                return redirect(url_for('login_page'))
        finally:
            db.close()
        
        return f(*args, **kwargs)
    return decorated_function

def login_required_not_expired(f):
    """要求用户必须未过期（用于媒体库和客户端下载页面）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': '请先登录'}), 401
            return redirect(url_for('login_page'))
        
        db = get_db()
        try:
            user = db.query(User).get(session['user_id'])
            
            # 检查用户是否被禁用
            if user and not user.is_active:
                if request.is_json:
                    return jsonify({'success': False, 'message': '账号已被禁用'}), 403
                return redirect(url_for('login_page'))
            
            # 检查用户是否过期
            if user and user.is_expired():
                if request.is_json:
                    return jsonify({'success': False, 'message': '账号已过期，请先续期'}), 403
                flash('您的账号已过期，请先续期', 'warning')
                return redirect(url_for('user_profile_page'))
        finally:
            db.close()
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': '请先登录'}), 401
            return redirect(url_for('login_page'))
        
        db = get_db()
        try:
            user = db.query(User).get(session['user_id'])
            if not user or user.role != UserRole.ADMIN:
                if request.is_json:
                    return jsonify({'success': False, 'message': '需要管理员权限'}), 403
                return redirect(url_for('index'))
        finally:
            db.close()
        return f(*args, **kwargs)
    return decorated_function

def generate_activation_code():
    """生成10位大写字母+数字的激活码"""
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=10))

def get_duration_seconds(duration_type):
    """获取时长对应的秒数"""
    durations = {
        DurationType.HOUR: 3600,
        DurationType.DAY: 86400,
        DurationType.WEEK: 604800,
        DurationType.MONTH: 2592000,
        DurationType.QUARTER: 7776000,
        DurationType.YEAR: 31536000,
        DurationType.PERMANENT: 0
    }
    return durations.get(duration_type, 0)

def get_config(key, default=None):
    """获取系统配置"""
    db = get_db()
    try:
        config = db.query(SystemConfig).filter_by(key=key).first()
        return config.value if config else default
    finally:
        db.close()

def set_config(key, value):
    """设置系统配置"""
    db = get_db()
    try:
        config = db.query(SystemConfig).filter_by(key=key).first()
        if config:
            config.value = value
        else:
            config = SystemConfig(key=key, value=value)
            db.add(config)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"设置配置失败: {e}")
    finally:
        db.close()

# ============== Emby API 集成 ==============
class EmbyAPI:
    @staticmethod
    def get_server_url():
        return get_config('emby_server_url', '')
    
    @staticmethod
    def get_api_key():
        return get_config('emby_api_key', '')
    
    @staticmethod
    def is_configured():
        return bool(EmbyAPI.get_server_url() and EmbyAPI.get_api_key())
    
    @staticmethod
    def get_headers():
        return {
            'X-Emby-Token': EmbyAPI.get_api_key(),
            'Content-Type': 'application/json'
        }
    
    @staticmethod
    def get_users():
        """获取Emby用户列表"""
        if not EmbyAPI.is_configured():
            return None
        try:
            url = f"{EmbyAPI.get_server_url()}/emby/Users"
            response = requests.get(url, headers=EmbyAPI.get_headers(), timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"获取Emby用户失败: {e}")
            return None
    
    @staticmethod
    def get_user(user_id):
        """获取单个Emby用户"""
        if not EmbyAPI.is_configured():
            return None
        try:
            url = f"{EmbyAPI.get_server_url()}/emby/Users/{user_id}"
            response = requests.get(url, headers=EmbyAPI.get_headers(), timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"获取Emby用户失败: {e}")
            return None

    @staticmethod
    def get_user_policy(emby_user_id):
        """获取用户当前策略

        Args:
            emby_user_id: Emby用户ID

        Returns:
            Policy字段字典，失败返回None
        """
        if not EmbyAPI.is_configured():
            return None
        try:
            url = f"{EmbyAPI.get_server_url()}/emby/Users/{emby_user_id}"
            response = requests.get(url, headers=EmbyAPI.get_headers(), timeout=10)
            if response.status_code == 200:
                user_data = response.json()
                return user_data.get('Policy', {})
            return None
        except Exception as e:
            logger.error(f"获取Emby用户策略失败: {e}")
            return None

    @staticmethod
    def calculate_policy_hash(policy_data):
        """计算策略哈希

        Args:
            policy_data: 策略数据字典

        Returns:
            MD5哈希字符串
        """
        if not policy_data:
            return ""
        try:
            critical_fields = EmbyAPI.get_critical_policy_fields(policy_data)
            policy_str = json.dumps(critical_fields, sort_keys=True, ensure_ascii=False)
            return hashlib.md5(policy_str.encode('utf-8')).hexdigest()
        except Exception as e:
            logger.error(f"计算策略哈希失败: {e}")
            return ""

    @staticmethod
    def get_critical_policy_fields(policy_data):
        """提取关键安全字段

        Args:
            policy_data: 策略数据字典

        Returns:
            包含关键安全字段的字典
        """
        if not policy_data:
            return {}
        critical_fields = [
            'IsAdministrator',
            'IsDisabled',
            'EnableContentDownloading',
            'EnableContentDeletion',
            'EnableMediaPlayback',
            'EnableAudioPlaybackTranscoding',
            'EnableVideoPlaybackTranscoding',
            'EnablePlaybackRemuxing',
            'EnableRemoteAccess',
            'EnableRemoteControlOfOtherUsers',
            'EnableSharedDeviceControl',
            'EnableLiveTvManagement',
            'EnablePublicSharing',
            'MaxActiveSessions',
            'EnableAllFolders',
            'EnabledFolders',
        ]
        result = {}
        for field in critical_fields:
            if field in policy_data:
                result[field] = policy_data[field]
        return result

    @staticmethod
    def update_user(user_id, data):
        """更新Emby用户"""
        if not EmbyAPI.is_configured():
            logger.warning("Emby未配置，无法更新用户")
            return False
        try:
            # 先获取用户当前信息
            user_info = EmbyAPI.get_user(user_id)
            if not user_info:
                logger.error(f"无法获取Emby用户信息: {user_id}")
                return False
            
            # 更新用户数据
            url = f"{EmbyAPI.get_server_url()}/emby/Users/{user_id}"
            
            # 合并现有数据和更新数据
            update_data = {**user_info, **data}
            
            logger.info(f"正在更新Emby用户 {user_id}: {data}")
            response = requests.post(url, headers=EmbyAPI.get_headers(), json=update_data, timeout=10)
            
            if response.status_code in [200, 204]:
                logger.info(f"Emby用户更新成功: {user_id}")
                return True
            else:
                logger.error(f"更新Emby用户失败: HTTP {response.status_code}, 响应: {response.text}")
                return False
        except Exception as e:
            logger.error(f"更新Emby用户失败: {e}")
            return False
    
    @staticmethod
    def create_user(username, password, is_disabled=False):
        """在Emby中创建新用户并设置密码和应用默认策略
        
        Args:
            username: 用户名
            password: 密码
            is_disabled: 是否禁用该用户（用于邮箱注册未激活的用户）
        """
        if not EmbyAPI.is_configured():
            return None
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            headers = EmbyAPI.get_headers()
            headers['Accept'] = 'application/json'
            
            # 步骤1: 先用 /Users/New 创建用户（Emby的CreateUserByName只包含Name字段）
            create_url = f"{server_url}/emby/Users/New"
            create_data = {
                'Name': username
            }
            
            logger.info(f"步骤1: 正在创建Emby用户: {username}, is_disabled={is_disabled}")
            create_response = requests.post(create_url, headers=headers, json=create_data, timeout=10)
            
            logger.info(f"创建Emby用户响应: HTTP {create_response.status_code}")
            if create_response.text:
                logger.info(f"创建Emby用户响应内容: {create_response.text[:200]}")
            
            if create_response.status_code not in [200, 201]:
                logger.error(f"创建Emby用户失败: HTTP {create_response.status_code}, 响应: {create_response.text}")
                return None
            
            result = create_response.json()
            emby_user_id = result.get('Id')
            if not emby_user_id:
                logger.error(f"创建Emby用户失败: 未返回用户ID")
                return None
            
            logger.info(f"Emby用户创建成功: {username}, ID: {emby_user_id}")
            
            # 步骤2: 设置密码
            if password:
                logger.info(f"步骤2: 正在设置Emby用户密码: {emby_user_id}")
                password_url = f"{server_url}/emby/Users/{emby_user_id}/Password"
                password_data = {
                    'CurrentPw': '',
                    'NewPw': password,
                    'ResetPassword': False
                }
                
                password_response = requests.post(password_url, headers=headers, json=password_data, timeout=10)
                
                logger.info(f"设置密码响应: HTTP {password_response.status_code}")
                if password_response.text:
                    logger.info(f"设置密码响应内容: {password_response.text[:200]}")
                
                if password_response.status_code in [200, 204]:
                    logger.info(f"Emby用户密码设置成功: {emby_user_id}")
                else:
                    logger.warning(f"Emby用户密码设置失败: HTTP {password_response.status_code}, 但用户已创建")
            
            # 步骤3: 应用默认用户策略（传入is_disabled参数）
            try:
                EmbyAPI.apply_default_policy(emby_user_id, is_disabled=is_disabled)
            except Exception as e:
                logger.warning(f"应用用户策略失败: {e}")
            
            return emby_user_id
        except Exception as e:
            logger.error(f"创建Emby用户失败: {e}")
            return None
    
    @staticmethod
    def update_password(user_id, new_password):
        """更新Emby用户密码 - 管理员重置密码"""
        if not EmbyAPI.is_configured():
            logger.warning("Emby未配置，无法更新密码")
            return False
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            
            # 使用标准请求头
            headers = EmbyAPI.get_headers()
            headers['Accept'] = 'application/json'
            
            # 方法1: 使用密码重置端点（管理员无需提供当前密码）
            # Emby API 格式: POST /Users/{Id}/Password/Reset
            reset_url = f"{server_url}/emby/Users/{user_id}/Password/Reset"
            
            # 使用 JSON 请求体（Emby官方格式）
            reset_data = {
                'Id': user_id,
                'NewPw': new_password
            }
            
            logger.info(f"方法1: 正在重置Emby用户密码: {user_id}")
            logger.info(f"请求URL: {reset_url}")
            logger.info(f"请求数据: {reset_data}")
            
            response = requests.post(reset_url, headers=headers, json=reset_data, timeout=10)
            
            logger.info(f"方法1响应: HTTP {response.status_code}")
            if response.text:
                logger.info(f"方法1响应内容: {response.text[:200]}")
            
            if response.status_code in [200, 204]:
                logger.info(f"Emby用户密码重置成功(方法1): {user_id}")
                return True
            else:
                logger.warning(f"方法1失败: HTTP {response.status_code}")
                
                # 方法2: 使用 /Password 端点（Emby官方API格式）
                try:
                    logger.info(f"方法2: 尝试使用/Password端点: {user_id}")
                    
                    # Emby官方密码更新格式
                    # 注意: ResetPassword 必须为 false，true会清除密码
                    password_url = f"{server_url}/emby/Users/{user_id}/Password"
                    password_data = {
                        'CurrentPw': '',
                        'NewPw': new_password,
                        'ResetPassword': False
                    }
                    
                    logger.info(f"请求URL: {password_url}")
                    logger.info(f"请求数据: {password_data}")
                    
                    password_response = requests.post(password_url, headers=headers, json=password_data, timeout=10)
                    
                    logger.info(f"方法2响应: HTTP {password_response.status_code}")
                    if password_response.text:
                        logger.info(f"方法2响应内容: {password_response.text[:200]}")
                    
                    if password_response.status_code in [200, 204]:
                        logger.info(f"Emby用户密码更新成功(方法2): {user_id}")
                        return True
                    else:
                        logger.warning(f"方法2失败: HTTP {password_response.status_code}")
                except Exception as e2:
                    logger.error(f"方法2异常: {e2}")
                
                # 方法3: 通过更新用户对象的 Password 字段
                try:
                    logger.info(f"方法3: 尝试通过更新用户对象设置密码: {user_id}")
                    
                    # 先获取当前用户信息
                    user_url = f"{server_url}/emby/Users/{user_id}"
                    user_response = requests.get(user_url, headers=headers, timeout=10)
                    
                    if user_response.status_code != 200:
                        logger.error(f"无法获取Emby用户信息: {user_id}, HTTP {user_response.status_code}")
                        return False
                    
                    user_data = user_response.json()
                    logger.info(f"获取到Emby用户信息: {user_data.get('Name')}")
                    
                    # 设置密码字段
                    user_data['Password'] = new_password
                    
                    # 更新用户信息
                    update_response = requests.post(user_url, headers=headers, json=user_data, timeout=10)
                    
                    logger.info(f"方法3响应: HTTP {update_response.status_code}")
                    if update_response.text:
                        logger.info(f"方法3响应内容: {update_response.text[:200]}")
                    
                    if update_response.status_code in [200, 204]:
                        logger.info(f"Emby用户密码更新成功(方法3): {user_id}")
                        return True
                    else:
                        logger.error(f"方法3失败: HTTP {update_response.status_code}")
                except Exception as e3:
                    logger.error(f"方法3异常: {e3}")
                
                return False
        except Exception as e:
            logger.error(f"更新Emby用户密码失败: {e}")
            return False
    
    @staticmethod
    def apply_default_policy(emby_user_id, is_disabled=False):
        """应用默认用户策略到新创建的Emby用户

        Args:
            emby_user_id: Emby用户ID
            is_disabled: 是否禁用该用户（用于邮箱注册未激活的用户）
        """
        global emby_policy_last_system_update
        if not EmbyAPI.is_configured():
            logger.warning("Emby未配置，无法应用策略")
            return False
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Emby-Token': api_key
            }
            
            # 首先获取Emby用户当前信息，检查是否为管理员（安全验证）
            try:
                user_info_url = f"{server_url}/emby/Users/{emby_user_id}"
                user_response = requests.get(user_info_url, headers=headers, timeout=10)
                if user_response.status_code == 200:
                    user_data = user_response.json()
                    current_policy = user_data.get('Policy', {})
                    # 安全检查：如果用户当前是Emby管理员，记录警告日志
                    if current_policy.get('IsAdministrator', False):
                        logger.warning(f"安全警告：Emby用户 {user_data.get('Name')} (ID: {emby_user_id}) 当前是管理员，应用默认策略将移除其管理员权限")
            except Exception as e:
                logger.warning(f"获取Emby用户信息失败（不影响策略应用）: {e}")
            
            # 从数据库获取默认策略
            db = get_db()
            try:
                policy_record = db.query(EmbyUserPolicy).filter_by(is_default=True).first()
                if policy_record:
                    enable_download = policy_record.enable_download
                    enable_transcoding = policy_record.enable_transcoding
                    max_active_devices = policy_record.max_active_devices
                    allowed_library_ids = json.loads(policy_record.allowed_library_ids) if policy_record.allowed_library_ids else []
                    logger.info(f"从数据库获取默认策略: 下载={enable_download}, 转码={enable_transcoding}, 最大设备={max_active_devices}, 媒体库={allowed_library_ids}")
                else:
                    # 使用硬编码默认值
                    enable_download = True
                    enable_transcoding = True
                    max_active_devices = 3
                    allowed_library_ids = []
                    logger.info("数据库中没有默认策略，使用硬编码默认值")
            finally:
                db.close()
            
            # 处理媒体库访问规则
            # - 空数组：允许访问所有媒体库（保持向后兼容）
            # - ['__NONE__']：不允许访问任何媒体库
            # - 其他非空数组：只允许访问指定的媒体库
            is_no_library_access = allowed_library_ids == ['__NONE__']
            enable_all_folders = len(allowed_library_ids) == 0 or is_no_library_access
            enabled_folders = [] if is_no_library_access else allowed_library_ids
            
            # 构建Emby Policy对象
            # 参考Emby API文档: https://api.emby.media/#operation/UserPolicyController_UpdateUserPolicy
            # 安全注意：IsAdministrator 强制为 False，防止任何用户获得管理员权限
            policy = {
                'IsAdministrator': False,  # 强制非管理员，防止提权
                'IsHidden': False,
                'IsHiddenRemotely': True,
                'IsDisabled': is_disabled,  # 根据传入参数设置禁用状态
                'EnableAllFolders': enable_all_folders,
                'EnabledFolders': enabled_folders,
                'EnableAllChannels': True,
                'EnableLiveTvManagement': True,
                'EnableLiveTvAccess': True,
                'EnableMediaPlayback': True,
                'EnableAudioPlaybackTranscoding': enable_transcoding,
                'EnableVideoPlaybackTranscoding': enable_transcoding,
                'EnablePlaybackRemuxing': enable_transcoding,
                'EnableContentDeletion': enable_download,
                'EnableContentDownloading': enable_download,
                'EnableSyncTranscoding': enable_transcoding,
                'EnablePublicSharing': False,
                'EnableRemoteControlOfOtherUsers': False,
                'EnableSharedDeviceControl': False,
                'EnableRemoteAccess': True,
                'MaxActiveSessions': max_active_devices,
                'IsAdministrator': False,  # 重复设置以确保安全
                'EnableAllFolders': enable_all_folders,
                'EnabledFolders': enabled_folders,
                'EnableContentDeletionFromFolders': enabled_folders if enable_download else [],
                'EnableContentDownloading': enable_download,
                'EnableSubtitleManagement': False,
                'EnableLyricManagement': False,
                'EnableMediaPlaybackFromInternet': True,
                'EnablePublicSharing': False,
                'BlockedTags': [],
                'IsHidden': False,
                'EnableUserPreferenceAccess': True,
                'AccessSchedules': [],
                'BlockUnratedItems': [],
                'EnableRemoteControlOfOtherUsers': False,
                'EnableSharedDeviceControl': False,
                'EnableRemoteAccess': True,
                'MaxActiveSessions': max_active_devices
            }
            
            # 使用 /Users/{Id}/Policy 端点设置策略
            policy_url = f"{server_url}/emby/Users/{emby_user_id}/Policy"
            
            logger.info(f"正在设置Emby用户策略: {emby_user_id}")
            logger.info(f"策略内容: {json.dumps({'enable_download': enable_download, 'enable_transcoding': enable_transcoding, 'max_active_devices': max_active_devices, 'allowed_library_ids': allowed_library_ids})}")
            
            response = requests.post(policy_url, headers=headers, json=policy, timeout=15)
            
            logger.info(f"设置策略响应: HTTP {response.status_code}")
            if response.text:
                logger.info(f"设置策略响应内容: {response.text[:200]}")
            
            if response.status_code in [200, 204]:
                logger.info(f"Emby用户策略应用成功: {emby_user_id}")

                # 验证策略是否已正确设置
                try:
                    verify_url = f"{server_url}/emby/Users/{emby_user_id}"
                    verify_response = requests.get(verify_url, headers=headers, timeout=10)
                    if verify_response.status_code == 200:
                        verify_data = verify_response.json()
                        verify_policy = verify_data.get('Policy', {})
                        logger.info(f"验证结果 - EnableContentDownloading: {verify_policy.get('EnableContentDownloading')}, EnableVideoPlaybackTranscoding: {verify_policy.get('EnableVideoPlaybackTranscoding')}, MaxActiveSessions: {verify_policy.get('MaxActiveSessions')}")
                except Exception as e:
                    logger.warning(f"验证策略时出错: {e}")

                # 更新系统策略修改时间戳（用于策略巡查区分系统变更和异常变更）
                emby_policy_last_system_update[emby_user_id] = datetime.now()
                logger.debug(f"已更新系统策略修改时间戳: {emby_user_id}")

                return True
            else:
                logger.error(f"Emby用户策略应用失败: HTTP {response.status_code}, 响应: {response.text}")
                return False
        except Exception as e:
            logger.error(f"应用Emby用户策略失败: {e}")
            return False

    @staticmethod
    def disable_user(user_id):
        """禁用Emby用户 - 使用完整Policy对象"""
        global emby_policy_last_system_update
        if not EmbyAPI.is_configured():
            logger.warning("Emby未配置，无法禁用用户")
            return False
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()

            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            # 获取用户当前信息
            user_url = f"{server_url}/emby/Users/{user_id}?api_key={api_key}"
            logger.info(f"获取用户信息: {user_url.replace(api_key, '***')}")

            response = requests.get(user_url, headers=headers, timeout=10)
            if response.status_code != 200:
                logger.error(f"获取用户信息失败: HTTP {response.status_code}")
                return False

            user_data = response.json()
            logger.info(f"获取到用户: {user_data.get('Name')}")

            # 获取当前Policy或创建默认Policy
            current_policy = user_data.get('Policy', {})

            # 构建完整的Policy对象 - Emby 4.9需要完整的Policy
            policy = {
                'IsAdministrator': current_policy.get('IsAdministrator', False),
                'IsHidden': current_policy.get('IsHidden', False),
                'IsHiddenRemotely': current_policy.get('IsHiddenRemotely', False),
                'IsHiddenFromUnusedDevices': current_policy.get('IsHiddenFromUnusedDevices', False),
                'IsDisabled': True,  # 设置为禁用
                'LockedOutDate': current_policy.get('LockedOutDate', 0),
                'AllowTagOrRating': current_policy.get('AllowTagOrRating', False),
                'BlockedTags': current_policy.get('BlockedTags', []),
                'IsTagBlockingModeInclusive': current_policy.get('IsTagBlockingModeInclusive', False),
                'IncludeTags': current_policy.get('IncludeTags', []),
                'EnableUserPreferenceAccess': current_policy.get('EnableUserPreferenceAccess', True),
                'AccessSchedules': current_policy.get('AccessSchedules', []),
                'BlockUnratedItems': current_policy.get('BlockUnratedItems', []),
                'EnableRemoteControlOfOtherUsers': current_policy.get('EnableRemoteControlOfOtherUsers', False),
                'EnableSharedDeviceControl': current_policy.get('EnableSharedDeviceControl', True),
                'EnableRemoteAccess': current_policy.get('EnableRemoteAccess', True),
                'EnableLiveTvManagement': current_policy.get('EnableLiveTvManagement', True),
                'EnableLiveTvAccess': current_policy.get('EnableLiveTvAccess', True),
                'EnableMediaPlayback': current_policy.get('EnableMediaPlayback', True),
                'EnableAudioPlaybackTranscoding': current_policy.get('EnableAudioPlaybackTranscoding', True),
                'EnableVideoPlaybackTranscoding': current_policy.get('EnableVideoPlaybackTranscoding', True),
                'EnablePlaybackRemuxing': current_policy.get('EnablePlaybackRemuxing', True),
                'EnableContentDeletion': current_policy.get('EnableContentDeletion', False),
                'RestrictedFeatures': current_policy.get('RestrictedFeatures', []),
                'EnableContentDeletionFromFolders': current_policy.get('EnableContentDeletionFromFolders', []),
                'EnableContentDownloading': current_policy.get('EnableContentDownloading', True),
                'EnableSubtitleDownloading': current_policy.get('EnableSubtitleDownloading', True),
                'EnableSubtitleManagement': current_policy.get('EnableSubtitleManagement', False),
                'EnableSyncTranscoding': current_policy.get('EnableSyncTranscoding', True),
                'EnableMediaConversion': current_policy.get('EnableMediaConversion', True),
                'EnabledChannels': current_policy.get('EnabledChannels', []),
                'EnableAllChannels': current_policy.get('EnableAllChannels', True),
                'EnabledFolders': current_policy.get('EnabledFolders', []),
                'EnableAllFolders': current_policy.get('EnableAllFolders', True),
                'InvalidLoginAttemptCount': current_policy.get('InvalidLoginAttemptCount', 0),
                'EnablePublicSharing': current_policy.get('EnablePublicSharing', True),
                'RemoteClientBitrateLimit': current_policy.get('RemoteClientBitrateLimit', 0),
                'ExcludedSubFolders': current_policy.get('ExcludedSubFolders', []),
                'SimultaneousStreamLimit': current_policy.get('SimultaneousStreamLimit', 0),
                'EnabledDevices': current_policy.get('EnabledDevices', []),
                'EnableAllDevices': current_policy.get('EnableAllDevices', True),
                'AllowCameraUpload': current_policy.get('AllowCameraUpload', True),
                'AllowSharingPersonalItems': current_policy.get('AllowSharingPersonalItems', False),
                'AuthenticationProviderId': current_policy.get('AuthenticationProviderId', 'Emby.Server.Implementations.Library.DefaultAuthenticationProvider')
            }

            # 方法1: 使用 /Users/{Id}/Policy 端点
            policy_url = f"{server_url}/emby/Users/{user_id}/Policy?api_key={api_key}"
            logger.info(f"尝试Policy端点: {policy_url.replace(api_key, '***')}")

            response = requests.post(policy_url, headers=headers, json=policy, timeout=10)
            logger.info(f"Policy POST响应: HTTP {response.status_code}")

            if response.status_code in [200, 204]:
                # 验证
                verify = requests.get(user_url, headers=headers, timeout=10)
                if verify.status_code == 200:
                    vdata = verify.json()
                    is_disabled = vdata.get('Policy', {}).get('IsDisabled', False)
                    logger.info(f"验证结果 - IsDisabled: {is_disabled}")
                    if is_disabled:
                        logger.info(f"Policy端点禁用成功: {user_id}")
                        # 更新系统策略修改时间戳
                        emby_policy_last_system_update[user_id] = datetime.now()
                        logger.debug(f"已更新系统策略修改时间戳(禁用): {user_id}")
                        return True
                    else:
                        logger.warning(f"Policy端点返回成功但验证失败")
            else:
                logger.error(f"Policy端点失败: {response.text}")

            # 方法2: 更新整个用户对象
            logger.info(f"尝试更新整个用户对象")
            user_data['Policy'] = policy
            user_data['IsDisabled'] = True

            response = requests.post(user_url, headers=headers, json=user_data, timeout=10)
            logger.info(f"更新用户响应: HTTP {response.status_code}")

            if response.status_code in [200, 204]:
                # 验证
                verify = requests.get(user_url, headers=headers, timeout=10)
                if verify.status_code == 200:
                    vdata = verify.json()
                    is_disabled = vdata.get('Policy', {}).get('IsDisabled', False)
                    logger.info(f"验证结果 - IsDisabled: {is_disabled}")
                    if is_disabled:
                        logger.info(f"更新用户禁用成功: {user_id}")
                        # 更新系统策略修改时间戳
                        emby_policy_last_system_update[user_id] = datetime.now()
                        logger.debug(f"已更新系统策略修改时间戳(禁用): {user_id}")
                        return True
            else:
                logger.error(f"更新用户失败: {response.text}")

            logger.error(f"所有方法都失败: {user_id}")
            return False

        except Exception as e:
            logger.error(f"禁用Emby用户失败: {e}")
            return False
    
    @staticmethod
    def enable_user(user_id):
        """启用Emby用户 - 使用系统默认策略"""
        if not EmbyAPI.is_configured():
            logger.warning("Emby未配置，无法启用用户")
            return False
        try:
            # 使用 apply_default_policy 应用完整的默认策略（包括媒体库访问权限）
            # 这样可以确保用户启用时，媒体库访问权限与系统设置一致
            result = EmbyAPI.apply_default_policy(user_id, is_disabled=False)
            if result:
                logger.info(f"Emby用户已启用并应用默认策略: {user_id}")
                # 注意：apply_default_policy 内部已更新 emby_policy_last_system_update
            else:
                logger.error(f"启用Emby用户失败: {user_id}")
            return result

        except Exception as e:
            logger.error(f"启用Emby用户失败: {e}")
            return False
    
    @staticmethod
    def delete_user(user_id):
        """删除Emby用户"""
        if not EmbyAPI.is_configured():
            return False
        try:
            url = f"{EmbyAPI.get_server_url()}/emby/Users/{user_id}"
            response = requests.delete(url, headers=EmbyAPI.get_headers(), timeout=10)

            if response.status_code in [200, 204]:
                logger.info(f"Emby用户删除成功: {user_id}")
                return True
            else:
                logger.error(f"删除Emby用户失败: HTTP {response.status_code}, 响应: {response.text}")
                return False
        except Exception as e:
            logger.error(f"删除Emby用户失败: {e}")
            return False

    @staticmethod
    def is_admin(user_id):
        """检查Emby用户是否为管理员

        Args:
            user_id: Emby用户ID

        Returns:
            bool: True如果是管理员，False如果不是或查询失败
        """
        if not EmbyAPI.is_configured():
            return False
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            headers = {'Accept': 'application/json'}

            user_url = f"{server_url}/emby/Users/{user_id}?api_key={api_key}"
            response = requests.get(user_url, headers=headers, timeout=10)

            if response.status_code == 200:
                user_data = response.json()
                policy = user_data.get('Policy', {})
                is_admin = policy.get('IsAdministrator', False)
                logger.info(f"检查用户管理员状态: {user_data.get('Name')}, IsAdministrator: {is_admin}")
                return is_admin
            else:
                logger.warning(f"获取用户信息失败，无法检查管理员状态: HTTP {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"检查用户管理员状态失败: {e}")
            return False

    @staticmethod
    def demote_admin(user_id):
        """将Emby管理员降级为非管理员

        Args:
            user_id: Emby用户ID

        Returns:
            bool: True成功，False失败
        """
        global emby_policy_last_system_update
        if not EmbyAPI.is_configured():
            logger.warning("Emby未配置，无法降级用户")
            return False
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            # 获取用户当前信息
            user_url = f"{server_url}/emby/Users/{user_id}?api_key={api_key}"
            response = requests.get(user_url, headers=headers, timeout=10)

            if response.status_code != 200:
                logger.error(f"获取用户信息失败: HTTP {response.status_code}")
                return False

            user_data = response.json()
            logger.info(f"正在降级用户: {user_data.get('Name')}")

            # 获取当前Policy并修改IsAdministrator为False
            current_policy = user_data.get('Policy', {})
            current_policy['IsAdministrator'] = False

            # 使用Policy端点更新
            policy_url = f"{server_url}/emby/Users/{user_id}/Policy?api_key={api_key}"
            policy_response = requests.post(policy_url, headers=headers, json=current_policy, timeout=10)

            if policy_response.status_code in [200, 204]:
                logger.info(f"用户降级成功: {user_data.get('Name')}")
                # 更新系统策略修改时间戳
                emby_policy_last_system_update[user_id] = datetime.now()
                return True
            else:
                logger.error(f"用户降级失败: HTTP {policy_response.status_code}, 响应: {policy_response.text}")
                return False

        except Exception as e:
            logger.error(f"降级用户失败: {e}")
            return False

    @staticmethod
    def get_libraries():
        """获取Emby媒体库列表"""
        if not EmbyAPI.is_configured():
            return None
        try:
            url = f"{EmbyAPI.get_server_url()}/emby/Library/VirtualFolders"
            response = requests.get(url, headers=EmbyAPI.get_headers(), timeout=10)
            if response.status_code == 200:
                libraries = response.json()
                # 返回简化格式
                return [{'id': lib.get('ItemId', ''), 'name': lib.get('Name', '')} for lib in libraries]
            return None
        except Exception as e:
            logger.error(f"获取Emby媒体库失败: {e}")
            return None

    @staticmethod
    def get_item_info(item_id):
        """获取Emby项目详细信息
        
        Args:
            item_id: Emby项目ID
            
        Returns:
            dict: 项目信息字典，或None如果失败
        """
        if not EmbyAPI.is_configured() or not item_id:
            return None
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            url = f"{server_url}/emby/Items/{item_id}"
            params = {
                'api_key': api_key,
                'Fields': 'SeriesName,SeasonName,ParentId,SeriesId,Overview,ImageTags,BackdropImageTags,PrimaryImageTag'
            }
            response = requests.get(url, params=params, headers={'Accept': 'application/json'}, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"获取Emby项目信息失败: {e}")
            return None

    @staticmethod
    def get_items_by_ids(emby_user_id, item_ids):
        """批量获取Emby项目详细信息

        Args:
            emby_user_id: Emby用户ID
            item_ids: Emby项目ID列表

        Returns:
            dict: 包含Items字段的字典，或None如果失败
        """
        if not EmbyAPI.is_configured() or not emby_user_id or not item_ids:
            return None
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            url = f"{server_url}/emby/Users/{emby_user_id}/Items"
            params = {
                'api_key': api_key,
                'Ids': ','.join(str(iid) for iid in item_ids),
                'Fields': 'SeriesName,SeasonName,ParentId,SeriesId,Overview,ImageTags,BackdropImageTags,PrimaryImageTag'
            }
            response = requests.get(url, params=params, headers={'Accept': 'application/json'}, timeout=15)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"批量获取Emby项目信息失败: {e}")
            return None

    @staticmethod
    def get_items_by_ids_admin(item_ids):
        """管理员批量获取Emby项目详细信息（不依赖具体用户ID）

        Args:
            item_ids: Emby项目ID列表

        Returns:
            dict: 包含Items字段的字典，或None如果失败
        """
        if not EmbyAPI.is_configured() or not item_ids:
            return None
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            url = f"{server_url}/emby/Items"
            params = {
                'api_key': api_key,
                'Ids': ','.join(str(iid) for iid in item_ids),
                'Fields': 'SeriesName,SeasonName,ParentId,SeriesId,Overview,ImageTags,BackdropImageTags,PrimaryImageTag'
            }
            response = requests.get(url, params=params, headers={'Accept': 'application/json'}, timeout=15)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"管理员批量获取Emby项目信息失败: {e}")
            return None

    @staticmethod
    def get_active_sessions():
        """获取Emby当前活跃的播放会话
        
        Returns:
            list: 活跃会话列表，每个会话包含播放信息
        """
        if not EmbyAPI.is_configured():
            return []
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            url = f"{server_url}/emby/Sessions"
            params = {
                'api_key': api_key
                # 移除 IsPlaying 限制，获取所有会话
            }
            response = requests.get(url, params=params, headers={'Accept': 'application/json'}, timeout=10)
            if response.status_code == 200:
                sessions = response.json()
                # 过滤出有播放活动的会话（包括正在播放和最近播放的）
                active_sessions = []
                for session in sessions:
                    # 获取用户信息
                    user_id = session.get('UserId')
                    now_playing = session.get('NowPlayingItem')
                    last_played_item = session.get('LastPlayedItem')
                    
                    # 如果有正在播放的项目
                    if now_playing:
                        active_sessions.append({
                            'user_id': user_id,
                            'device_name': session.get('DeviceName'),
                            'client': session.get('Client'),
                            'item_id': now_playing.get('Id'),
                            'item_name': now_playing.get('Name'),
                            'item_type': now_playing.get('Type'),
                            'series_name': now_playing.get('SeriesName', ''),
                            'season_name': now_playing.get('SeasonName', ''),
                            'position_ticks': session.get('PlayState', {}).get('PositionTicks', 0),
                            'is_paused': session.get('PlayState', {}).get('IsPaused', False),
                            'is_now_playing': True
                        })
                    # 如果有最近播放的项目（但当前没在播放）
                    elif last_played_item:
                        active_sessions.append({
                            'user_id': user_id,
                            'device_name': session.get('DeviceName'),
                            'client': session.get('Client'),
                            'item_id': last_played_item.get('Id'),
                            'item_name': last_played_item.get('Name'),
                            'item_type': last_played_item.get('Type'),
                            'series_name': last_played_item.get('SeriesName', ''),
                            'season_name': last_played_item.get('SeasonName', ''),
                            'position_ticks': 0,
                            'is_paused': False,
                            'is_now_playing': False
                        })
                return active_sessions
            return []
        except Exception as e:
            logger.error(f"获取Emby活跃会话失败: {e}")
            return []

    @staticmethod
    def get_user_watch_history(emby_user_id):
        """获取Emby用户的观看历史
        
        使用多种方法获取播放记录：
        1. 标准 Items API 获取已播放项目（主要方法）
        2. Playback Reporting 插件 API（如果可用）
        3. 遍历媒体库获取已播放项目
        4. 获取最近访问的项目
        
        Args:
            emby_user_id: Emby用户ID
            
        Returns:
            dict: 包含观看历史Items的字典，或None如果失败
        """
        if not EmbyAPI.is_configured():
            return None
        try:
            server_url = EmbyAPI.get_server_url().rstrip('/')
            api_key = EmbyAPI.get_api_key()
            headers = {'Accept': 'application/json'}
            
            all_played_items = []
            seen_ids = set()
            
            # 方法1: 使用标准 Items API 获取项目并筛选已播放的（主要方法）
            try:
                logger.info(f"尝试使用 Items API 获取项目并筛选已播放的: {emby_user_id}")
                items_url = f"{server_url}/emby/Users/{emby_user_id}/Items"
                items_params = {
                    'api_key': api_key,
                    'Recursive': 'true',
                    'Limit': '500',  # 增加限制以获取更多项目
                    'Fields': 'DatePlayed,DateCreated,RunTimeTicks,PlaybackPositionTicks,Type,SeriesName,SeasonName,UserData,UserDataLastPlayedDate,UserDataPlayCount,Name,Overview,DateLastPlayed,ParentId,SeriesId,SeasonId',
                    'IncludeItemTypes': 'Movie,Episode',
                    'SortBy': 'DatePlayed,DateCreated',  # 优先按播放时间排序
                    'SortOrder': 'Descending',
                    'EnableUserData': 'true'
                }
                
                items_response = requests.get(items_url, params=items_params, headers=headers, timeout=15)
                logger.info(f"Items API 状态码: {items_response.status_code}")
                
                if items_response.status_code == 200:
                    items_data = items_response.json()
                    all_items = items_data.get('Items', [])
                    logger.info(f"Items API 获取到 {len(all_items)} 个项目")
                    
                    played_count = 0
                    for item in all_items:
                        item_id = item.get('Id')
                        if not item_id or item_id in seen_ids:
                            continue
                        
                        # 获取项目类型
                        item_type = item.get('Type', '')
                        
                        # 检查 UserData 中的各种播放相关字段
                        user_data = item.get('UserData', {})
                        is_played = user_data.get('Played', False)
                        last_played_date = user_data.get('LastPlayedDate') or item.get('DateLastPlayed')
                        play_count = user_data.get('PlayCount', 0)
                        playback_position = user_data.get('PlaybackPositionTicks', 0)
                        
                        # 如果满足以下任一条件，则认为是已播放项目：
                        # 1. 标记为已播放 (Played=True)
                        # 2. 有最后播放日期 (LastPlayedDate)
                        # 3. 播放次数大于0 (PlayCount > 0)
                        # 4. 有播放位置 (PlaybackPositionTicks > 0)
                        if is_played or last_played_date or play_count > 0 or playback_position > 0:
                            # 如果是剧集但没有系列名称，尝试获取
                            if item_type == 'Episode' and not item.get('SeriesName'):
                                series_id = item.get('SeriesId')
                                if series_id:
                                    try:
                                        series_info = EmbyAPI.get_item_info(series_id)
                                        if series_info:
                                            item['SeriesName'] = series_info.get('Name', '')
                                            logger.info(f"从SeriesId获取系列名称: {item['SeriesName']}")
                                    except Exception as e:
                                        logger.warning(f"获取系列信息失败: {e}")
                            
                            all_played_items.append(item)
                            seen_ids.add(item_id)
                            played_count += 1
                        
                        # 如果是 Series 类型，尝试获取其子项目（Seasons/Episodes）
                        elif item_type == 'Series':
                            try:
                                logger.info(f"发现Series类型项目: {item.get('Name')}, 尝试获取其子项目")
                                # 获取该系列的所有子项目（递归获取剧集）
                                series_items_url = f"{server_url}/emby/Users/{emby_user_id}/Items"
                                series_items_params = {
                                    'api_key': api_key,
                                    'ParentId': item_id,
                                    'Recursive': 'true',
                                    'Limit': '200',
                                    'Fields': 'DatePlayed,DateCreated,RunTimeTicks,PlaybackPositionTicks,Type,SeriesName,SeasonName,UserData,UserDataLastPlayedDate,UserDataPlayCount,Name,DateLastPlayed,ParentId,SeriesId,SeasonId',
                                    'IncludeItemTypes': 'Episode',
                                    'EnableUserData': 'true'
                                }
                                
                                series_items_response = requests.get(series_items_url, params=series_items_params, headers=headers, timeout=15)
                                if series_items_response.status_code == 200:
                                    series_items_data = series_items_response.json()
                                    series_items = series_items_data.get('Items', [])
                                    logger.info(f"从Series '{item.get('Name')}' 获取到 {len(series_items)} 个子项目")
                                    
                                    for episode in series_items:
                                        episode_id = episode.get('Id')
                                        if not episode_id or episode_id in seen_ids:
                                            continue
                                        
                                        episode_user_data = episode.get('UserData', {})
                                        episode_is_played = episode_user_data.get('Played', False)
                                        episode_last_played = episode_user_data.get('LastPlayedDate') or episode.get('DateLastPlayed')
                                        episode_play_count = episode_user_data.get('PlayCount', 0)
                                        episode_position = episode_user_data.get('PlaybackPositionTicks', 0)
                                        
                                        if episode_is_played or episode_last_played or episode_play_count > 0 or episode_position > 0:
                                            # 确保系列名称正确
                                            if not episode.get('SeriesName'):
                                                episode['SeriesName'] = item.get('Name', '')
                                            
                                            all_played_items.append(episode)
                                            seen_ids.add(episode_id)
                                            played_count += 1
                                            logger.info(f"从Series添加已播放剧集: {episode.get('Name')}")
                            except Exception as e:
                                logger.warning(f"获取Series子项目失败: {e}")
                    
                    logger.info(f"从 Items API 筛选出 {played_count} 个已播放项目")
                elif items_response.status_code == 500:
                    logger.warning(f"Items API 返回 HTTP 500")
            except Exception as e:
                logger.warning(f"Items API 获取失败: {e}")
            
            # 方法2: 使用 Items API 配合 IsPlayed 过滤器（某些Emby版本支持）
            if len(all_played_items) < 5:
                try:
                    logger.info(f"尝试使用 Items API + IsPlayed 过滤器: {emby_user_id}")
                    items_url = f"{server_url}/emby/Users/{emby_user_id}/Items"
                    items_params = {
                        'api_key': api_key,
                        'Recursive': 'true',
                        'Limit': '500',
                        'Filters': 'IsPlayed',  # 尝试使用过滤器
                        'Fields': 'DatePlayed,DateCreated,RunTimeTicks,PlaybackPositionTicks,Type,SeriesName,SeasonName,UserData,UserDataLastPlayedDate,UserDataPlayCount,Name,DateLastPlayed,ParentId,SeriesId,SeasonId',
                        'IncludeItemTypes': 'Movie,Episode',
                        'SortBy': 'DatePlayed',
                        'SortOrder': 'Descending',
                        'EnableUserData': 'true'
                    }
                    
                    items_response = requests.get(items_url, params=items_params, headers=headers, timeout=15)
                    logger.info(f"Items API (IsPlayed) 状态码: {items_response.status_code}")
                    
                    if items_response.status_code == 200:
                        items_data = items_response.json()
                        all_items = items_data.get('Items', [])
                        logger.info(f"Items API (IsPlayed) 获取到 {len(all_items)} 个项目")
                        
                        for item in all_items:
                            item_id = item.get('Id')
                            if not item_id or item_id in seen_ids:
                                continue
                            
                            # 如果是剧集但没有系列名称，尝试获取
                            item_type = item.get('Type', '')
                            if item_type == 'Episode' and not item.get('SeriesName'):
                                series_id = item.get('SeriesId')
                                if series_id:
                                    try:
                                        series_info = EmbyAPI.get_item_info(series_id)
                                        if series_info:
                                            item['SeriesName'] = series_info.get('Name', '')
                                    except Exception as e:
                                        logger.warning(f"获取系列信息失败: {e}")
                            
                            all_played_items.append(item)
                            seen_ids.add(item_id)
                except Exception as e:
                    logger.warning(f"Items API (IsPlayed) 获取失败: {e}")
            
            # 方法3: 遍历媒体库获取已播放项目
            if len(all_played_items) < 10:
                try:
                    logger.info(f"尝试遍历媒体库获取播放记录: {emby_user_id}")
                    libraries_url = f"{server_url}/emby/Users/{emby_user_id}/Views"
                    lib_response = requests.get(libraries_url, params={'api_key': api_key}, headers=headers, timeout=10)
                    if lib_response.status_code == 200:
                        libraries = lib_response.json().get('Items', [])
                        logger.info(f"用户有 {len(libraries)} 个媒体库")
                        
                        for lib in libraries:
                            try:
                                lib_id = lib.get('Id')
                                lib_name = lib.get('Name', 'Unknown')
                                if not lib_id:
                                    continue
                                
                                lib_items_url = f"{server_url}/emby/Users/{emby_user_id}/Items"
                                lib_items_params = {
                                    'api_key': api_key,
                                    'ParentId': lib_id,
                                    'Recursive': 'true',
                                    'Limit': '200',
                                    'Fields': 'DatePlayed,DateCreated,RunTimeTicks,PlaybackPositionTicks,Type,SeriesName,SeasonName,UserData,UserDataLastPlayedDate,UserDataPlayCount,Name,DateLastPlayed,ParentId,SeriesId,SeasonId',
                                    'IncludeItemTypes': 'Movie,Episode',
                                    'SortBy': 'DatePlayed',
                                    'SortOrder': 'Descending',
                                    'EnableUserData': 'true'
                                }
                                
                                lib_items_response = requests.get(lib_items_url, params=lib_items_params, headers=headers, timeout=15)
                                if lib_items_response.status_code == 200:
                                    lib_items_data = lib_items_response.json()
                                    lib_items = lib_items_data.get('Items', [])
                                    
                                    played_count = 0
                                    for item in lib_items:
                                        item_id = item.get('Id')
                                        if not item_id or item_id in seen_ids:
                                            continue
                                        
                                        user_data = item.get('UserData', {})
                                        is_played = user_data.get('Played', False)
                                        last_played_date = user_data.get('LastPlayedDate')
                                        play_count = user_data.get('PlayCount', 0)
                                        playback_position = user_data.get('PlaybackPositionTicks', 0)
                                        
                                        if is_played or last_played_date or play_count > 0 or playback_position > 0:
                                            item_type = item.get('Type', '')
                                            if item_type == 'Episode' and not item.get('SeriesName'):
                                                series_id = item.get('SeriesId')
                                                if series_id:
                                                    try:
                                                        series_info = EmbyAPI.get_item_info(series_id)
                                                        if series_info:
                                                            item['SeriesName'] = series_info.get('Name', '')
                                                    except Exception as e:
                                                        logger.warning(f"获取系列信息失败: {e}")
                                            
                                            all_played_items.append(item)
                                            seen_ids.add(item_id)
                                            played_count += 1
                                    
                                    logger.info(f"从库 '{lib_name}' 筛选出 {played_count} 个已播放项目")
                                elif lib_items_response.status_code == 500:
                                    logger.warning(f"库 '{lib_name}' 返回 HTTP 500")
                            except Exception as e:
                                logger.warning(f"获取库 '{lib.get('Name', 'Unknown')}' 的播放记录失败: {e}")
                                continue
                except Exception as e:
                    logger.warning(f"遍历媒体库获取播放记录失败: {e}")
            
            # 方法4: 使用 /Users/{UserId}/Items/Latest 获取最近访问的项目
            if len(all_played_items) < 20:
                try:
                    logger.info(f"尝试使用 Latest Items API 获取最近项目: {emby_user_id}")
                    latest_url = f"{server_url}/emby/Users/{emby_user_id}/Items/Latest"
                    latest_params = {
                        'api_key': api_key,
                        'Limit': '100',
                        'Fields': 'DatePlayed,DateCreated,RunTimeTicks,PlaybackPositionTicks,Type,SeriesName,SeasonName,UserData,UserDataLastPlayedDate,UserDataPlayCount,Name,DateLastPlayed,ParentId,SeriesId,SeasonId',
                        'IncludeItemTypes': 'Movie,Episode',
                        'EnableUserData': 'true'
                    }
                    
                    latest_response = requests.get(latest_url, params=latest_params, headers=headers, timeout=15)
                    logger.info(f"Latest Items API 状态码: {latest_response.status_code}")
                    
                    if latest_response.status_code == 200:
                        latest_data = latest_response.json()
                        latest_items = latest_data if isinstance(latest_data, list) else latest_data.get('Items', [])
                        logger.info(f"Latest Items API 获取到 {len(latest_items)} 个最近项目")
                        
                        added_count = 0
                        for item in latest_items:
                            item_id = item.get('Id')
                            if not item_id or item_id in seen_ids:
                                continue
                            
                            user_data = item.get('UserData', {})
                            last_played_date = user_data.get('LastPlayedDate')
                            play_count = user_data.get('PlayCount', 0)
                            position_ticks = user_data.get('PlaybackPositionTicks', 0)
                            
                            if last_played_date or play_count > 0 or position_ticks > 0:
                                item_type = item.get('Type', '')
                                if item_type == 'Episode' and not item.get('SeriesName'):
                                    series_id = item.get('SeriesId')
                                    if series_id:
                                        try:
                                            series_info = EmbyAPI.get_item_info(series_id)
                                            if series_info:
                                                item['SeriesName'] = series_info.get('Name', '')
                                        except Exception as e:
                                            logger.warning(f"获取系列信息失败: {e}")
                                
                                all_played_items.append(item)
                                seen_ids.add(item_id)
                                added_count += 1
                        
                        logger.info(f"从 Latest Items API 添加 {added_count} 个最近观看项目")
                except Exception as e:
                    logger.warning(f"Latest Items API 获取失败: {e}")
            
            # 方法5: 使用 Playback Reporting 插件的 API（如果可用）
            # 注意：这些端点可能在某些版本中不可用
            try:
                logger.info(f"尝试使用 Playback Reporting API: {emby_user_id}")
                # 尝试获取 Playback Reporting 的播放活动
                pr_url = f"{server_url}/emby/user_usage_stats/PlayActivity"
                pr_params = {
                    'api_key': api_key,
                    'UserId': emby_user_id,
                    'Days': '30',
                    'Limit': '100'
                }
                
                pr_response = requests.get(pr_url, params=pr_params, headers=headers, timeout=10)
                logger.info(f"Playback Reporting PlayActivity 状态码: {pr_response.status_code}")
                
                if pr_response.status_code == 200:
                    pr_data = pr_response.json()
                    records = pr_data if isinstance(pr_data, list) else pr_data.get('Items', [])
                    logger.info(f"Playback Reporting 获取到 {len(records)} 条播放记录")
                    
                    for record in records:
                        item_id = record.get('ItemId') or record.get('Id')
                        if item_id and item_id not in seen_ids:
                            date_played = (record.get('DateCreated') or 
                                         record.get('PlaybackDate') or 
                                         record.get('DatePlayed') or 
                                         record.get('LastPlayedDate', ''))
                            
                            item_type = record.get('Type') or record.get('ItemType', 'Movie')
                            item_name = record.get('Name') or record.get('ItemName', '未知影片')
                            series_name = record.get('SeriesName', '')
                            season_name = record.get('SeasonName', '')
                            
                            if item_type == 'Episode' and not series_name:
                                try:
                                    item_details = EmbyAPI.get_item_info(item_id)
                                    if item_details:
                                        series_name = item_details.get('SeriesName', '')
                                        season_name = item_details.get('SeasonName', season_name)
                                except Exception as e:
                                    logger.warning(f"获取项目详情失败: {e}")
                            
                            item = {
                                'Id': item_id,
                                'Name': item_name,
                                'Type': item_type,
                                'SeriesName': series_name,
                                'SeasonName': season_name,
                                'DateCreated': record.get('DateCreated', ''),
                                'DatePlayed': date_played,
                                'DateLastPlayed': date_played,
                                'RunTimeTicks': (record.get('PlaybackDuration', 0) or record.get('Duration', 0)) * 10000000,
                                'PlaybackPositionTicks': record.get('PlaybackPositionTicks', 0),
                                'UserData': {
                                    'LastPlayedDate': date_played,
                                    'PlaybackPositionTicks': record.get('PlaybackPositionTicks', 0),
                                    'Played': True
                                }
                            }
                            all_played_items.append(item)
                            seen_ids.add(item_id)
            except Exception as e:
                logger.info(f"Playback Reporting API 不可用: {e}")
            
            # 按播放时间排序（最新的在前面）
            def get_play_date(item):
                user_data = item.get('UserData', {})
                # 优先使用 LastPlayedDate，然后是 DatePlayed，最后是 DateCreated
                date_str = (user_data.get('LastPlayedDate') or 
                           item.get('DateLastPlayed') or 
                           item.get('DatePlayed') or 
                           item.get('DateCreated', ''))
                return date_str
            
            # 排序前记录日志
            logger.info(f"排序前共有 {len(all_played_items)} 条记录")
            all_played_items.sort(key=lambda x: get_play_date(x), reverse=True)
            logger.info(f"排序后返回 {len(all_played_items)} 条记录")
            
            return {'Items': all_played_items[:50]}  # 最多返回50条
            
        except Exception as e:
            logger.error(f"获取Emby用户观看历史失败: {e}")
            return None
    
    @staticmethod
    def sync_user_watch_history(user_id, emby_user_id):
        """同步Emby用户的观看历史到本地数据库
        
        Args:
            user_id: 本地用户ID
            emby_user_id: Emby用户ID
            
        Returns:
            bool: 同步是否成功
        """
        if not EmbyAPI.is_configured():
            return False
        
        try:
            # 获取Emby观看历史
            emby_data = EmbyAPI.get_user_watch_history(emby_user_id)
            if not emby_data or 'Items' not in emby_data:
                logger.warning(f"获取Emby观看历史失败或没有数据: emby_user_id={emby_user_id}")
                return False
            
            db = get_db()
            try:
                items = emby_data.get('Items', [])
                logger.info(f"开始同步 {len(items)} 条观看记录到用户 {user_id}")
                
                # 清理该用户的旧观看记录（只保留最近7天的，或全部清理）
                # 这样可以确保旧的、不完整的记录被替换
                try:
                    # 获取所有旧记录的ID
                    old_records = db.query(WatchHistory).filter_by(user_id=user_id).all()
                    old_count = len(old_records)
                    if old_count > 0:
                        # 删除旧记录
                        for old_record in old_records:
                            db.delete(old_record)
                        logger.info(f"已清理用户 {user_id} 的 {old_count} 条旧观看记录")
                except Exception as e:
                    logger.warning(f"清理旧记录时出错: {e}")
                
                synced_count = 0
                error_count = 0
                
                for item in items:
                    try:
                        emby_item_id = item.get('Id', 'unknown')
                        item_type = item.get('Type', 'Unknown')
                        
                        # 获取完整的影片信息（包含系列名称）
                        # 对于剧集，需要获取父级信息来确保系列名称正确
                        series_name = item.get('SeriesName', '')
                        season_name = item.get('SeasonName', '')
                        episode_name = item.get('Name', '未知影片')
                        
                        # 如果是剧集但没有系列名称，尝试从父级获取
                        if item_type == 'Episode' and not series_name:
                            series_id = item.get('SeriesId')
                            if series_id:
                                try:
                                    series_info = EmbyAPI.get_item_info(series_id)
                                    if series_info:
                                        series_name = series_info.get('Name', '')
                                        logger.info(f"从SeriesId获取到系列名称: {series_name}")
                                except Exception as e:
                                    logger.warning(f"获取系列信息失败: {e}")
                        
                        # 构建完整的影片名称
                        if series_name and item_type == 'Episode':
                            # 剧集格式: "系列名称 - S01E01 - 集名称" 或 "系列名称 - 集名称"
                            if season_name:
                                item_name = f"{series_name} - {season_name} - {episode_name}"
                            else:
                                item_name = f"{series_name} - {episode_name}"
                        else:
                            item_name = episode_name
                        
                        # 确保 item_name 不为空
                        if not item_name:
                            item_name = '未知影片'
                            logger.warning(f"项目名称为空，使用默认值: emby_item_id={emby_item_id}")
                        
                        logger.info(f"处理观看记录: emby_item_id={emby_item_id}, type={item_type}, name={item_name}")
                        
                        # 获取UserData（包含播放信息）
                        user_data = item.get('UserData', {})
                        
                        # 获取播放时间相关字段
                        last_played_date = user_data.get('LastPlayedDate') or item.get('DateLastPlayed')
                        date_played = (last_played_date or 
                                      item.get('DatePlayed') or 
                                      item.get('DateCreated') or 
                                      item.get('PremiereDate'))
                        
                        # 获取播放次数和播放位置
                        play_count = user_data.get('PlayCount', 0)
                        position_ticks = user_data.get('PlaybackPositionTicks', 0) or item.get('PlaybackPositionTicks', 0)
                        
                        logger.info(f"播放时间字段: LastPlayedDate={last_played_date}, DateLastPlayed={item.get('DateLastPlayed')}, DatePlayed={item.get('DatePlayed')}, 最终使用={date_played}")
                        logger.info(f"播放数据: PlayCount={play_count}, PlaybackPositionTicks={position_ticks}")
                        
                        start_time = None
                        if date_played:
                            try:
                                # 处理Emby返回的时间格式: 2026-04-26T05:50:14.0000000Z
                                # Python的fromisoformat只能处理最多6位小数，需要截断
                                import re
                                from datetime import timedelta
                                
                                # 将Z替换为+00:00
                                date_str = date_played.replace('Z', '+00:00')
                                
                                # 处理7位或更多小数位的情况 (如 .0000000)
                                # 匹配小数点后7位或更多数字
                                match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{6})\d+(\+\d{2}:\d{2})$', date_str)
                                if match:
                                    # 截断到6位小数
                                    date_str = f"{match.group(1)}{match.group(2)}{match.group(3)}"
                                
                                # 处理没有时区的情况
                                if '+' not in date_str and '-' not in date_str[10:]:
                                    date_str = date_str + '+00:00'
                                
                                # 解析UTC时间
                                utc_time = datetime.fromisoformat(date_str)
                                # 转换为北京时间 (UTC+8)
                                start_time = utc_time + timedelta(hours=8)
                                # 移除时区信息，只保留本地时间
                                start_time = start_time.replace(tzinfo=None)
                                logger.info(f"解析播放时间成功 (UTC转北京时间): {start_time}")
                            except Exception as e:
                                logger.warning(f"解析播放时间失败 [{item_name}]: {date_played}, 错误: {e}")
                                # 尝试备用解析方法
                                try:
                                    from datetime import timedelta
                                    # 使用strptime解析基本格式
                                    date_str = date_played.replace('Z', '').split('.')[0]
                                    utc_time = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
                                    # 转换为北京时间 (UTC+8)
                                    start_time = utc_time + timedelta(hours=8)
                                    logger.info(f"使用备用方法解析成功 (UTC转北京时间): {start_time}")
                                except Exception as e2:
                                    logger.warning(f"备用解析也失败: {e2}")
                                    start_time = None
                        
                        # 如果无法获取时间，使用当前日期（只精确到日期）
                        if not start_time:
                            logger.warning(f"无法获取播放时间 [{item_name}]，使用当前日期")
                            start_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                        
                        # 获取时长（ticks转换为秒）
                        runtime_ticks = item.get('RunTimeTicks', 0)
                        duration_seconds = runtime_ticks // 10000000 if runtime_ticks else 0
                        
                        # 计算播放位置（秒）
                        position_seconds = position_ticks // 10000000 if position_ticks else 0
                        
                        # 计算结束时间和实际观看时长
                        # Emby API 不提供真正的"观看时长"，只提供播放位置
                        # 我们需要根据 PlayCount 和 PlaybackPositionTicks 来估算
                        
                        if position_seconds == 0 and last_played_date:
                            # 用户有播放记录但没有播放位置，可能是短暂观看或已经看完
                            if play_count > 0:
                                # 如果有播放次数但没有播放位置，说明可能已经看完
                                # 使用视频总时长作为观看时长
                                actual_duration = duration_seconds if duration_seconds > 0 else 1
                                end_time = start_time + timedelta(seconds=actual_duration)
                                logger.info(f"观看完成记录: {item_name}, 使用总时长{actual_duration}秒")
                            else:
                                # 没有播放次数，可能是标记为已播放但未实际观看
                                actual_duration = duration_seconds
                                end_time = start_time + timedelta(seconds=duration_seconds) if duration_seconds > 0 else start_time
                        elif position_seconds > 0 and duration_seconds > 0:
                            # 有播放位置
                            # 如果播放位置接近总时长（90%以上），认为已经看完
                            if position_seconds >= duration_seconds * 0.9:
                                actual_duration = duration_seconds
                                end_time = start_time + timedelta(seconds=duration_seconds)
                                logger.info(f"观看接近完成: {item_name}, 使用总时长{duration_seconds}s")
                            else:
                                # 播放位置小于90%，使用播放位置作为观看时长
                                # 注意：这可能不完全准确，因为用户可能跳转了
                                actual_duration = position_seconds
                                end_time = start_time + timedelta(seconds=position_seconds)
                                logger.info(f"部分观看: {item_name}, 播放到{position_seconds}s/{duration_seconds}s")
                        else:
                            # 其他情况，使用总时长
                            actual_duration = duration_seconds
                            end_time = start_time + timedelta(seconds=duration_seconds) if duration_seconds > 0 else start_time
                        
                        logger.info(f"记录详情: name={item_name}, start_time={start_time}, duration={actual_duration}s")
                        
                        # 检查是否已存在（优先通过emby_item_id匹配，其次通过user_id和item_name匹配）
                        existing = None
                        if emby_item_id != 'unknown':
                            existing = db.query(WatchHistory).filter_by(
                                user_id=user_id,
                                item_id=emby_item_id
                            ).first()
                        
                        if not existing:
                            # 如果没有通过item_id找到，尝试通过item_name和start_time匹配
                            existing = db.query(WatchHistory).filter_by(
                                user_id=user_id,
                                item_name=item_name
                            ).filter(
                                WatchHistory.start_time >= start_time.replace(hour=0, minute=0, second=0, microsecond=0),
                                WatchHistory.start_time < start_time.replace(hour=23, minute=59, second=59, microsecond=999999)
                            ).first()
                        
                        if existing:
                            # 更新现有记录
                            existing.item_id = emby_item_id
                            existing.item_type = item_type
                            existing.item_name = item_name
                            existing.start_time = start_time
                            existing.end_time = end_time
                            existing.duration = actual_duration
                            existing.play_count = (existing.play_count or 0) + 1
                            logger.info(f"更新记录: {item_name}, play_count={existing.play_count}")
                        else:
                            # 创建新记录
                            watch_record = WatchHistory(
                                user_id=user_id,
                                item_id=emby_item_id,
                                item_type=item_type,
                                item_name=item_name,
                                start_time=start_time,
                                end_time=end_time,
                                duration=actual_duration,
                                play_count=1
                            )
                            db.add(watch_record)
                            logger.info(f"创建新记录: {item_name}")
                        
                        synced_count += 1
                    except Exception as e:
                        error_count += 1
                        import traceback
                        logger.error(f"处理观看记录项失败 [{item.get('Name', 'unknown')}]: {e}")
                        logger.error(f"错误详情: {traceback.format_exc()}")
                        logger.error(f"项目数据: ID={item.get('Id')}, Type={item.get('Type')}, UserData={item.get('UserData', {})}")
                        continue
                
                db.commit()
                logger.info(f"同步观看历史完成: 用户 {user_id}, 成功 {synced_count} 条, 失败 {error_count} 条")
                return error_count == 0 or synced_count > 0
            except Exception as e:
                db.rollback()
                logger.error(f"同步观看历史到数据库失败: {e}")
                return False
            finally:
                db.close()
        except Exception as e:
            logger.error(f"同步观看历史失败: {e}")
            return False

    @staticmethod
    def sync_user_watch_history_improved(user_id, emby_user_id):
        """改进版同步Emby用户的观看历史（用于后台批量同步）
        
        Args:
            user_id: 本地用户ID
            emby_user_id: Emby用户ID
            
        Returns:
            bool: 同步是否成功
        """
        # 直接调用标准同步方法
        return EmbyAPI.sync_user_watch_history(user_id, emby_user_id)
    
    @staticmethod
    def sync_users():
        """同步Emby用户到本地数据库"""
        emby_users = EmbyAPI.get_users()
        if not emby_users:
            logger.warning("未能从Emby获取用户列表")
            return False
        
        db = get_db()
        synced_count = 0
        try:
            for emby_user in emby_users:
                emby_id = emby_user.get('Id')
                emby_name = emby_user.get('Name')
                
                if not emby_id or not emby_name:
                    continue
                
                # 跳过管理员账号
                if emby_name.lower() == 'admin':
                    continue
                
                # 查找本地用户
                local_user = db.query(User).filter_by(emby_user_id=emby_id).first()
                if not local_user:
                    local_user = db.query(User).filter_by(username=emby_name).first()
                    if local_user:
                        local_user.emby_user_id = emby_id
                        synced_count += 1
                    else:
                        new_user = User(
                            username=emby_name,
                            password_hash=generate_password_hash('123456'),
                            role=UserRole.USER,
                            is_active=True,
                            expiry_date=None,
                            emby_user_id=emby_id
                        )
                        db.add(new_user)
                        db.flush()
                        synced_count += 1
                        db.commit()
                        
                        try:
                            EmbyAPI.sync_user_watch_history(new_user.id, emby_id)
                        except Exception as e:
                            logger.error(f"同步用户 {emby_name} 的观看历史失败: {e}")
                        
                        db = get_db()
            
            db.commit()
            logger.info(f"成功同步 {synced_count} 个Emby用户")
            return True
        except Exception as e:
            db.rollback()
            logger.error(f"同步用户失败: {e}")
            return False
        finally:
            db.close()


# ============== WebDAV Provider 框架 ==============
class WebDAVProvider:
    """WebDAV 后端 Provider 抽象基类"""

    def __init__(self, server):
        self.server = server

    def test_connection(self):
        """测试与 WebDAV 后端的连接"""
        raise NotImplementedError

    def create_user(self, username, password, base_path):
        """在后端创建用户/目录"""
        raise NotImplementedError

    def enable_user(self, username):
        """启用用户"""
        raise NotImplementedError

    def disable_user(self, username):
        """禁用用户"""
        raise NotImplementedError

    def update_password(self, username, password):
        """更新用户密码"""
        raise NotImplementedError

    def set_quota(self, username, quota_bytes):
        """设置用户容量配额"""
        raise NotImplementedError


class GenericWebDAVProvider(WebDAVProvider):
    """通用 WebDAV Provider

    仅支持测试连接（PROPFIND），不尝试在后端创建/禁用用户。
    实际的用户启停需要管理员在 WebDAV 服务器侧自行配置。
    """

    def test_connection(self):
        try:
            url = self.server.server_url.rstrip('/')
            if self.server.root_path:
                url = url + '/' + self.server.root_path.strip('/')
            response = requests.request(
                'PROPFIND',
                url,
                auth=(self.server.admin_username, self.server.admin_password) if self.server.admin_username else None,
                headers={'Depth': '0'},
                timeout=10
            )
            return response.status_code in [200, 207]
        except Exception as e:
            logger.warning(f"通用 WebDAV 连接测试失败: {e}")
            return False

    def create_user(self, username, password, base_path):
        logger.info(f"通用 WebDAV Provider 不自动创建后端用户: {username}")
        return True

    def enable_user(self, username):
        logger.info(f"通用 WebDAV Provider 不自动启用后端用户: {username}")
        return True

    def disable_user(self, username):
        logger.info(f"通用 WebDAV Provider 不自动禁用后端用户: {username}")
        return True

    def update_password(self, username, password):
        logger.info(f"通用 WebDAV Provider 不自动更新后端密码: {username}")
        return True

    def set_quota(self, username, quota_bytes):
        logger.info(f"通用 WebDAV Provider 不自动设置后端配额: {username}")
        return True


class AListWebDAVProvider(WebDAVProvider):
    """AList WebDAV Provider（预留实现框架）"""

    def _get_token(self):
        try:
            url = self.server.server_url.rstrip('/')
            login_url = f"{url}/api/auth/login"
            response = requests.post(
                login_url,
                json={
                    'username': self.server.admin_username,
                    'password': self.server.admin_password
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 200:
                    return data.get('data', {}).get('token')
        except Exception as e:
            logger.error(f"AList 登录失败: {e}")
        return None

    def test_connection(self):
        token = self._get_token()
        if not token:
            return False
        try:
            url = self.server.server_url.rstrip('/')
            response = requests.get(
                f"{url}/api/admin/user/list",
                headers={'Authorization': token},
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"AList 连接测试失败: {e}")
            return False

    def create_user(self, username, password, base_path):
        token = self._get_token()
        if not token:
            return False
        try:
            url = self.server.server_url.rstrip('/')
            response = requests.post(
                f"{url}/api/admin/user/create",
                headers={'Authorization': token},
                json={
                    'username': username,
                    'password': password,
                    'base_path': base_path,
                    'role': 0,
                    'disabled': False
                },
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"AList 创建用户失败: {e}")
            return False

    def enable_user(self, username):
        return self._update_user(username, disabled=False)

    def disable_user(self, username):
        return self._update_user(username, disabled=True)

    def update_password(self, username, password):
        return self._update_user(username, password=password)

    def set_quota(self, username, quota_bytes):
        logger.info(f"AList 暂不直接支持按用户配额设置: {username}")
        return True

    def _update_user(self, username, disabled=None, password=None):
        token = self._get_token()
        if not token:
            return False
        try:
            url = self.server.server_url.rstrip('/')
            payload = {'username': username}
            if disabled is not None:
                payload['disabled'] = disabled
            if password is not None:
                payload['password'] = password
            response = requests.post(
                f"{url}/api/admin/user/update",
                headers={'Authorization': token},
                json=payload,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"AList 更新用户失败: {e}")
            return False


_WEBDAV_PROVIDERS = {
    'generic': GenericWebDAVProvider,
    'alist': AListWebDAVProvider,
}


def get_webdav_provider(server):
    """根据服务器类型获取对应 Provider"""
    provider_class = _WEBDAV_PROVIDERS.get(server.server_type, GenericWebDAVProvider)
    return provider_class(server)


# WebDAV 管理员密码加密 helpers
_FERNET_INST = None


def _get_fernet():
    """获取或创建 Fernet 实例，密钥保存在 SystemConfig 中"""
    global _FERNET_INST
    if _FERNET_INST is not None:
        return _FERNET_INST
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None

    key = get_config('webdav_encryption_key')
    if not key:
        key = Fernet.generate_key().decode()
        set_config('webdav_encryption_key', key)
    _FERNET_INST = Fernet(key.encode())
    return _FERNET_INST


def encrypt_webdav_password(plain):
    """加密 WebDAV 管理员密码"""
    if not plain:
        return plain
    f = _get_fernet()
    if f is None:
        return plain
    return f.encrypt(plain.encode()).decode()


def decrypt_webdav_password(cipher):
    """解密 WebDAV 管理员密码"""
    if not cipher:
        return cipher
    f = _get_fernet()
    if f is None:
        return cipher
    try:
        return f.decrypt(cipher.encode()).decode()
    except Exception:
        return cipher


# ============== WebDAV 用户分配与状态同步 ==============
def assign_webdav_to_user(user, db, server_id=None):
    """为指定用户自动分配一个可用的 WebDAV 服务器，可指定server_id"""
    # 已分配过且至少有一个可用分配的用户不再重复分配
    existing = db.query(UserWebDAVAssignment).filter_by(user_id=user.id).first()
    if existing:
        return existing

    if server_id:
        server = db.query(WebDAVServer).filter_by(id=server_id, is_active=True).first()
    else:
        # 选择启用且已分配用户数最少的服务器
        server = db.query(WebDAVServer).filter_by(is_active=True).order_by(
            func.coalesce(func.count(UserWebDAVAssignment.id), 0).asc()
        ).outerjoin(UserWebDAVAssignment).group_by(WebDAVServer.id).first()

    if not server:
        logger.warning(f"没有可用的 WebDAV 服务器，跳过用户分配: {user.username}")
        return None

    # 生成路径，避免特殊字符和冲突
    base_path = re.sub(r'[^a-zA-Z0-9_\-]', '_', user.username)
    assigned_path = f"/{base_path}"
    suffix = 1
    while db.query(UserWebDAVAssignment).filter_by(server_id=server.id, assigned_path=assigned_path).first():
        assigned_path = f"/{base_path}_{suffix}"
        suffix += 1

    quota = server.default_quota_bytes
    assignment = UserWebDAVAssignment(
        user_id=user.id,
        server_id=server.id,
        assigned_path=assigned_path,
        quota_bytes=quota,
        is_active=user.is_active and not user.is_expired()
    )
    db.add(assignment)
    db.flush()

    # 调用 Provider 尝试在后端创建用户（generic 模式下仅记录日志）
    try:
        provider = get_webdav_provider(server)
        password = ''  # 通用模式下不需要初始密码
        provider.create_user(user.username, password, assigned_path)
    except Exception as e:
        logger.warning(f"WebDAV Provider 创建用户失败: {user.username}, 错误: {e}")

    logger.info(f"用户已分配 WebDAV: {user.username} -> {server.name}{assigned_path}")
    return assignment


def sync_webdav_user_status(user, enable, db=None):
    """同步用户 WebDAV 启用/禁用状态"""
    should_close = False
    if db is None:
        db = get_db()
        should_close = True
    try:
        assignments = db.query(UserWebDAVAssignment).filter_by(user_id=user.id).all()
        for assignment in assignments:
            assignment.is_active = enable
            try:
                provider = get_webdav_provider(assignment.server)
                if enable:
                    provider.enable_user(user.username)
                else:
                    provider.disable_user(user.username)
            except Exception as e:
                logger.error(f"同步 WebDAV 用户状态失败: {user.username}, server={assignment.server.name}, 错误: {e}")
        db.commit()
    except Exception as e:
        logger.error(f"同步 WebDAV 用户状态时出错: {e}")
        db.rollback()
    finally:
        if should_close:
            db.close()


def sync_webdav_user_password(user, new_password, db=None):
    """同步用户 WebDAV 密码"""
    should_close = False
    if db is None:
        db = get_db()
        should_close = True
    try:
        assignments = db.query(UserWebDAVAssignment).filter_by(user_id=user.id).all()
        for assignment in assignments:
            try:
                provider = get_webdav_provider(assignment.server)
                provider.update_password(user.username, new_password)
            except Exception as e:
                logger.error(f"同步 WebDAV 密码失败: {user.username}, server={assignment.server.name}, 错误: {e}")
    except Exception as e:
        logger.error(f"同步 WebDAV 密码时出错: {e}")
    finally:
        if should_close:
            db.close()


def get_user_webdav_info(user, db=None):
    """获取用户可展示的 WebDAV 信息"""
    should_close = False
    if db is None:
        db = get_db()
        should_close = True
    try:
        # 过期/手动禁用/未激活用户不展示
        if not user.is_active or user.is_expired():
            return []
        assignments = db.query(UserWebDAVAssignment).filter_by(user_id=user.id, is_active=True).all()
        result = []
        for assignment in assignments:
            server = assignment.server
            if not server or not server.is_active:
                continue
            root = server.root_path.strip('/')
            path = assignment.assigned_path.strip('/')
            full_url = server.server_url.rstrip('/')
            if root:
                full_url = f"{full_url}/{root}"
            if path:
                full_url = f"{full_url}/{path}"
            result.append({
                'server_name': server.name,
                'server_type': server.server_type,
                'url': full_url,
                'username': user.username,
                'password_hint': '与登录密码相同',
                'quota_bytes': assignment.quota_bytes,
                'assigned_path': assignment.assigned_path
            })
        return result
    finally:
        if should_close:
            db.close()


def bulk_assign_webdav_to_existing_users():
    """为所有没有 WebDAV 分配的现有普通活跃用户批量分配"""
    db = SessionLocal()
    try:
        # 查找所有普通用户中没有 WebDAV 分配的用户
        subquery = select(UserWebDAVAssignment.user_id).where(
            UserWebDAVAssignment.user_id.isnot(None)
        ).distinct()
        users = db.query(User).filter(
            User.role == UserRole.USER,
            ~User.id.in_(subquery)
        ).all()

        count = 0
        for user in users:
            try:
                assign_webdav_to_user(user, db)
                count += 1
            except Exception as e:
                logger.error(f"批量分配 WebDAV 失败: {user.username}, 错误: {e}")
        db.commit()
        logger.info(f"批量 WebDAV 分配完成，共为 {count} 个用户分配")
        return count
    except Exception as e:
        db.rollback()
        logger.error(f"批量分配 WebDAV 时出错: {e}")
        return 0
    finally:
        db.close()


def trigger_bulk_assign_webdav_async(delay=1):
    """异步触发 WebDAV 存量用户分配（用于新增/启用服务器后）"""
    def _run():
        try:
            time.sleep(delay)
            bulk_assign_webdav_to_existing_users()
        except Exception as e:
            logger.error(f"异步 WebDAV 批量分配失败: {e}")

    Thread(target=_run, daemon=True).start()
    logger.info("WebDAV 存量用户分配任务已异步触发")


# ============== 邮件服务类 ==============
class EmailService:
    """邮件服务类 - 支持Resend API和SMTP两种方式发送邮件"""
    
    # 预设的邮件服务商配置
    EMAIL_PROVIDERS = {
        'resend': {
            'name': 'Resend API',
            'type': 'api',
            'help_url': 'https://resend.com/api-keys'
        },
        'qq': {
            'name': 'QQ邮箱',
            'type': 'smtp',
            'smtp_server': 'smtp.qq.com',
            'smtp_port': 465,
            'use_ssl': True,
            'help_url': 'https://service.mail.qq.com/cgi-bin/help?subtype=1&&id=28&&no=1001256'
        },
        '163': {
            'name': '163邮箱',
            'type': 'smtp',
            'smtp_server': 'smtp.163.com',
            'smtp_port': 465,
            'use_ssl': True,
            'help_url': 'https://help.mail.163.com/faqDetail.do?code=d7a5dc8471cd0c0e8b4b12f9293e86c5'
        },
        '126': {
            'name': '126邮箱',
            'type': 'smtp',
            'smtp_server': 'smtp.126.com',
            'smtp_port': 465,
            'use_ssl': True,
            'help_url': 'https://help.mail.163.com/faqDetail.do?code=d7a5dc8471cd0c0e8b4b12f9293e86c5'
        },
        'gmail': {
            'name': 'Gmail',
            'type': 'smtp',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 465,
            'use_ssl': True,
            'help_url': 'https://support.google.com/accounts/answer/185833'
        },
        'outlook': {
            'name': 'Outlook/Hotmail',
            'type': 'smtp',
            'smtp_server': 'smtp.office365.com',
            'smtp_port': 587,
            'use_ssl': False,
            'help_url': 'https://support.microsoft.com/zh-cn/account-billing/%E5%A6%82%E4%BD%95%E4%BD%BF%E7%94%A8outlook-com%E7%9A%84%E5%BA%94%E7%94%A8%E5%AF%86%E7%A0%81-9479f9d4-9c9c-4c25-9e1d-4f63937b5279'
        },
        'custom': {
            'name': '自定义SMTP',
            'type': 'smtp',
            'smtp_server': '',
            'smtp_port': 587,
            'use_ssl': False,
            'help_url': ''
        }
    }
    
    @staticmethod
    def get_config():
        """获取邮件配置"""
        db = get_db()
        try:
            config = db.query(EmailConfig).first()
            if config:
                return config.to_dict()
            return None
        finally:
            db.close()
    
    @staticmethod
    def is_configured():
        """检查邮件是否已配置"""
        config = EmailService.get_config()
        if not config:
            return False
        
        provider = config.get('provider', 'resend')
        
        if provider == 'resend':
            # Resend模式：检查API Key和发件邮箱
            return bool(config.get('resend_api_key') and config.get('system_email'))
        else:
            # SMTP模式：检查邮箱和密码
            return bool(config.get('system_email') and config.get('smtp_password'))
    
    @staticmethod
    def get_provider_config(provider_key):
        """获取邮件服务商配置"""
        return EmailService.EMAIL_PROVIDERS.get(provider_key, EmailService.EMAIL_PROVIDERS['custom'])
    
    @staticmethod
    def test_connection(config_data=None):
        """测试邮件连接"""
        try:
            if config_data:
                provider = config_data.get('provider', 'resend')
            else:
                config = EmailService.get_config()
                if not config:
                    return False, "邮件未配置"
                provider = config.get('provider', 'resend')
            
            # 根据服务商类型选择不同的测试方式
            if provider == 'resend':
                return EmailService._test_resend_connection(config_data)
            else:
                return EmailService._test_smtp_connection(config_data)
        except Exception as e:
            logger.error(f"邮件连接测试失败: {e}")
            return False, f"连接失败: {str(e)}"
    
    @staticmethod
    def _test_resend_connection(config_data=None):
        """测试Resend API连接"""
        try:
            import requests
            
            if config_data:
                api_key = config_data.get('resend_api_key', '')
                from_email = config_data.get('system_email', '')
            else:
                config = EmailService.get_config()
                if not config:
                    return False, "邮件未配置"
                api_key = config.get('resend_api_key', '')
                from_email = config.get('system_email', '')
            
            if not api_key:
                return False, "请提供Resend API Key"
            
            if not from_email:
                return False, "请提供发件邮箱地址"
            
            # 测试API Key是否有效
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get('https://api.resend.com/domains', headers=headers, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"Resend API连接成功")
                return True, "Resend API连接成功"
            else:
                error_data = response.json()
                error_msg = error_data.get('message', '未知错误')
                return False, f"Resend API认证失败: {error_msg}"
        except requests.exceptions.RequestException as e:
            logger.error(f"Resend API测试失败: {e}")
            return False, f"网络错误: {str(e)}"
        except Exception as e:
            logger.error(f"Resend API测试失败: {e}")
            return False, str(e)
    
    @staticmethod
    def _test_smtp_connection(config_data=None):
        """测试SMTP连接"""
        try:
            import smtplib
            
            if config_data:
                provider = config_data.get('provider', 'custom')
                email = config_data.get('system_email', '')
                password = config_data.get('smtp_password', '')
                
                # 获取服务商配置
                if provider == 'custom':
                    smtp_server = config_data.get('smtp_server', '')
                    smtp_port = int(config_data.get('smtp_port', 587))
                else:
                    provider_config = EmailService.get_provider_config(provider)
                    smtp_server = provider_config['smtp_server']
                    smtp_port = provider_config['smtp_port']
            else:
                config = EmailService.get_config()
                if not config:
                    return False, "邮件未配置"
                provider = config.get('provider', 'custom')
                email = config.get('system_email', '')
                password = config.get('smtp_password', '')
                
                if provider == 'custom':
                    smtp_server = config.get('smtp_server', '')
                    smtp_port = int(config.get('smtp_port', 587))
                else:
                    provider_config = EmailService.get_provider_config(provider)
                    smtp_server = provider_config['smtp_server']
                    smtp_port = provider_config['smtp_port']
            
            if not all([smtp_server, email, password]):
                return False, "配置信息不完整"
            
            # 获取服务商配置
            if config_data and provider != 'custom':
                provider_config = EmailService.get_provider_config(provider)
                use_ssl = provider_config.get('use_ssl', False)
            elif provider != 'custom':
                provider_config = EmailService.get_provider_config(provider)
                use_ssl = provider_config.get('use_ssl', smtp_port == 465)
            else:
                use_ssl = smtp_port == 465
            
            logger.info(f"测试SMTP连接: server={smtp_server}, port={smtp_port}, use_ssl={use_ssl}, email={email}")
            
            # 尝试连接SMTP服务器
            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=15)
                logger.info(f"使用SMTP_SSL连接到 {smtp_server}:{smtp_port}")
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
                logger.info(f"使用SMTP连接到 {smtp_server}:{smtp_port}")
                server.set_debuglevel(1)
                server.starttls()
            
            # 尝试登录
            try:
                server.login(email, password)
                logger.info(f"登录成功: {email}")
            except smtplib.SMTPAuthenticationError as auth_err:
                logger.error(f"SMTP认证失败: {auth_err}")
                if provider == 'outlook':
                    logger.info("尝试使用备用SMTP服务器...")
                    return EmailService._try_outlook_backup(email, password)
                raise
            
            server.quit()
            return True, "连接成功"
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"邮件认证失败: {e}")
            error_msg = str(e)
            if '535' in error_msg or '5.7.139' in error_msg or '5.7.3' in error_msg or 'SmtpClientAuthentication' in error_msg:
                return False, "SMTP认证失败。请检查：1) 已启用SMTP访问 2) 使用应用密码 3) 账户未设置双重认证阻止"
            return False, f"认证失败: {str(e)}"
        except Exception as e:
            logger.error(f"邮件连接测试失败: {e}")
            return False, f"连接失败: {str(e)}"
    
    @staticmethod
    def _try_outlook_backup(email, password):
        """尝试使用备用Outlook SMTP服务器"""
        import smtplib
        
        backup_servers = [
            ('smtp.office365.com', 587, False),
            ('smtp-mail.outlook.com', 587, False),
            ('smtp.live.com', 587, False),
        ]
        
        for server, port, use_ssl in backup_servers:
            try:
                logger.info(f"尝试备用服务器: {server}:{port}")
                if use_ssl:
                    conn = smtplib.SMTP_SSL(server, port, timeout=15)
                else:
                    conn = smtplib.SMTP(server, port, timeout=15)
                    conn.ehlo()
                    conn.starttls()
                    conn.ehlo()
                
                conn.login(email, password)
                logger.info(f"备用服务器连接成功: {server}")
                conn.quit()
                return True, f"连接成功 (使用 {server})"
            except Exception as e:
                logger.warning(f"备用服务器 {server} 失败: {e}")
                continue
        
        return False, "所有Outlook SMTP服务器都无法连接。请检查：1) 账户是否启用SMTP访问 2) 是否使用应用密码而非登录密码"
    
    @staticmethod
    def send_email(to_email, subject, content, username='用户'):
        """发送邮件 - 支持Resend API和SMTP两种方式"""
        try:
            config = EmailService.get_config()
            if not config:
                return False, "邮件未配置"
            
            provider = config.get('provider', 'resend')
            
            if provider == 'resend':
                return EmailService._send_via_resend(to_email, subject, content, config)
            else:
                return EmailService._send_via_smtp(to_email, subject, content, config)
        except Exception as e:
            logger.error(f"邮件发送失败: {e}")
            return False, str(e)
    
    @staticmethod
    def _send_via_resend(to_email, subject, content, config):
        """通过Resend API发送邮件"""
        try:
            import requests
            
            api_key = config.get('resend_api_key', '')
            from_email = config.get('system_email', '')
            sender_name = config.get('sender_name', 'Emby Manager')
            
            if not api_key:
                return False, "Resend API Key未配置"
            
            if not from_email:
                return False, "发件邮箱未配置"
            
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'from': f'{sender_name} <{from_email}>',
                'to': [to_email],
                'subject': subject,
                'html': content
            }
            
            response = requests.post('https://api.resend.com/emails', json=data, headers=headers, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Resend邮件发送成功: {to_email}, ID: {result.get('id')}")
                return True, "发送成功"
            else:
                error_data = response.json()
                error_msg = error_data.get('message', '未知错误')
                logger.error(f"Resend邮件发送失败: {error_msg}")
                return False, f"发送失败: {error_msg}"
        except requests.exceptions.RequestException as e:
            logger.error(f"Resend邮件发送失败: {e}")
            return False, f"网络错误: {str(e)}"
        except Exception as e:
            logger.error(f"Resend邮件发送失败: {e}")
            return False, str(e)
    
    @staticmethod
    def _send_via_smtp(to_email, subject, content, config):
        """通过SMTP发送邮件"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.utils import formataddr
            import uuid
            
            provider = config.get('provider', 'custom')
            email = config.get('system_email', '')
            password = config.get('smtp_password', '')
            sender_name = config.get('sender_name', 'Emby Manager')
            
            # 获取服务商配置
            if provider == 'custom':
                smtp_server = config.get('smtp_server', '')
                smtp_port = int(config.get('smtp_port', 587))
            else:
                provider_config = EmailService.get_provider_config(provider)
                smtp_server = provider_config['smtp_server']
                smtp_port = provider_config['smtp_port']
            
            if not all([smtp_server, email, password]):
                return False, "邮件配置不完整"
            
            # 获取use_ssl配置
            provider_config = EmailService.get_provider_config(provider)
            use_ssl = provider_config.get('use_ssl', smtp_port == 465)
            
            # 创建HTML内容部分
            msg_content = MIMEText(content, 'html', 'utf-8')
            
            # 生成边界
            boundary = f"==============={uuid.uuid4().hex[:16]}=="
            
            # 修复：手动构建邮件头，确保中文主题正确显示
            from_header = formataddr((sender_name, email))
            full_message = f"""Content-Type: multipart/mixed; boundary="{boundary}"
MIME-Version: 1.0
From: {from_header}
To: {to_email}
Subject: {subject}

--{boundary}
{msg_content.as_string()}
--{boundary}--
"""
            
            logger.info(f"=== 邮件调试信息 ===")
            logger.info(f"From: {from_header}")
            logger.info(f"To: {to_email}")
            logger.info(f"Subject: {subject}")
            logger.info(f"完整邮件内容 (前500字符):\n{full_message[:500]}")
            
            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=15)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
                server.starttls()
            
            server.login(email, password)
            # 修复：将邮件内容编码为UTF-8字节
            server.sendmail(email, [to_email], full_message.encode('utf-8'))
            server.quit()
            
            logger.info(f"SMTP邮件发送成功: {to_email}")
            return True, "发送成功"
        except Exception as e:
            logger.error(f"SMTP邮件发送失败: {e}")
            error_msg = str(e)
            if '535' in error_msg or '5.7.139' in error_msg or '5.7.3' in error_msg:
                return False, "SMTP认证失败。请检查：1) 已启用SMTP访问 2) 使用应用密码 3) 账户未设置双重认证阻止"
            return False, error_msg
    
    @staticmethod
    def render_template(template, **kwargs):
        """渲染邮件模板"""
        if not template:
            return ""
        result = template
        for key, value in kwargs.items():
            result = result.replace(f'{{{{{key}}}}}', str(value))
        return result
    
    @staticmethod
    def _is_html_content(content):
        """检查内容是否为HTML格式"""
        if not content:
            return False
        # 检查是否包含常见的HTML标签
        html_tags = ['<html', '<body', '<div', '<p', '<br', '<span', '<h1', '<h2', '<h3', '<table', '<a ', '<img', '<strong', '<b>', '<i>', '<u>']
        content_lower = content.lower()
        return any(tag in content_lower for tag in html_tags)
    
    @staticmethod
    def _text_to_html(text):
        """将纯文本转换为HTML格式"""
        if not text:
            return ""
        # 转义HTML特殊字符
        import html
        text = html.escape(text)
        # 将换行符转换为<br>标签
        text = text.replace('\n', '<br>')
        # 包装在div中，添加基本样式
        return f'<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">{text}</div>'
    
    @staticmethod
    def send_verification_code(to_email, code, purpose='register', username='用户'):
        """发送验证码邮件"""
        config = EmailService.get_config()
        if not config:
            return False, "邮件未配置"
        
        # 获取模板
        template = config.get('email_template', '')
        subject_template = config.get('email_subject', '验证码通知')
        site_name = get_config('site_name', 'Emby Manager')
        
        # 渲染内容
        content = EmailService.render_template(
            template,
            username=username,
            code=code,
            expire_minutes=5,
            site_name=site_name
        )
        
        # 修复：如果内容不是HTML格式，将纯文本转换为HTML
        if not EmailService._is_html_content(content):
            content = EmailService._text_to_html(content)
        
        subject = EmailService.render_template(
            subject_template,
            username=username,
            site_name=site_name
        )
        
        return EmailService.send_email(to_email, subject, content, username)
    
    @staticmethod
    def save_config(config_data):
        """保存邮件配置"""
        db = get_db()
        try:
            config = db.query(EmailConfig).first()
            if not config:
                config = EmailConfig()
                db.add(config)
            
            config.provider = config_data.get('provider', 'resend')
            config.system_email = config_data.get('system_email', '')
            config.resend_api_key = config_data.get('resend_api_key', '')
            config.sender_name = config_data.get('sender_name', 'Emby Manager')
            config.email_template = config_data.get('email_template', '')
            config.email_subject = config_data.get('email_subject', '验证码通知')
            config.is_enabled = config_data.get('is_enabled', True)
            config.updated_at = datetime.now()
            
            # 如果是SMTP服务商，保存SMTP服务器和端口
            if config.provider != 'resend':
                if config.provider == 'custom':
                    config.smtp_server = config_data.get('smtp_server', '')
                    config.smtp_port = config_data.get('smtp_port', 587)
                else:
                    provider_config = EmailService.get_provider_config(config.provider)
                    config.smtp_server = provider_config['smtp_server']
                    config.smtp_port = provider_config['smtp_port']
                config.smtp_password = config_data.get('smtp_password', '')
            
            db.commit()
            return True, "配置保存成功"
        except Exception as e:
            db.rollback()
            logger.error(f"保存邮件配置失败: {e}")
            return False, str(e)
        finally:
            db.close()
    
    @staticmethod
    def get_email_logs(page=1, per_page=20):
        """获取验证码记录（分页）- 直接查询验证码表以显示所有验证码状态"""
        db = get_db()
        try:
            # 直接查询验证码表，这样可以显示所有验证码（包括没有邮件日志的）
            query = db.query(EmailVerificationCode).order_by(EmailVerificationCode.created_at.desc())
            total = query.count()
            verifications = query.offset((page - 1) * per_page).limit(per_page).all()
            
            # 转换为字典
            logs_data = []
            for v in verifications:
                # 查询对应的邮件发送记录（如果有）
                send_log = db.query(EmailSendLog).filter(
                    EmailSendLog.email == v.email,
                    EmailSendLog.code == v.code,
                    EmailSendLog.send_type == v.purpose
                ).order_by(EmailSendLog.created_at.desc()).first()
                
                log_dict = {
                    'id': v.id,
                    'user_id': v.user_id,
                    'email': v.email,
                    'code': v.code,
                    'send_type': v.purpose,  # 用途作为发送类型
                    'content': send_log.content if send_log else None,  # 从邮件日志获取内容
                    'created_at': v.created_at.isoformat() if v.created_at else None,
                    'is_used': v.is_used,
                    'is_expired': v.expires_at < datetime.now() if v.expires_at else False,
                    'used_at': v.used_at.isoformat() if v.used_at else None,
                    'expires_at': v.expires_at.isoformat() if v.expires_at else None,
                    'is_success': send_log.is_success if send_log else True,  # 如果没有邮件日志，假设发送成功
                    'error_message': send_log.error_message if send_log else None,
                    'ip_address': v.ip_address
                }
                logs_data.append(log_dict)
            
            return {
                'total': total,
                'page': page,
                'per_page': per_page,
                'logs': logs_data
            }
        finally:
            db.close()
    
    @staticmethod
    def delete_email_logs(log_ids):
        """删除验证码记录"""
        db = get_db()
        try:
            # 删除验证码表中的记录
            deleted_count = db.query(EmailVerificationCode).filter(EmailVerificationCode.id.in_(log_ids)).delete(synchronize_session=False)
            db.commit()
            logger.info(f"删除验证码记录成功: {deleted_count}条")
            return True, f"成功删除{deleted_count}条记录"
        except Exception as e:
            db.rollback()
            logger.error(f"删除验证码记录失败: {e}")
            return False, str(e)
        finally:
            db.close()


# ============== Favicon ==============
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static', 'images'),
                               'favicon.svg', mimetype='image/svg+xml')

# ============== 认证 API ==============
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': '请输入用户名和密码'}), 400
    
    # 登录失败限制检查
    client_ip = request.remote_addr
    current_time = time.time()
    
    # 清理过期的登录尝试记录
    if client_ip in login_attempts:
        attempts = login_attempts[client_ip]
        # 移除超过封禁时间的记录
        attempts['times'] = [t for t in attempts.get('times', []) if current_time - t < LOGIN_BLOCK_TIME]
        
        # 检查是否被封禁
        if len(attempts.get('times', [])) >= MAX_LOGIN_ATTEMPTS:
            logger.warning(f"IP {client_ip} 登录尝试过多，已被临时封禁")
            return jsonify({'success': False, 'message': '登录尝试过多，请5分钟后再试'}), 429
    
    db = get_db()
    try:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            logger.warning(f"登录失败 - 用户不存在: {username}")
            # 记录登录失败（先记录到内存，确保即使数据库失败也能限制）
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {'times': []}
            login_attempts[client_ip]['times'].append(current_time)

            # 记录登录失败日志（使用username作为标识，但user_id为0表示用户不存在）
            try:
                login_log = LoginLog(
                    user_id=0,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                    success=0  # 使用整数0表示失败
                )
                db.add(login_log)
                db.commit()
            except Exception as log_error:
                logger.error(f"记录登录失败日志失败: {log_error}")
                db.rollback()
            return jsonify({'success': False, 'message': '用户名或密码错误'}), 401

        password_match = check_password_hash(user.password_hash, password)
        logger.info(f"登录验证 - 用户名: {username}, 存储的哈希前50位: {user.password_hash[:50]}..., 密码匹配: {password_match}")

        if not password_match:
            # 记录登录失败（先记录到内存，确保即使数据库失败也能限制）
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {'times': []}
            login_attempts[client_ip]['times'].append(current_time)

            # 记录登录失败日志
            try:
                login_log = LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                    success=0  # 使用整数0表示失败
                )
                db.add(login_log)
                db.commit()
            except Exception as log_error:
                logger.error(f"记录登录失败日志失败: {log_error}")
                db.rollback()
            return jsonify({'success': False, 'message': '用户名或密码错误'}), 401
        
        # 获取IP地址和用户代理
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # 记录登录日志
        login_log = LoginLog(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=1  # 使用整数1表示成功
        )
        db.add(login_log)
        db.commit()
        
        # 检查是否被禁用（is_active完全手动控制）
        if not user.is_active:
            return jsonify({'success': False, 'message': '账号已被禁用'}), 403
        
        # 检查是否过期 - 过期用户允许登录但只能续期
        is_expired = user.is_expired()
        
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role.value
        
        if is_expired:
            logger.info(f"过期用户登录: {username}")
            return jsonify({
                'success': True,
                'message': '账号已过期，请续期',
                'data': {
                    'id': user.id,
                    'username': user.username,
                    'role': user.role.value,
                    'is_expired': True,
                    'require_renew': True
                }
            })
        
        logger.info(f"用户登录: {username}")
        
        return jsonify({
            'success': True,
            'message': '登录成功',
            'data': {
                'id': user.id,
                'username': user.username,
                'role': user.role.value,
                'is_expired': False
            }
        })
    finally:
        db.close()

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """退出登录页面路由"""
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"用户登出: {username}")
    return redirect('/login')

@app.route('/auth/logout', methods=['GET', 'POST'])
def auth_logout():
    """用户端退出登录路由"""
    return logout()

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """API退出登录"""
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"用户登出: {username}")
    return jsonify({'success': True, 'message': '登出成功'})

@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    data = request.get_json()
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    csrf_token = data.get('csrf_token', '')

    # 验证CSRF token
    if not verify_csrf_token(csrf_token):
        logger.warning(f"CSRF验证失败 - 用户: {session.get('username', 'unknown')}")
        return jsonify({'success': False, 'message': '安全验证失败，请刷新页面后重试'}), 403

    if not old_password or not new_password:
        return jsonify({'success': False, 'message': '请填写完整信息'}), 400
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': '新密码至少6位'}), 400
    
    user_id = session['user_id']
    username = None
    emby_user_id = None
    client_ip = request.remote_addr
    current_time = datetime.now()
    
    # 清理过期记录
    cleanup_password_attempts()
    
    # 安全检测：检查同一用户1小时内修改次数
    if user_id in password_change_attempts:
        if len(password_change_attempts[user_id]) >= PASSWORD_CHANGE_HOUR_LIMIT:
            logger.warning(f"密码修改频率超限 - 用户ID: {user_id}, 1小时内修改次数: {len(password_change_attempts[user_id])}")
            ban_user_for_suspicious_activity(user_id, "1小时内密码修改次数超过5次")
            return jsonify({'success': False, 'message': '密码修改频率过高，账号已被临时封禁，请联系管理员'}), 429
    
    # 安全检测：检查同一IP在10分钟内是否有≥3个不同用户修改密码
    if client_ip in password_change_ip_attempts:
        ip_data = password_change_ip_attempts[client_ip]
        if len(ip_data['user_ids']) >= PASSWORD_CHANGE_IP_USER_LIMIT and user_id not in ip_data['user_ids']:
            logger.warning(f"IP地址密码修改行为异常 - IP: {client_ip}, 不同用户数: {len(ip_data['user_ids'])}")
            # 封禁该IP下的所有用户
            for uid in ip_data['user_ids']:
                ban_user_for_suspicious_activity(uid, f"同一IP({client_ip})在10分钟内有多个用户修改密码")
            # 封禁当前用户
            ban_user_for_suspicious_activity(user_id, f"同一IP({client_ip})在10分钟内有多个用户修改密码")
            return jsonify({'success': False, 'message': '检测到异常密码修改行为，相关账号已被封禁'}), 429
    
    # 第一步：验证原密码并更新本地密码
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            db.close()
            return jsonify({'success': False, 'message': '用户不存在'}), 400

        username = user.username
        emby_user_id = user.emby_user_id

        if not check_password_hash(user.password_hash, old_password):
            logger.warning(f"修改密码失败 - 原密码错误: {username}")
            # 记录失败次数
            if user_id not in password_change_failures:
                password_change_failures[user_id] = {'count': 0, 'last_time': current_time}
            password_change_failures[user_id]['count'] += 1
            password_change_failures[user_id]['last_time'] = current_time
            
            # 检查连续失败次数
            if password_change_failures[user_id]['count'] >= PASSWORD_CHANGE_FAILURE_LIMIT:
                logger.warning(f"密码修改连续失败次数超限 - 用户: {username}, 失败次数: {password_change_failures[user_id]['count']}")
                ban_user_for_suspicious_activity(user_id, "连续3次密码修改原密码验证失败")
                db.close()
                return jsonify({'success': False, 'message': '密码修改失败次数过多，账号已被封禁'}), 429
            
            db.close()
            return jsonify({'success': False, 'message': '原密码错误'}), 400

        # 原密码验证成功，清理失败记录
        if user_id in password_change_failures:
            del password_change_failures[user_id]

        # 生成新密码哈希
        new_hash = generate_password_hash(new_password)
        logger.info(f"准备更新密码 - 用户名: {username}, 旧哈希前50位: {user.password_hash[:50]}..., 新哈希前50位: {new_hash[:50]}...")

        # 更新密码并提交
        user.password_hash = new_hash
        db.commit()
        logger.info(f"本地密码修改成功并已提交到数据库: {username}")
    except Exception as e:
        db.rollback()
        logger.error(f"修改本地密码失败: {e}")
        db.close()
        return jsonify({'success': False, 'message': '修改失败'}), 500
    finally:
        db.close()
    
    # 第二步：使用新会话验证密码是否正确写入
    db = get_db()
    try:
        user_check = db.query(User).get(user_id)
        if not user_check:
            logger.error(f"验证失败 - 用户不存在: {user_id}")
            return jsonify({'success': False, 'message': '验证失败'}), 500
        
        logger.info(f"数据库验证 - 提交后的密码哈希前50位: {user_check.password_hash[:50]}...")
        verify_result = check_password_hash(user_check.password_hash, new_password)
        logger.info(f"密码验证测试 - 使用新密码验证: {verify_result}")
        
        if not verify_result:
            logger.error(f"密码验证失败 - 新密码无法通过验证: {username}")
            return jsonify({'success': False, 'message': '密码修改后验证失败'}), 500
    except Exception as e:
        logger.error(f"验证密码失败: {e}")
        return jsonify({'success': False, 'message': '验证失败'}), 500
    finally:
        db.close()
    
    # 第三步：同步到Emby（不影响本地密码修改结果）
    emby_sync_success = True
    if emby_user_id and EmbyAPI.is_configured():
        try:
            emby_sync_success = EmbyAPI.update_password(emby_user_id, new_password)
            if emby_sync_success:
                logger.info(f"Emby密码同步成功: {username}")
            else:
                logger.warning(f"Emby密码同步失败: {username}")
        except Exception as e:
            logger.error(f"Emby密码同步异常: {e}")
            emby_sync_success = False

    # 第四步：同步到 WebDAV（不影响本地密码修改结果）
    webdav_sync_success = True
    try:
        db = get_db()
        try:
            user = db.query(User).get(user_id)
            if user:
                sync_webdav_user_password(user, new_password, db)
                logger.info(f"WebDAV密码同步完成: {username}")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"WebDAV密码同步异常: {e}")
        webdav_sync_success = False
    
    # 记录密码修改成功
    if user_id not in password_change_attempts:
        password_change_attempts[user_id] = []
    password_change_attempts[user_id].append(current_time)
    
    # 记录IP行为
    if client_ip not in password_change_ip_attempts:
        password_change_ip_attempts[client_ip] = {'user_ids': set(), 'timestamps': []}
    password_change_ip_attempts[client_ip]['user_ids'].add(user_id)
    password_change_ip_attempts[client_ip]['timestamps'].append(current_time)
    
    message = '密码修改成功'
    if not emby_sync_success and not webdav_sync_success:
        message = '密码修改成功，但Emby和WebDAV密码同步失败'
    elif not emby_sync_success:
        message = '密码修改成功，但Emby密码同步失败'
    elif not webdav_sync_success:
        message = '密码修改成功，但WebDAV密码同步失败'
    
    logger.info(f"用户修改密码完成: {username}")
    return jsonify({'success': True, 'message': message})

@app.route('/api/login-logs', methods=['GET'])
@login_required
def api_get_login_logs():
    """获取当前用户的登录日志（支持分页）"""
    db = get_db()
    try:
        user_id = session['user_id']
        
        # 获取分页参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # 限制每页最大记录数
        if per_page > 100:
            per_page = 100
        
        # 计算偏移量
        offset = (page - 1) * per_page
        
        # 获取总记录数
        total = db.query(LoginLog).filter_by(user_id=user_id).count()
        
        # 获取分页数据
        logs = db.query(LoginLog).filter_by(user_id=user_id).order_by(
            LoginLog.login_time.desc()
        ).offset(offset).limit(per_page).all()
        
        logs_data = [log.to_dict() for log in logs]
        
        # 计算总页数
        total_pages = (total + per_page - 1) // per_page
        
        logger.info(f"获取登录日志 - 用户ID: {user_id}, 页码: {page}, 每页: {per_page}, 总数: {total}")
        
        return jsonify({
            'success': True,
            'data': logs_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': total_pages
            }
        })
    except Exception as e:
        logger.error(f"获取登录日志失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()

@app.route('/api/login-logs/clear', methods=['POST'])
@login_required
def api_clear_login_logs():
    """清空当前用户的所有登录日志"""
    data = request.get_json() or {}
    csrf_token = data.get('csrf_token', '')
    
    # 验证CSRF token
    if not verify_csrf_token(csrf_token):
        logger.warning(f"CSRF验证失败 - 清空登录日志 - 用户: {session.get('username', 'unknown')}")
        return jsonify({'success': False, 'message': '安全验证失败，请刷新页面后重试'}), 403
    
    db = get_db()
    try:
        user_id = session['user_id']
        
        # 删除该用户的所有登录日志
        deleted_count = db.query(LoginLog).filter_by(user_id=user_id).delete(synchronize_session=False)
        db.commit()
        
        logger.info(f"用户 {user_id} 清空了登录日志，共删除 {deleted_count} 条记录")
        return jsonify({'success': True, 'message': f'已清空 {deleted_count} 条登录日志'})
    except Exception as e:
        db.rollback()
        logger.error(f"清空登录日志失败: {e}")
        return jsonify({'success': False, 'message': '清空失败'}), 500
    finally:
        db.close()

@app.route('/api/login-logs/batch-delete', methods=['POST'])
@login_required
def api_batch_delete_login_logs():
    """批量删除当前用户的登录日志"""
    data = request.get_json() or {}
    csrf_token = data.get('csrf_token', '')
    
    # 验证CSRF token
    if not verify_csrf_token(csrf_token):
        logger.warning(f"CSRF验证失败 - 批量删除登录日志 - 用户: {session.get('username', 'unknown')}")
        return jsonify({'success': False, 'message': '安全验证失败，请刷新页面后重试'}), 403
    
    db = get_db()
    try:
        user_id = session['user_id']
        log_ids = data.get('log_ids', [])
        
        if not log_ids or not isinstance(log_ids, list):
            return jsonify({'success': False, 'message': '请选择要删除的日志'}), 400
        
        # 限制批量删除数量，防止滥用
        if len(log_ids) > 100:
            return jsonify({'success': False, 'message': '单次最多删除100条日志'}), 400
        
        # 删除指定ID的日志（只能删除自己的日志）
        deleted_count = db.query(LoginLog).filter(
            LoginLog.id.in_(log_ids),
            LoginLog.user_id == user_id
        ).delete(synchronize_session=False)
        db.commit()
        
        logger.info(f"用户 {user_id} 批量删除了登录日志，共删除 {deleted_count} 条记录")
        return jsonify({'success': True, 'message': f'已删除 {deleted_count} 条登录日志'})
    except Exception as e:
        db.rollback()
        logger.error(f"批量删除登录日志失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()

@app.route('/api/check-session', methods=['GET'])
def api_check_session():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'}), 401
    
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        if not user:
            session.clear()
            return jsonify({'success': False, 'message': '用户不存在'}), 401
        
        return jsonify({
            'success': True,
            'data': {
                'id': user.id,
                'username': user.username,
                'role': user.role.value,
                'is_active': user.is_active,
                'is_expired': user.is_expired()
            }
        })
    finally:
        db.close()

# ============== 注册 API ==============
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    code = data.get('code', '').strip().upper()
    email = data.get('email', '').strip().lower() if data.get('email') else ''
    email_code = data.get('email_code', '').strip() if data.get('email_code') else ''
    
    logger.info(f"=== 注册请求调试 ===")
    logger.info(f"username: {repr(username)}")
    logger.info(f"email: {repr(email)}")
    logger.info(f"email_code: {repr(email_code)}")
    logger.info(f"code: {repr(code)}")
    logger.info(f"完整请求数据: {data}")
    
    if not username or not password:
        return jsonify({'success': False, 'message': '请填写用户名和密码'}), 400
    
    if len(username) < 3 or len(username) > 20:
        return jsonify({'success': False, 'message': '用户名长度3-20位'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': '密码至少6位'}), 400
    
    db = get_db()
    try:
        # 检查用户名是否存在
        if db.query(User).filter_by(username=username).first():
            return jsonify({'success': False, 'message': '用户名已存在'}), 400
        
        # 判断注册方式：邮箱注册或激活码注册
        is_email_register = bool(email and email_code)
        logger.info(f"注册方式: {'邮箱注册' if is_email_register else '激活码注册'}")
        
        if is_email_register:
            # 邮箱注册：验证邮箱和验证码
            if not email or not email_code:
                return jsonify({'success': False, 'message': '请提供邮箱和验证码'}), 400
            
            # 检查邮箱是否已被注册
            if db.query(User).filter_by(email=email).first():
                return jsonify({'success': False, 'message': '该邮箱已被注册'}), 400
            
            # 调试：记录收到的验证码信息
            logger.info(f"=== 邮箱注册调试信息 ===")
            logger.info(f"收到的邮箱: {repr(email)}")
            logger.info(f"收到的验证码: {repr(email_code)}")
            
            # 验证邮箱验证码
            verification = db.query(EmailVerificationCode).filter(
                EmailVerificationCode.email == email,
                EmailVerificationCode.code == email_code,
                EmailVerificationCode.purpose == 'register',
                EmailVerificationCode.is_used == False,
                EmailVerificationCode.expires_at > datetime.now()
            ).order_by(EmailVerificationCode.created_at.desc()).first()
            
            if not verification:
                # 调试：查找是否有任何匹配的记录
                all_codes = db.query(EmailVerificationCode).filter(
                    EmailVerificationCode.email == email,
                    EmailVerificationCode.purpose == 'register'
                ).order_by(EmailVerificationCode.created_at.desc()).all()
                
                logger.info(f"找到的验证码记录数: {len(all_codes)}")
                for vc in all_codes:
                    logger.info(f"  记录: code={repr(vc.code)}, is_used={vc.is_used}, expires_at={vc.expires_at}, now={datetime.now()}, expired={vc.expires_at <= datetime.now()}")
                
                return jsonify({'success': False, 'message': '邮箱验证码无效或已过期'}), 400
            
            logger.info(f"验证码验证成功: {email}")
            
            # 邮箱注册用户默认过期（需要后续激活）
            expiry_date = datetime.now()  # 设置为当前时间，表示已过期
            
            # 标记验证码为已使用
            verification.is_used = True
            verification.used_at = datetime.now()
            
            activation_code_id = None
        else:
            # 激活码注册：验证激活码
            if not code:
                return jsonify({'success': False, 'message': '请提供激活码或邮箱验证码'}), 400
            
            activation_code = db.query(ActivationCode).filter_by(code=code, is_used=False).first()
            if not activation_code:
                return jsonify({'success': False, 'message': '激活码无效或已被使用'}), 400
            
            # 计算过期时间
            expiry_date = None
            if activation_code.duration_seconds > 0:
                expiry_date = datetime.now() + timedelta(seconds=activation_code.duration_seconds)
            
            activation_code_id = activation_code.id
        
        # 如果Emby已配置，先在Emby中创建用户
        # 邮箱注册的用户（未激活）应该在Emby中被禁用
        emby_user_should_disabled = is_email_register  # 邮箱注册的用户默认禁用，直到激活
        emby_user_id = None
        if EmbyAPI.is_configured():
            emby_user_id = EmbyAPI.create_user(username, password, is_disabled=emby_user_should_disabled)
            if not emby_user_id:
                logger.warning(f"在Emby中创建用户失败: {username}")
                # 继续创建本地用户，但记录警告
            else:
                logger.info(f"在Emby中创建用户成功: {username}, ID: {emby_user_id}, is_disabled: {emby_user_should_disabled}")
        
        # 创建用户
        # 邮箱注册的用户默认在Emby中被禁用，同步标记Emby访问已禁用
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=UserRole.USER,
            is_active=True,
            expiry_date=expiry_date,
            emby_user_id=emby_user_id,
            email=email if is_email_register else None,
            email_verified=is_email_register,
            emby_access_disabled=emby_user_should_disabled
        )
        db.add(user)
        db.flush()
        
        # 处理激活码或邮箱验证码的后续操作
        if is_email_register:
            # 更新验证码的用户ID
            verification.user_id = user.id
            logger.info(f"新用户邮箱注册: {username}, email: {email}")
        else:
            # 标记激活码已使用
            activation_code.is_used = True
            activation_code.used_by = user.id
            activation_code.used_at = datetime.utcnow()
            
            # 使用直接SQL更新，确保激活码状态被正确写入
            from sqlalchemy import text
            db.execute(text("UPDATE activation_codes SET is_used = 1, used_by = :user_id, used_at = :used_at WHERE code = :code"), 
                      {"user_id": user.id, "used_at": datetime.now(), "code": code})
            logger.info(f"新用户激活码注册: {username}, Emby ID: {emby_user_id}")
        
        # 为新用户自动分配 WebDAV
        try:
            assign_webdav_to_user(user, db)
        except Exception as e:
            logger.warning(f"新用户 WebDAV 分配失败: {username}, 错误: {e}")
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': '注册成功',
            'data': {
                'id': user.id,
                'username': user.username,
                'expiry_date': expiry_date.isoformat() if expiry_date else None,
                'email': user.email,
                'email_verified': user.email_verified,
                'register_type': 'email' if is_email_register else 'activation_code'
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"注册失败: {e}")
        return jsonify({'success': False, 'message': f'注册失败: {str(e)}'}), 500
    finally:
        db.close()

# ============== 管理员 API ==============
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    db = get_db()
    try:
        users = db.query(User).all()
        # 添加日志查看每个用户的状态
        for user in users:
            logger.info(f"[api_admin_users] 用户 {user.username}: is_active={user.is_active}, expiry_date={user.expiry_date}")
        users_data = [user.to_dict() for user in users]
        # 记录返回给前端的数据
        for user_data in users_data:
            logger.info(f"[api_admin_users返回] 用户 {user_data['username']}: is_active={user_data['is_active']}, expiry_date={user_data['expiry_date']}")
        return jsonify({
            'success': True,
            'data': users_data
        })
    finally:
        db.close()

@app.route('/api/admin/users/delete', methods=['POST'])
@admin_required
def api_admin_users_delete():
    data = request.get_json()
    user_ids = data.get('user_ids', [])

    if not user_ids:
        return jsonify({'success': False, 'message': '请选择要删除的用户'}), 400

    db = get_db()
    try:
        deleted_count = 0
        emby_deleted_count = 0
        emby_failed_users = []
        deleted_user_ids = []

        for user_id in user_ids:
            user = db.query(User).get(user_id)
            if user and user.role != UserRole.ADMIN:
                # 先删除Emby用户
                if user.emby_user_id and EmbyAPI.is_configured():
                    if EmbyAPI.delete_user(user.emby_user_id):
                        emby_deleted_count += 1
                        logger.info(f"已删除Emby用户: {user.username}")
                    else:
                        emby_failed_users.append(user.username)
                        logger.warning(f"删除Emby用户失败: {user.username}")

                # 记录要删除的用户ID
                deleted_user_ids.append(user_id)
                deleted_count += 1

        # 逐个删除用户，确保数据被正确删除
        if deleted_user_ids:
            from sqlalchemy import text
            for uid in deleted_user_ids:
                # 先删除关联的观看历史记录
                db.execute(text("DELETE FROM watch_history WHERE user_id = :user_id"),
                          {"user_id": uid})
                # 再删除关联的登录日志
                db.execute(text("DELETE FROM login_logs WHERE user_id = :user_id"),
                          {"user_id": uid})
                # 最后删除用户
                db.execute(text("DELETE FROM users WHERE id = :user_id"),
                          {"user_id": uid})
            db.commit()

        message = f'成功删除{deleted_count}个用户'
        if emby_deleted_count > 0:
            message += f'，其中{emby_deleted_count}个Emby用户已同步删除'
        if emby_failed_users:
            message += f'。以下用户的Emby账号删除失败: {", ".join(emby_failed_users)}'

        logger.info(f"批量删除用户: {deleted_count}个，Emby删除: {emby_deleted_count}个")
        return jsonify({'success': True, 'message': message})
    except Exception as e:
        db.rollback()
        logger.error(f"删除用户失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/users/add', methods=['POST'])
@admin_required
def api_admin_users_add():
    """管理员手动添加用户"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip() if data.get('email') else ''
    webdav_server_id = data.get('webdav_server_id')  # None表示自动分配
    remark = data.get('remark', '').strip() if data.get('remark') else ''

    # 验证必填字段
    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码为必填项'}), 400

    if len(username) < 3 or len(username) > 20:
        return jsonify({'success': False, 'message': '用户名长度3-20位'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': '密码至少6位'}), 400

    db = get_db()
    try:
        # 检查用户名是否已存在
        if db.query(User).filter_by(username=username).first():
            return jsonify({'success': False, 'message': '用户名已存在'}), 400

        # 检查邮箱是否已被使用
        if email and db.query(User).filter_by(email=email).first():
            return jsonify({'success': False, 'message': '该邮箱已被注册'}), 400

        # 管理员添加的用户初始状态为过期（需要后续续期）
        expiry_date = datetime.now()

        # 在Emby中创建用户（如果Emby已配置）
        emby_user_id = None
        if EmbyAPI.is_configured():
            emby_user_id = EmbyAPI.create_user(username, password, is_disabled=True)
            if not emby_user_id:
                logger.warning(f"在Emby中创建用户失败: {username}")
            else:
                logger.info(f"在Emby中创建用户成功: {username}, ID: {emby_user_id}")

        # 创建用户
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=UserRole.USER,
            is_active=True,
            expiry_date=expiry_date,
            emby_user_id=emby_user_id,
            email=email if email else None,
            email_verified=False,
            emby_access_disabled=True  # 初始状态禁用Emby访问
        )
        db.add(user)
        db.flush()

        # 为新用户分配 WebDAV
        try:
            if webdav_server_id:
                # 指定WebDAV服务器
                server = db.query(WebDAVServer).get(webdav_server_id)
                if server:
                    assign_webdav_to_user(user, db, server_id=server.id)
                else:
                    logger.warning(f"指定的WebDAV服务器不存在: {webdav_server_id}")
                    assign_webdav_to_user(user, db)
            else:
                # 自动分配
                assign_webdav_to_user(user, db)
        except Exception as e:
            logger.warning(f"新用户 WebDAV 分配失败: {username}, 错误: {e}")

        db.commit()

        logger.info(f"管理员添加新用户: {username}, ID: {user.id}")

        return jsonify({
            'success': True,
            'message': '用户添加成功',
            'data': user.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"添加用户失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': f'添加失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/users/renew', methods=['POST'])
@admin_required
def api_admin_users_renew():
    data = request.get_json()
    user_id = data.get('user_id')
    duration_type = data.get('duration_type')
    duration_seconds = data.get('duration_seconds')  # 支持直接传入秒数
    
    if not user_id or not duration_type:
        return jsonify({'success': False, 'message': '参数不完整'}), 400
    
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        # 检查用户是否被禁用
        if not user.is_active:
            return jsonify({'success': False, 'message': '用户已被禁用，请先启用用户后再续期'}), 403
        
        # 处理立即到期（expired 类型）
        if duration_type == 'expired':
            # 将过期时间设置为当前时间，使用户立即过期
            # 注意：不修改is_active，用户仍可登录系统进行续期
            now = datetime.now()
            old_is_active = user.is_active  # 记录旧的is_active值
            logger.info(f"[立即到期前] 用户 {user.username}: is_active={old_is_active}")
            
            user.expiry_date = now
            # 注意：不修改is_active

            # 禁用Emby用户（但不禁用系统登录）
            if user.emby_user_id and EmbyAPI.is_configured():
                if EmbyAPI.disable_user(user.emby_user_id):
                    user.emby_access_disabled = True

            # 提交更改
            db.commit()

            # 同步禁用 WebDAV
            try:
                sync_webdav_user_status(user, False, db)
            except Exception as e:
                logger.error(f"立即到期时同步 WebDAV 状态失败: {user.username}, 错误: {e}")

            # 使用直接SQL更新，确保expiry_date、is_active和emby_access_disabled被正确写入
            from sqlalchemy import text
            db.execute(text("UPDATE users SET expiry_date = :expiry_date, is_active = :is_active, emby_access_disabled = 1 WHERE id = :user_id"),
                      {"expiry_date": now, "is_active": 1 if old_is_active else 0, "user_id": user_id})
            db.commit()

            # 重新查询用户获取最新数据
            db.expire_all()
            user = db.query(User).get(user_id)
            
            logger.info(f"[立即到期后] 用户 {user.username}: is_active={user.is_active}, expiry_date={user.expiry_date}")
            return jsonify({
                'success': True,
                'message': '用户已设置为立即到期，用户仍可登录系统进行续期',
                'data': user.to_dict()
            })
        
        # 获取续期秒数
        if duration_seconds is not None:
            # 优先使用传入的秒数
            duration = int(duration_seconds)
        else:
            # 从 duration_type 转换
            try:
                duration_enum = DurationType(duration_type)
                duration = get_duration_seconds(duration_enum)
            except ValueError:
                return jsonify({'success': False, 'message': '无效的时长类型'}), 400
        
        if duration == 0:  # 永久
            user.expiry_date = None
            logger.info(f"[续期] 用户 {user.username}: 设置为永久有效")
        else:
            # 从原过期时间基础上延长（如果存在过期时间且未过期）
            if user.expiry_date:
                now = datetime.now()
                old_expiry = user.expiry_date
                if user.expiry_date > now:
                    # 原过期时间还未过期，在原有过期时间基础上延长
                    user.expiry_date = user.expiry_date + timedelta(seconds=duration)
                    logger.info(f"[续期] 用户 {user.username}: 原过期时间 {old_expiry} 未过期，延长 {duration} 秒，新过期时间 {user.expiry_date}")
                else:
                    # 原过期时间已过期（如管理员设置的立即到期），从当前时间开始计算
                    user.expiry_date = now + timedelta(seconds=duration)
                    logger.info(f"[续期] 用户 {user.username}: 原过期时间 {old_expiry} 已过期，从当前时间 {now} 开始计算，新过期时间 {user.expiry_date}")
            else:
                # 没有过期时间（可能是首次激活或永久用户），从当前时间开始
                user.expiry_date = datetime.now() + timedelta(seconds=duration)
                logger.info(f"[续期] 用户 {user.username}: 无原过期时间，从当前时间开始计算，新过期时间 {user.expiry_date}")
        
        # 启用用户（仅当不是手动禁用时）
        user.is_active = True
        user.emby_access_disabled = False  # 用户已续期，清除Emby访问禁用标记

        # 启用Emby用户
        if user.emby_user_id and EmbyAPI.is_configured():
            EmbyAPI.enable_user(user.emby_user_id)

        # 同步启用 WebDAV
        try:
            sync_webdav_user_status(user, True, db)
        except Exception as e:
            logger.error(f"续期时同步 WebDAV 状态失败: {user.username}, 错误: {e}")

        # 使用直接SQL更新，确保expiry_date、is_active和emby_access_disabled被正确写入
        from sqlalchemy import text
        db.commit()
        if user.expiry_date:
            db.execute(text("UPDATE users SET expiry_date = :expiry_date, is_active = 1, emby_access_disabled = 0 WHERE id = :user_id"),
                      {"expiry_date": user.expiry_date, "user_id": user_id})
        else:
            db.execute(text("UPDATE users SET expiry_date = NULL, is_active = 1, emby_access_disabled = 0 WHERE id = :user_id"),
                      {"user_id": user_id})
        db.commit()
        
        logger.info(f"用户续期: {user.username}, 时长: {duration}秒")
        
        return jsonify({
            'success': True,
            'message': '续期成功',
            'data': user.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"续期失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': f'续期失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/users/toggle', methods=['POST'])
@admin_required
def api_admin_users_toggle():
    """
    设置用户启用状态（完全手动控制）
    前端直接传递期望的状态，后端直接设置
    """
    data = request.get_json()
    user_id = data.get('user_id')
    new_status = data.get('is_active')  # 前端直接传递期望的状态
    
    logger.info(f"[api_admin_users_toggle] 收到请求: user_id={user_id}, new_status={new_status}, type={type(new_status)}")
    
    if user_id is None or new_status is None:
        return jsonify({'success': False, 'message': '参数不完整'}), 400
    
    # 确保 new_status 是布尔值
    if isinstance(new_status, str):
        new_status = new_status.lower() == 'true'
    new_status = bool(new_status)
    
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            logger.error(f"[api_admin_users_toggle] 用户不存在: user_id={user_id}")
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        logger.info(f"[api_admin_users_toggle] 当前用户状态: username={user.username}, is_active={user.is_active}")
        
        if user.role == UserRole.ADMIN:
            return jsonify({'success': False, 'message': '不能禁用管理员'}), 403
        
        # 直接设置新状态
        try:
            if new_status:
                # ===== 启用用户 =====
                logger.info(f"[api_admin_users_toggle] 正在启用用户 {user.username}")
                # 尝试更新 disabled_at（如果字段存在）
                try:
                    if user.expiry_date:
                        disabled_duration = datetime.now() - (user.disabled_at or datetime.now())
                        user.expiry_date = user.expiry_date + disabled_duration
                    user.disabled_at = None
                except Exception as e:
                    logger.warning(f"[api_admin_users_toggle] 更新 disabled_at 失败（可能字段不存在）: {e}")
                
            else:
                # ===== 禁用用户 =====
                logger.info(f"[api_admin_users_toggle] 正在禁用用户 {user.username}")
                try:
                    user.disabled_at = datetime.now()
                except Exception as e:
                    logger.warning(f"[api_admin_users_toggle] 设置 disabled_at 失败（可能字段不存在）: {e}")
            
            # 更新启用状态
            user.is_active = new_status
            logger.info(f"[api_admin_users_toggle] 已设置 is_active={new_status}")
            
        except Exception as e:
            logger.error(f"[api_admin_users_toggle] 设置状态时出错: {e}")
            raise
        
        # 同步Emby用户状态
        if user.emby_user_id and EmbyAPI.is_configured():
            # 只有在用户未过期时才启用Emby
            if user.is_active and not user.is_expired():
                user.emby_access_disabled = False  # 清除标记，允许正常访问
                EmbyAPI.enable_user(user.emby_user_id)
            else:
                # 用户已过期或被禁用，禁用Emby访问
                if EmbyAPI.disable_user(user.emby_user_id):
                    user.emby_access_disabled = True  # 设置标记，避免调度器重复禁用

        # 同步 WebDAV 用户状态
        try:
            webdav_enabled = user.is_active and not user.is_expired()
            sync_webdav_user_status(user, webdav_enabled, db)
        except Exception as e:
            logger.error(f"切换用户状态时同步 WebDAV 失败: {user.username}, 错误: {e}")

        # 使用直接SQL更新，确保数据写入
        try:
            from sqlalchemy import text
            # 先提交ORM更改
            db.commit()
            # 然后使用直接SQL更新is_active和emby_access_disabled，确保写入
            # 用户被启用且未过期时清除标记；被禁用或已过期时设置标记
            emby_disabled_flag = 0 if (user.is_active and not user.is_expired()) else 1
            db.execute(text("UPDATE users SET is_active = :status, emby_access_disabled = :emby_disabled WHERE id = :user_id"),
                      {"status": 1 if new_status else 0, "emby_disabled": emby_disabled_flag, "user_id": user_id})
            db.commit()
            logger.info(f"[api_admin_users_toggle] 数据库提交成功")
        except Exception as e:
            logger.error(f"[api_admin_users_toggle] 数据库提交失败: {e}")
            db.rollback()
            raise
        
        status = '启用' if user.is_active else '禁用'
        logger.info(f"[api_admin_users_toggle] 用户状态变更成功: {user.username} -> {status}, is_active={user.is_active}")
        
        return jsonify({
            'success': True,
            'message': f'已{status}',
            'data': user.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"[api_admin_users_toggle] 切换用户状态失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': f'操作失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/users/test', methods=['POST'])
@admin_required
def api_admin_users_test():
    """测试API - 直接设置用户状态"""
    data = request.get_json()
    user_id = data.get('user_id')
    new_status = data.get('is_active')
    
    logger.info(f"[api_admin_users_test] 收到测试请求: user_id={user_id}, new_status={new_status}")
    
    if user_id is None or new_status is None:
        return jsonify({'success': False, 'message': '参数不完整'}), 400
    
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        logger.info(f"[api_admin_users_test] 当前状态: username={user.username}, is_active={user.is_active}")
        
        # 直接设置状态
        user.is_active = new_status
        
        if new_status:
            user.disabled_at = None
        else:
            user.disabled_at = datetime.now()
        
        db.commit()
        
        logger.info(f"[api_admin_users_test] 新状态: is_active={user.is_active}")
        
        return jsonify({
            'success': True,
            'message': f'已{"启用" if new_status else "禁用"}',
            'data': user.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"[api_admin_users_test] 失败: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

# 管理员刷新所有用户观看记录
@app.route('/api/admin/sync-all-history', methods=['POST'])
@admin_required
def api_admin_sync_all_history():
    """刷新所有用户的观看记录"""
    if not EmbyAPI.is_configured():
        return jsonify({'success': False, 'message': 'Emby未配置，无法同步'}), 400
    
    db = get_db()
    try:
        # 获取所有有Emby用户ID的用户
        users = db.query(User).filter(
            and_(
                User.emby_user_id != None,
                User.emby_user_id != '',
                User.role == UserRole.USER
            )
        ).all()
        
        synced_count = 0
        failed_count = 0
        total_records = 0
        
        for user in users:
            try:
                # 先同步活跃播放会话
                user_sessions = EmbyAPI.get_active_sessions()
                if user_sessions:
                    # 过滤出该用户的会话
                    user_active = [s for s in user_sessions if s.get('UserId') == user.emby_user_id]
                    for session in user_active:
                        now_playing = session.get('NowPlayingItem', {})
                        play_state = session.get('PlayState', {})
                        
                        item_name = now_playing.get('Name', '未知影片')
                        position_ticks = play_state.get('PositionTicks', 0)
                        duration_seconds = position_ticks // 10000000 if position_ticks > 0 else 0
                        
                        now = datetime.now()
                        end_time = now
                        start_time = now - timedelta(seconds=duration_seconds) if duration_seconds > 0 else now
                        
                        existing = db.query(WatchHistory).filter_by(
                            user_id=user.id,
                            item_name=item_name
                        ).first()
                        
                        if existing:
                            existing.item_name = item_name
                            existing.start_time = start_time
                            existing.end_time = end_time
                            existing.duration = duration_seconds
                            total_records += 1
                        else:
                            watch_record = WatchHistory(
                                user_id=user.id,
                                item_name=item_name,
                                start_time=start_time,
                                end_time=end_time,
                                duration=duration_seconds
                            )
                            db.add(watch_record)
                            total_records += 1
                
                # 同步历史观看记录
                success = EmbyAPI.sync_user_watch_history_improved(user.id, user.emby_user_id)
                if success:
                    synced_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                failed_count += 1
                logger.error(f"同步用户 {user.username} 的观看历史失败: {e}")
        
        db.commit()
        
        logger.info(f"管理员刷新观看记录完成，同步 {synced_count} 个用户，失败 {failed_count} 个，共 {total_records} 条活跃记录")
        
        return jsonify({
            'success': True,
            'message': f'刷新完成！同步了 {synced_count} 个用户的观看记录',
            'synced_count': synced_count,
            'failed_count': failed_count,
            'active_records': total_records
        })
    except Exception as e:
        db.rollback()
        logger.error(f"刷新观看记录失败: {e}")
        return jsonify({'success': False, 'message': f'刷新失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/users/<int:user_id>/history', methods=['GET'])
@admin_required
def api_admin_user_history(user_id):
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        # 优先从Emby获取最新的观看历史
        emby_history_items = []
        if user.emby_user_id and EmbyAPI.is_configured():
            try:
                emby_data = EmbyAPI.get_user_watch_history(user.emby_user_id)
                if emby_data and 'Items' in emby_data:
                    emby_history_items = emby_data['Items']
                    # 同步到本地数据库
                    EmbyAPI.sync_user_watch_history(user.id, user.emby_user_id)
            except Exception as e:
                logger.error(f"从Emby获取用户 {user_id} 观看历史失败: {e}")
        
        # 从本地数据库获取（已包含同步后的数据）
        history = db.query(WatchHistory).filter_by(user_id=user_id).order_by(WatchHistory.start_time.desc()).all()
        
        # 如果本地没有数据但Emby有数据，使用Emby数据
        if not history and emby_history_items:
            # 格式化Emby数据返回
            formatted_history = []
            for item in emby_history_items[:50]:  # 最多返回50条
                item_name = item.get('Name', '未知影片')
                date_played = item.get('DatePlayed')
                start_time = None
                if date_played:
                    try:
                        start_time = datetime.fromisoformat(date_played.replace('Z', '+00:00')).replace(tzinfo=None)
                    except:
                        start_time = datetime.now()
                else:
                    start_time = datetime.now()
                
                runtime_ticks = item.get('RunTimeTicks', 0)
                duration = runtime_ticks // 10000000 if runtime_ticks else 0
                
                formatted_history.append({
                    'id': item.get('Id', ''),
                    'item_name': item_name,
                    'start_time': start_time.isoformat() if start_time else None,
                    'end_time': None,
                    'duration': duration,
                    'user_id': user_id
                })
            return jsonify({
                'success': True,
                'data': formatted_history
            })
        
        return jsonify({
            'success': True,
            'data': [h.to_dict() for h in history]
        })
    finally:
        db.close()

@app.route('/api/admin/users/<int:user_id>/sync-to-emby', methods=['POST'])
@admin_required
def api_admin_user_sync_to_emby(user_id):
    """将用户同步到Emby媒体库"""
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        if not EmbyAPI.is_configured():
            return jsonify({'success': False, 'message': 'Emby服务器未配置'}), 400
        
        if user.emby_user_id:
            return jsonify({'success': False, 'message': '用户已同步到Emby'}), 400
        
        # 在Emby中创建用户
        # 使用默认密码 '123456'，用户需要通过Emby修改密码
        emby_user_id = EmbyAPI.create_user(user.username, '123456')
        
        if not emby_user_id:
            return jsonify({'success': False, 'message': '在Emby中创建用户失败'}), 500
        
        # 如果用户已过期或禁用，同步禁用状态
        if not user.is_active or user.is_expired():
            if EmbyAPI.disable_user(emby_user_id):
                user.emby_access_disabled = True  # 设置标记，避免调度器重复禁用
        else:
            user.emby_access_disabled = False  # 用户正常，清除禁用标记

        # 更新用户的emby_user_id
        user.emby_user_id = emby_user_id
        db.commit()
        
        logger.info(f"用户已同步到Emby: {user.username}, Emby ID: {emby_user_id}")
        
        return jsonify({
            'success': True,
            'message': '用户已同步到Emby',
            'data': user.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"同步用户到Emby失败: {e}")
        return jsonify({'success': False, 'message': f'同步失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/codes/generate', methods=['POST'])
@admin_required
def api_admin_codes_generate():
    data = request.get_json()
    duration_type = data.get('duration_type')
    count = data.get('count', 1)
    custom_seconds = data.get('custom_seconds')  # 自定义秒数
    
    if not duration_type:
        return jsonify({'success': False, 'message': '请选择时长类型'}), 400
    
    # 处理自定义秒数情况
    if duration_type == 'CUSTOM':
        if not custom_seconds or custom_seconds < 1:
            return jsonify({'success': False, 'message': '请输入有效的自定义秒数'}), 400
        duration_enum = DurationType.PERMANENT  # 使用PERMANENT作为自定义的标记
        duration_seconds = custom_seconds
    else:
        # 将前端大写值映射到枚举
        duration_type_map = {
            'HOUR': DurationType.HOUR,
            'DAY': DurationType.DAY,
            'WEEK': DurationType.WEEK,
            'MONTH': DurationType.MONTH,
            'YEAR': DurationType.YEAR,
            'PERMANENT': DurationType.PERMANENT,
            # 也支持小写
            'hour': DurationType.HOUR,
            'day': DurationType.DAY,
            'week': DurationType.WEEK,
            'month': DurationType.MONTH,
            'year': DurationType.YEAR,
            'permanent': DurationType.PERMANENT
        }
        
        duration_enum = duration_type_map.get(duration_type)
        if not duration_enum:
            return jsonify({'success': False, 'message': f'无效的时长类型: {duration_type}'}), 400
        
        duration_seconds = get_duration_seconds(duration_enum)
    
    if count < 1 or count > 100:
        return jsonify({'success': False, 'message': '生成数量1-100'}), 400
    
    db = get_db()
    try:
        codes = []
        for _ in range(count):
            code_str = generate_activation_code()
            # 确保唯一
            while db.query(ActivationCode).filter_by(code=code_str).first():
                code_str = generate_activation_code()
            
            code = ActivationCode(
                code=code_str,
                duration_type=duration_enum,
                duration_seconds=duration_seconds,
                is_used=False
            )
            db.add(code)
            codes.append(code)
        
        db.commit()
        
        logger.info(f"生成激活码: {count}个, 类型: {duration_type}, 秒数: {duration_seconds}")
        
        return jsonify({
            'success': True,
            'message': f'成功生成{count}个激活码',
            'data': [c.to_dict() for c in codes]
        })
    except Exception as e:
        db.rollback()
        logger.error(f"生成激活码失败: {e}")
        return jsonify({'success': False, 'message': f'生成失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/codes', methods=['GET'])
@admin_required
def api_admin_codes():
    db = get_db()
    try:
        codes = db.query(ActivationCode).order_by(ActivationCode.created_at.desc()).all()
        
        # 构建响应数据，包含使用者用户名
        codes_data = []
        for code in codes:
            code_dict = code.to_dict()
            # 添加使用者用户名
            if code.used_by:
                user = db.query(User).get(code.used_by)
                code_dict['used_by_username'] = user.username if user else None
            else:
                code_dict['used_by_username'] = None
            codes_data.append(code_dict)
        
        return jsonify({
            'success': True,
            'data': codes_data
        })
    finally:
        db.close()

@app.route('/api/admin/codes/delete', methods=['POST'])
@admin_required
def api_admin_codes_delete():
    data = request.get_json()
    code_ids = data.get('code_ids', [])
    
    if not code_ids:
        return jsonify({'success': False, 'message': '请选择要删除的激活码'}), 400
    
    db = get_db()
    try:
        deleted_count = 0
        for code_id in code_ids:
            code = db.query(ActivationCode).get(code_id)
            if code:
                db.delete(code)
                deleted_count += 1
        
        db.commit()
        logger.info(f"批量删除激活码: {deleted_count}个")
        return jsonify({'success': True, 'message': f'成功删除{deleted_count}个激活码'})
    except Exception as e:
        db.rollback()
        logger.error(f"删除激活码失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/emby/test', methods=['POST'])
@admin_required
def api_admin_emby_test():
    """测试Emby连接"""
    data = request.get_json()
    server_url = data.get('server_url', '').strip()
    api_key = data.get('api_key', '').strip()
    
    if not server_url or not api_key:
        return jsonify({'success': False, 'message': '请填写完整信息'}), 400
    
    # 确保URL格式正确
    if server_url.endswith('/'):
        server_url = server_url[:-1]
    
    try:
        headers = {'X-Emby-Token': api_key}
        test_url = f"{server_url}/emby/System/Info"
        response = requests.get(test_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return jsonify({
                'success': True,
                'message': '连接成功',
                'data': response.json()
            })
        elif response.status_code == 401:
            return jsonify({'success': False, 'message': 'API密钥无效，请检查密钥是否正确'}), 400
        else:
            return jsonify({'success': False, 'message': f'连接失败，HTTP状态码: {response.status_code}'}), 400
    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'message': '连接超时，请检查服务器地址是否正确'}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({'success': False, 'message': '无法连接到服务器，请检查地址和端口'}), 400
    except Exception as e:
        logger.error(f"测试Emby连接失败: {e}")
        return jsonify({'success': False, 'message': f'连接失败: {str(e)}'}), 400

@app.route('/api/admin/emby/bind', methods=['POST'])
@admin_required
def api_admin_emby_bind():
    data = request.get_json()
    server_url = data.get('server_url', '').strip()
    api_key = data.get('api_key', '').strip()
    
    if not server_url or not api_key:
        return jsonify({'success': False, 'message': '请填写完整信息'}), 400
    
    # 确保URL格式正确
    if server_url.endswith('/'):
        server_url = server_url[:-1]
    
    # 测试连接
    try:
        headers = {'X-Emby-Token': api_key}
        test_url = f"{server_url}/emby/System/Info"
        response = requests.get(test_url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return jsonify({'success': False, 'message': '连接失败，请检查配置'}), 400
        
        # 保存配置
        set_config('emby_server_url', server_url)
        set_config('emby_api_key', api_key)
        
        # 同步用户
        EmbyAPI.sync_users()
        
        logger.info("Emby服务器绑定成功")
        
        return jsonify({
            'success': True,
            'message': '绑定成功',
            'data': response.json()
        })
    except Exception as e:
        logger.error(f"绑定Emby失败: {e}")
        return jsonify({'success': False, 'message': f'连接失败: {str(e)}'}), 400

@app.route('/api/admin/emby/config', methods=['GET'])
@admin_required
def api_admin_emby_config():
    return jsonify({
        'success': True,
        'data': {
            'server_url': get_config('emby_server_url', ''),
            'api_key': '***' if get_config('emby_api_key') else ''
        }
    })

@app.route('/api/admin/emby/sync-users', methods=['POST'])
@admin_required
def api_admin_emby_sync_users():
    """手动同步Emby用户"""
    if not EmbyAPI.is_configured():
        return jsonify({'success': False, 'message': 'Emby服务器未配置'}), 400
    
    try:
        result = EmbyAPI.sync_users()
        if result:
            # 获取同步后的用户数量
            db = get_db()
            try:
                user_count = db.query(User).filter(User.role == UserRole.USER).count()
                return jsonify({
                    'success': True,
                    'message': f'已同步 {user_count} 个用户',
                    'data': {'user_count': user_count}
                })
            finally:
                db.close()
        else:
            return jsonify({'success': False, 'message': '同步失败，请检查Emby服务器连接'}), 500
    except Exception as e:
        logger.error(f"手动同步用户失败: {e}")
        return jsonify({'success': False, 'message': f'同步失败: {str(e)}'}), 500

@app.route('/api/admin/emby/unbind', methods=['POST'])
@admin_required
def api_admin_emby_unbind():
    """解绑Emby媒体库并清空所有用户数据"""
    data = request.get_json()
    confirm = data.get('confirm', False)
    
    if not confirm:
        return jsonify({'success': False, 'message': '请确认解绑操作'}), 400
    
    db = get_db()
    try:
        # 1. 清除Emby配置
        set_config('emby_server_url', '')
        set_config('emby_api_key', '')
        
        # 2. 删除所有普通用户（保留管理员）
        users_to_delete = db.query(User).filter(User.role == UserRole.USER).all()
        deleted_user_count = len(users_to_delete)
        for user in users_to_delete:
            db.delete(user)
        
        # 3. 删除所有观看历史记录
        try:
            watch_history_deleted = db.query(WatchHistory).delete()
        except:
            watch_history_deleted = 0
        
        # 4. 删除所有激活码
        try:
            activation_codes_deleted = db.query(ActivationCode).delete()
        except:
            activation_codes_deleted = 0
        
        # 5. 删除所有登录日志（保留管理员的）
        try:
            admin_users = db.query(User).filter(User.role == UserRole.ADMIN).all()
            admin_ids = [u.id for u in admin_users]
            if admin_ids:
                login_logs_deleted = db.query(LoginLog).filter(~LoginLog.user_id.in_(admin_ids)).delete(synchronize_session=False)
            else:
                login_logs_deleted = db.query(LoginLog).delete()
        except:
            login_logs_deleted = 0
        
        db.commit()
        
        logger.info(f"Emby媒体库已解绑，删除了 {deleted_user_count} 个用户, {watch_history_deleted} 条观看记录, {activation_codes_deleted} 个激活码")
        
        return jsonify({
            'success': True,
            'message': f'解绑成功！已清空 {deleted_user_count} 个用户、{watch_history_deleted} 条观看记录、{activation_codes_deleted} 个激活码',
            'data': {
                'deleted_users': deleted_user_count,
                'deleted_watch_history': watch_history_deleted,
                'deleted_activation_codes': activation_codes_deleted
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"解绑Emby失败: {e}")
        return jsonify({'success': False, 'message': f'解绑失败: {str(e)}'}), 500
    finally:
        db.close()

# ============== WebDAV 管理接口 ==============

def _parse_quota_bytes(value):
    """将容量字符串解析为字节数，支持 GB/TB/MB 等后缀"""
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)):
        return int(value)
    value = str(value).strip().upper().replace(' ', '')
    if not value:
        return None
    multipliers = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024 ** 2,
        'MB': 1024 ** 2,
        'G': 1024 ** 3,
        'GB': 1024 ** 3,
        'T': 1024 ** 4,
        'TB': 1024 ** 4,
        'P': 1024 ** 5,
        'PB': 1024 ** 5,
    }
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if value.endswith(suffix):
            try:
                return int(float(value[:-len(suffix)]) * mult)
            except ValueError:
                return None
    try:
        return int(float(value))
    except ValueError:
        return None


def _format_quota_bytes(bytes_value):
    """将字节数格式化为人类可读字符串"""
    if bytes_value is None:
        return None
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    size = float(bytes_value)
    unit_idx = 0
    while size >= 1024 and unit_idx < len(units) - 1:
        size /= 1024
        unit_idx += 1
    if unit_idx == 0:
        return f"{int(size)} {units[unit_idx]}"
    return f"{size:.2f} {units[unit_idx]}"


@app.route('/api/admin/webdav/servers', methods=['GET'])
@admin_required
def api_get_webdav_servers():
    """获取所有 WebDAV 服务器"""
    db = get_db()
    try:
        servers = db.query(WebDAVServer).order_by(WebDAVServer.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [s.to_dict() for s in servers]
        })
    except Exception as e:
        logger.error(f"获取 WebDAV 服务器列表失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/servers', methods=['POST'])
@admin_required
def api_add_webdav_server():
    """添加 WebDAV 服务器"""
    data = request.get_json()
    name = (data.get('name') or '').strip()
    server_url = (data.get('server_url') or '').strip()
    server_type = (data.get('server_type') or 'generic').strip().lower()
    admin_username = (data.get('admin_username') or '').strip() or None
    admin_password = (data.get('admin_password') or '').strip() or None
    root_path = (data.get('root_path') or '').strip()
    default_quota = _parse_quota_bytes(data.get('default_quota_bytes'))

    if not name or not server_url:
        return jsonify({'success': False, 'message': '名称和服务器地址不能为空'}), 400

    if server_type not in _WEBDAV_PROVIDERS:
        return jsonify({'success': False, 'message': '不支持的 WebDAV 类型'}), 400

    # 规范化 URL 和根路径
    server_url = server_url.rstrip('/')
    root_path = root_path.strip('/')

    # 保存前先使用明文密码测试连接
    test_server = WebDAVServer(
        name=name,
        server_url=server_url,
        server_type=server_type,
        admin_username=admin_username,
        admin_password=admin_password,
        root_path=root_path,
        default_quota_bytes=default_quota,
        is_active=data.get('is_active', True)
    )
    try:
        provider = get_webdav_provider(test_server)
        if not provider.test_connection():
            return jsonify({'success': False, 'message': '连接测试失败，请检查服务器地址、账号和密码是否正确'}), 400
    except Exception as e:
        logger.error(f"添加 WebDAV 服务器前连接测试异常: {e}")
        return jsonify({'success': False, 'message': f'连接测试异常: {str(e)}'}), 400

    db = SessionLocal()
    try:
        server = WebDAVServer(
            name=name,
            server_url=server_url,
            server_type=server_type,
            admin_username=admin_username,
            admin_password=encrypt_webdav_password(admin_password) if admin_password else None,
            root_path=root_path,
            default_quota_bytes=default_quota,
            is_active=data.get('is_active', True)
        )
        db.add(server)
        db.commit()
        db.refresh(server)

        # 如果新添加的服务器已启用，异步为没有分配的用户补分配
        if server.is_active:
            trigger_bulk_assign_webdav_async()

        return jsonify({
            'success': True,
            'message': '添加成功',
            'data': server.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"添加 WebDAV 服务器失败: {e}")
        return jsonify({'success': False, 'message': f'添加失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/servers/<int:server_id>', methods=['PUT'])
@admin_required
def api_update_webdav_server(server_id):
    """编辑 WebDAV 服务器"""
    data = request.get_json()
    db = SessionLocal()
    try:
        server = db.query(WebDAVServer).get(server_id)
        if not server:
            return jsonify({'success': False, 'message': '服务器不存在'}), 404

        old_is_active = server.is_active

        # 先计算新值，不立即写入数据库
        new_name = (data['name'] or '').strip() if 'name' in data else server.name
        new_server_url = (data['server_url'] or '').strip().rstrip('/') if 'server_url' in data else server.server_url
        new_server_type = server.server_type
        if 'server_type' in data:
            new_server_type = (data['server_type'] or '').strip().lower()
            if new_server_type not in _WEBDAV_PROVIDERS:
                return jsonify({'success': False, 'message': '不支持的 WebDAV 类型'}), 400
        new_admin_username = (data['admin_username'] or '').strip() or None if 'admin_username' in data else server.admin_username
        new_root_path = (data['root_path'] or '').strip().strip('/') if 'root_path' in data else server.root_path

        new_admin_password_plain = None
        password_changed = False
        if 'admin_password' in data:
            pwd = (data['admin_password'] or '').strip()
            if pwd and pwd != '***':
                new_admin_password_plain = pwd
                password_changed = True
            elif not pwd:
                new_admin_password_plain = None
                password_changed = True
            else:
                # '***' 表示不修改密码
                new_admin_password_plain = decrypt_webdav_password(server.admin_password)
        else:
            new_admin_password_plain = decrypt_webdav_password(server.admin_password)

        new_is_active = bool(data['is_active']) if 'is_active' in data else server.is_active

        # 检查连接相关字段是否发生变化
        connection_fields_changed = (
            'server_url' in data or
            'server_type' in data or
            'admin_username' in data or
            password_changed
        )

        if connection_fields_changed:
            test_server = WebDAVServer(
                name=new_name,
                server_url=new_server_url,
                server_type=new_server_type,
                admin_username=new_admin_username,
                admin_password=new_admin_password_plain,
                root_path=new_root_path,
                default_quota_bytes=server.default_quota_bytes,
                is_active=new_is_active
            )
            try:
                provider = get_webdav_provider(test_server)
                if not provider.test_connection():
                    return jsonify({'success': False, 'message': '连接测试失败，请检查服务器地址、账号和密码是否正确'}), 400
            except Exception as e:
                logger.error(f"更新 WebDAV 服务器前连接测试异常: {e}")
                return jsonify({'success': False, 'message': f'连接测试异常: {str(e)}'}), 400

        # 测试通过，写入数据库
        server.name = new_name
        server.server_url = new_server_url
        server.server_type = new_server_type
        server.admin_username = new_admin_username
        server.root_path = new_root_path
        if 'admin_password' in data:
            pwd = (data['admin_password'] or '').strip()
            if pwd and pwd != '***':
                server.admin_password = encrypt_webdav_password(pwd)
            elif not pwd:
                server.admin_password = None
        if 'default_quota_bytes' in data:
            server.default_quota_bytes = _parse_quota_bytes(data['default_quota_bytes'])
        if 'is_active' in data:
            server.is_active = new_is_active

        db.commit()
        db.refresh(server)

        # 如果服务器从禁用变为启用，异步为没有分配的用户补分配
        if not old_is_active and server.is_active:
            trigger_bulk_assign_webdav_async()

        return jsonify({
            'success': True,
            'message': '更新成功',
            'data': server.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"更新 WebDAV 服务器失败: {e}")
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/servers/<int:server_id>', methods=['DELETE'])
@admin_required
def api_delete_webdav_server(server_id):
    """解绑/删除 WebDAV 服务器"""
    db = get_db()
    try:
        server = db.query(WebDAVServer).get(server_id)
        if not server:
            return jsonify({'success': False, 'message': '服务器不存在'}), 404

        # 级联删除用户分配（模型 relationship 已配置 cascade）
        db.delete(server)
        db.commit()
        logger.info(f"WebDAV 服务器已删除: {server.name}")
        return jsonify({
            'success': True,
            'message': '删除成功'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"删除 WebDAV 服务器失败: {e}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/servers/<int:server_id>/test', methods=['POST'])
@admin_required
def api_test_webdav_server(server_id):
    """测试 WebDAV 服务器连接"""
    db = get_db()
    try:
        server = db.query(WebDAVServer).get(server_id)
        if not server:
            return jsonify({'success': False, 'message': '服务器不存在'}), 404

        # 解密密码用于测试
        server.admin_password = decrypt_webdav_password(server.admin_password)
        provider = get_webdav_provider(server)
        success = provider.test_connection()

        if success:
            return jsonify({'success': True, 'message': '连接成功'})
        else:
            return jsonify({'success': False, 'message': '连接失败，请检查地址和账号'}), 400
    except Exception as e:
        logger.error(f"测试 WebDAV 连接失败: {e}")
        return jsonify({'success': False, 'message': f'测试失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/servers/<int:server_id>/assignments', methods=['GET'])
@admin_required
def api_get_webdav_server_assignments(server_id):
    """获取某服务器下所有用户分配"""
    db = get_db()
    try:
        server = db.query(WebDAVServer).get(server_id)
        if not server:
            return jsonify({'success': False, 'message': '服务器不存在'}), 404

        assignments = db.query(UserWebDAVAssignment).filter_by(server_id=server_id).all()
        data = []
        for a in assignments:
            item = a.to_dict()
            item['username'] = a.user.username if a.user else None
            item['quota_display'] = _format_quota_bytes(a.quota_bytes)
            data.append(item)
        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        logger.error(f"获取 WebDAV 分配列表失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/users/<int:user_id>/assignments', methods=['GET'])
@admin_required
def api_get_user_webdav_assignments(user_id):
    """获取某用户的 WebDAV 分配"""
    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        assignments = db.query(UserWebDAVAssignment).filter_by(user_id=user_id).all()
        data = []
        for a in assignments:
            item = a.to_dict()
            item['username'] = user.username
            item['quota_display'] = _format_quota_bytes(a.quota_bytes)
            data.append(item)
        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        logger.error(f"获取用户 WebDAV 分配失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/users-without-assignment', methods=['GET'])
@admin_required
def api_get_users_without_webdav_assignment():
    """获取没有 WebDAV 分配的普通用户列表（供手动分配选择）"""
    db = SessionLocal()
    try:
        subquery = select(UserWebDAVAssignment.user_id).where(
            UserWebDAVAssignment.user_id.isnot(None)
        ).distinct()
        users = db.query(User).filter(
            User.role == UserRole.USER,
            ~User.id.in_(subquery)
        ).order_by(User.created_at.desc()).all()

        return jsonify({
            'success': True,
            'data': [{
                'id': u.id,
                'username': u.username,
                'created_at': u.created_at.isoformat() if u.created_at else None
            } for u in users]
        })
    except Exception as e:
        logger.error(f"获取未分配 WebDAV 用户列表失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/assignments', methods=['POST'])
@admin_required
def api_create_webdav_assignment():
    """手动为用户分配 WebDAV 服务器"""
    data = request.get_json()
    user_id = data.get('user_id')
    server_id = data.get('server_id')
    assigned_path = (data.get('assigned_path') or '').strip()
    quota_bytes = _parse_quota_bytes(data.get('quota_bytes'))

    if not user_id or not server_id:
        return jsonify({'success': False, 'message': '用户和服务器不能为空'}), 400

    db = SessionLocal()
    try:
        user = db.query(User).get(user_id)
        server = db.query(WebDAVServer).get(server_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        if not server:
            return jsonify({'success': False, 'message': '服务器不存在'}), 404
        if user.role != UserRole.USER:
            return jsonify({'success': False, 'message': '只能为普通用户分配 WebDAV'}), 400

        existing = db.query(UserWebDAVAssignment).filter_by(user_id=user_id).first()
        if existing:
            return jsonify({'success': False, 'message': '该用户已分配 WebDAV'}), 400

        # 自动生成路径
        if not assigned_path:
            base_path = re.sub(r'[^a-zA-Z0-9_\-]', '_', user.username)
            assigned_path = f"/{base_path}"
            suffix = 1
            while db.query(UserWebDAVAssignment).filter_by(server_id=server.id, assigned_path=assigned_path).first():
                assigned_path = f"/{base_path}_{suffix}"
                suffix += 1
        else:
            assigned_path = assigned_path.strip('/')
            assigned_path = f"/{assigned_path}" if assigned_path else '/'
            conflict = db.query(UserWebDAVAssignment).filter_by(
                server_id=server.id,
                assigned_path=assigned_path
            ).first()
            if conflict:
                return jsonify({'success': False, 'message': '该路径已被其他用户使用'}), 400

        assignment = UserWebDAVAssignment(
            user_id=user.id,
            server_id=server.id,
            assigned_path=assigned_path,
            quota_bytes=quota_bytes,
            is_active=user.is_active and not user.is_expired()
        )
        db.add(assignment)
        db.flush()

        # 调用 Provider 尝试在后端创建用户
        try:
            provider = get_webdav_provider(server)
            provider.create_user(user.username, '', assigned_path)
        except Exception as e:
            logger.warning(f"WebDAV Provider 手动创建用户失败: {user.username}, 错误: {e}")

        db.commit()
        db.refresh(assignment)
        item = assignment.to_dict()
        item['username'] = user.username
        item['quota_display'] = _format_quota_bytes(assignment.quota_bytes)
        return jsonify({
            'success': True,
            'message': '分配成功',
            'data': item
        })
    except Exception as e:
        db.rollback()
        logger.error(f"手动分配 WebDAV 失败: {e}")
        return jsonify({'success': False, 'message': f'分配失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/assignments/<int:assignment_id>', methods=['PUT'])
@admin_required
def api_update_webdav_assignment(assignment_id):
    """编辑用户 WebDAV 分配"""
    data = request.get_json()
    db = get_db()
    try:
        assignment = db.query(UserWebDAVAssignment).get(assignment_id)
        if not assignment:
            return jsonify({'success': False, 'message': '分配不存在'}), 404

        if 'assigned_path' in data:
            new_path = data['assigned_path'].strip().strip('/')
            new_path = f"/{new_path}" if new_path else '/'
            # 检查路径冲突
            conflict = db.query(UserWebDAVAssignment).filter(
                UserWebDAVAssignment.server_id == assignment.server_id,
                UserWebDAVAssignment.assigned_path == new_path,
                UserWebDAVAssignment.id != assignment.id
            ).first()
            if conflict:
                return jsonify({'success': False, 'message': '该路径已被其他用户使用'}), 400
            assignment.assigned_path = new_path
        if 'quota_bytes' in data:
            assignment.quota_bytes = _parse_quota_bytes(data['quota_bytes'])
        if 'is_active' in data:
            assignment.is_active = bool(data['is_active'])
            # 同步到后端 Provider
            try:
                provider = get_webdav_provider(assignment.server)
                if assignment.is_active:
                    provider.enable_user(assignment.user.username)
                else:
                    provider.disable_user(assignment.user.username)
            except Exception as e:
                logger.error(f"同步 WebDAV 分配状态失败: {e}")

        db.commit()
        db.refresh(assignment)
        item = assignment.to_dict()
        item['username'] = assignment.user.username if assignment.user else None
        item['quota_display'] = _format_quota_bytes(assignment.quota_bytes)
        return jsonify({
            'success': True,
            'message': '更新成功',
            'data': item
        })
    except Exception as e:
        db.rollback()
        logger.error(f"更新 WebDAV 分配失败: {e}")
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/admin/webdav/assignments/<int:assignment_id>', methods=['DELETE'])
@admin_required
def api_delete_webdav_assignment(assignment_id):
    """删除用户 WebDAV 分配"""
    db = get_db()
    try:
        assignment = db.query(UserWebDAVAssignment).get(assignment_id)
        if not assignment:
            return jsonify({'success': False, 'message': '分配不存在'}), 404

        db.delete(assignment)
        db.commit()
        return jsonify({
            'success': True,
            'message': '删除成功'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"删除 WebDAV 分配失败: {e}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500
    finally:
        db.close()


# ============== 弹幕API管理接口 ==============

@app.route('/api/admin/danmaku-apis', methods=['GET'])
@admin_required
def api_get_danmaku_apis():
    """获取所有弹幕API配置"""
    db = get_db()
    try:
        apis = db.query(DanmakuAPI).order_by(DanmakuAPI.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [api.to_dict() for api in apis]
        })
    except Exception as e:
        logger.error(f"获取弹幕API列表失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/danmaku-apis', methods=['POST'])
@admin_required
def api_add_danmaku_api():
    """添加弹幕API配置"""
    data = request.get_json()
    name = data.get('name', '').strip()
    url = data.get('url', '').strip()
    description = data.get('description', '').strip()
    is_default = data.get('is_default', False)
    
    if not name or not url:
        return jsonify({'success': False, 'message': '名称和URL不能为空'}), 400
    
    db = get_db()
    try:
        # 如果设置为默认，取消其他默认
        if is_default:
            db.query(DanmakuAPI).filter_by(is_default=True).update({'is_default': False})
        
        api = DanmakuAPI(
            name=name,
            url=url,
            description=description,
            is_default=is_default,
            is_active=True
        )
        db.add(api)
        db.commit()
        
        logger.info(f"管理员添加弹幕API: {name}")
        return jsonify({'success': True, 'message': '添加成功', 'data': api.to_dict()})
    except Exception as e:
        db.rollback()
        logger.error(f"添加弹幕API失败: {e}")
        return jsonify({'success': False, 'message': '添加失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/danmaku-apis/<int:api_id>', methods=['PUT'])
@admin_required
def api_update_danmaku_api(api_id):
    """更新弹幕API配置"""
    data = request.get_json()
    name = data.get('name', '').strip()
    url = data.get('url', '').strip()
    description = data.get('description', '').strip()
    is_default = data.get('is_default', None)
    is_active = data.get('is_active', None)
    
    db = get_db()
    try:
        api = db.query(DanmakuAPI).filter_by(id=api_id).first()
        if not api:
            return jsonify({'success': False, 'message': 'API配置不存在'}), 404
        
        # 只有在提供了名称和URL时才更新（支持部分更新）
        if name:
            api.name = name
        if url:
            api.url = url
        if description is not None:
            api.description = description
        if is_default is not None:
            # 如果设置为默认，取消其他默认
            if is_default and not api.is_default:
                db.query(DanmakuAPI).filter_by(is_default=True).update({'is_default': False})
            api.is_default = is_default
        if is_active is not None:
            api.is_active = is_active
        
        api.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"管理员更新弹幕API: {api.name}")
        return jsonify({'success': True, 'message': '更新成功', 'data': api.to_dict()})
    except Exception as e:
        db.rollback()
        logger.error(f"更新弹幕API失败: {e}")
        return jsonify({'success': False, 'message': '更新失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/danmaku-apis/<int:api_id>', methods=['DELETE'])
@admin_required
def api_delete_danmaku_api(api_id):
    """删除弹幕API配置"""
    db = get_db()
    try:
        api = db.query(DanmakuAPI).filter_by(id=api_id).first()
        if not api:
            return jsonify({'success': False, 'message': 'API配置不存在'}), 404
        
        db.delete(api)
        db.commit()
        
        logger.info(f"管理员删除弹幕API: {api.name}")
        return jsonify({'success': True, 'message': '删除成功'})
    except Exception as e:
        db.rollback()
        logger.error(f"删除弹幕API失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()

@app.route('/api/danmaku-apis', methods=['GET'])
@login_required
def api_get_active_danmaku_apis():
    """获取启用的弹幕API配置（用户端）"""
    db = get_db()
    try:
        apis = db.query(DanmakuAPI).filter_by(is_active=True).order_by(
            DanmakuAPI.is_default.desc(),
            DanmakuAPI.created_at.desc()
        ).all()
        return jsonify({
            'success': True,
            'data': [api.to_dict() for api in apis]
        })
    except Exception as e:
        logger.error(f"获取弹幕API列表失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_admin_stats():
    db = get_db()
    try:
        # 用户统计
        total_users = db.query(User).count()
        active_users = db.query(User).filter_by(is_active=True).count()
        expired_users = db.query(User).filter(
            and_(User.expiry_date != None, User.expiry_date < datetime.now())
        ).count()

        # 即将到期用户（7天内）
        soon_expire_date = datetime.now() + timedelta(days=7)
        expiring_soon = db.query(User).filter(
            and_(
                User.expiry_date != None,
                User.expiry_date > datetime.now(),
                User.expiry_date <= soon_expire_date
            )
        ).count()

        # 激活码统计
        total_codes = db.query(ActivationCode).count()
        used_codes = db.query(ActivationCode).filter_by(is_used=True).count()
        unused_codes = total_codes - used_codes

        # 今日新增用户
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_users = db.query(User).filter(User.created_at >= today).count()

        # 系统状态
        try:
            from sqlalchemy import text
            db.execute(text("SELECT 1"))
            database_status = "运行正常"
        except Exception:
            database_status = "连接异常"

        pending_recharges = db.query(RechargeRecord).filter_by(status='pending').count()
        security_status = "待处理" if pending_recharges > 0 else "安全"

        # 生成用户增长数据
        days = request.args.get('days', '7', type=str)
        try:
            days = int(days)
        except (ValueError, TypeError):
            days = 7
        if days not in (7, 30, 90):
            days = 7

        growth_labels = []
        growth_data = []
        for i in range(days - 1, -1, -1):
            date = datetime.now() - timedelta(days=i)
            date_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
            date_end = date_start + timedelta(days=1)
            count = db.query(User).filter(
                and_(User.created_at >= date_start, User.created_at < date_end)
            ).count()
            growth_labels.append(date.strftime('%m-%d'))
            growth_data.append(count)

        return jsonify({
            'success': True,
            'data': {
                'users': {
                    'total': total_users,
                    'active': active_users,
                    'expired': expired_users,
                    'expiring_soon': expiring_soon,
                    'today_new': today_users
                },
                'codes': {
                    'total': total_codes,
                    'used': used_codes,
                    'unused': unused_codes
                },
                'emby_connected': EmbyAPI.is_configured(),
                'growth': {
                    'labels': growth_labels,
                    'data': growth_data
                },
                'system_status': {
                    'database': database_status,
                    'security': security_status,
                    'version': 'v1.0.0'
                }
            }
        })
    finally:
        db.close()

# ============== 普通用户 API ==============
@app.route('/api/user/profile', methods=['GET'])
@login_required
def api_user_profile():
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        return jsonify({
            'success': True,
            'data': user.to_dict()
        })
    finally:
        db.close()

# 用户获取未读金币赠予通知
@app.route('/api/user/coin-notifications', methods=['GET'])
@login_required
def api_user_coin_notifications():
    """获取用户未读的金币赠予通知"""
    db = get_db()
    try:
        user_id = session['user_id']
        notifications = db.query(CoinTransaction).filter_by(
            user_id=user_id,
            is_read=False,
            type='grant'
        ).order_by(CoinTransaction.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'data': [n.to_dict() for n in notifications]
        })
    finally:
        db.close()

# 用户标记金币通知为已读
@app.route('/api/user/coin-notifications/read', methods=['POST'])
@login_required
def api_user_mark_coin_notifications_read():
    """标记金币通知为已读"""
    db = get_db()
    try:
        user_id = session['user_id']
        data = request.get_json()
        notification_id = data.get('notification_id')
        
        if notification_id:
            # 标记单个通知为已读
            result = db.query(CoinTransaction).filter_by(
                id=notification_id,
                user_id=user_id,
                type='grant'
            ).update({'is_read': True})
        else:
            # 标记所有金币通知为已读
            result = db.query(CoinTransaction).filter_by(
                user_id=user_id,
                is_read=False,
                type='grant'
            ).update({'is_read': True})
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': '已标记为已读',
            'count': result
        })
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

# 普通用户刷新自己的观看记录
@app.route('/api/user/sync-history', methods=['POST'])
@login_required
def api_user_sync_history():
    """刷新自己的观看记录（包括活跃播放会话和历史记录）"""
    if not EmbyAPI.is_configured():
        return jsonify({'success': False, 'message': 'Emby未配置，无法同步'}), 400
    
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        
        # 检查用户是否过期
        if user.is_expired():
            return jsonify({'success': False, 'message': '更新失败了QAQ 你的套餐已过期，请立即续费！'}), 403
        
        if not user.emby_user_id:
            return jsonify({'success': False, 'message': '未绑定Emby账户，无法同步'}), 400
        
        total_records = 0
        
        # 先同步活跃播放会话（正在播放的内容）
        try:
            user_sessions = EmbyAPI.get_active_sessions()
            logger.info(f"当前用户Emby ID: {user.emby_user_id}, 用户名: {user.username}")
            if user_sessions:
                # 过滤出该用户的会话
                user_active = [s for s in user_sessions if s.get('UserId') == user.emby_user_id]
                logger.info(f"过滤后该用户的活跃会话: {len(user_active)} 个")
                for user_session in user_active:
                    now_playing = user_session.get('NowPlayingItem', {})
                    play_state = user_session.get('PlayState', {})
                    
                    # 构建完整的影片名称（包含系列名称）
                    series_name = now_playing.get('SeriesName', '')
                    season_name = now_playing.get('SeasonName', '')
                    episode_name = now_playing.get('Name', '未知影片')
                    item_type = now_playing.get('Type', '')
                    
                    if series_name and item_type == 'Episode':
                        if season_name:
                            item_name = f"{series_name} - {season_name} - {episode_name}"
                        else:
                            item_name = f"{series_name} - {episode_name}"
                    else:
                        item_name = episode_name
                    
                    position_ticks = play_state.get('PositionTicks', 0)
                    duration_seconds = position_ticks // 10000000 if position_ticks > 0 else 0
                    
                    # 尝试获取会话的实际开始时间
                    session_info = user_session.get('SessionInfo', {})
                    last_activity = user_session.get('LastActivityDate') or session_info.get('LastActivityDate')
                    
                    if last_activity:
                        try:
                            end_time = datetime.fromisoformat(last_activity.replace('Z', '+00:00')).replace(tzinfo=None)
                        except:
                            end_time = datetime.now()
                    else:
                        end_time = datetime.now()
                    
                    # 开始时间 = 结束时间 - 播放时长
                    start_time = end_time - timedelta(seconds=duration_seconds) if duration_seconds > 0 else end_time
                    
                    existing = db.query(WatchHistory).filter_by(
                        user_id=user.id,
                        item_name=item_name
                    ).first()
                    
                    if existing:
                        existing.item_name = item_name
                        existing.start_time = start_time
                        existing.end_time = end_time
                        existing.duration = duration_seconds
                        total_records += 1
                    else:
                        watch_record = WatchHistory(
                            user_id=user.id,
                            item_name=item_name,
                            start_time=start_time,
                            end_time=end_time,
                            duration=duration_seconds
                        )
                        db.add(watch_record)
                        total_records += 1
        except Exception as e:
            logger.error(f"同步活跃播放会话失败: {e}")
        
        # 同步历史观看记录
        success = EmbyAPI.sync_user_watch_history_improved(user.id, user.emby_user_id)
        
        db.commit()
        
        message = f'刷新完成！获取到 {total_records} 条正在播放的记录'
        if success:
            message += '，历史记录同步成功'
        
        logger.info(f"用户 {user.username} 刷新观看记录完成")
        
        return jsonify({
            'success': True,
            'message': message,
            'active_records': total_records
        })
    except Exception as e:
        db.rollback()
        logger.error(f"刷新观看记录失败: {e}")
        return jsonify({'success': False, 'message': f'刷新失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/user/history', methods=['GET'])
@login_required
def api_user_history():
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        history = db.query(WatchHistory).filter_by(user_id=user.id).order_by(WatchHistory.created_at.desc()).all()
        
        # 尝试从Emby获取
        if user.emby_user_id and EmbyAPI.is_configured():
            emby_history = EmbyAPI.get_user_watch_history(user.emby_user_id)
            if emby_history and 'Items' in emby_history:
                emby_items = []
                for item in emby_history.get('Items', []):
                    emby_items.append({
                        'id': item.get('Id'),
                        'item_name': item.get('Name'),
                        'item_id': item.get('Id'),
                        'start_time': item.get('DateCreated'),
                        'duration': item.get('RunTimeTicks', 0) // 10000000 if item.get('RunTimeTicks') else None,
                        'created_at': item.get('DateCreated')
                    })
                return jsonify({
                    'success': True,
                    'data': emby_items
                })
        
        return jsonify({
            'success': True,
            'data': [h.to_dict() for h in history]
        })
    finally:
        db.close()

@app.route('/api/user/renew', methods=['POST'])
@login_required_allow_expired
def api_user_renew():
    data = request.get_json()
    code = data.get('code', '').strip().upper()
    
    if not code:
        return jsonify({'success': False, 'message': '请输入激活码'}), 400
    
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        
        # 检查用户是否被禁用（is_active完全手动控制）
        if not user.is_active:
            logger.warning(f"用户 {user.username} 尝试续期，但账号已被禁用")
            return jsonify({'success': False, 'message': '账号已被禁用，请联系管理员'}), 403
        
        # 首先检查激活码是否存在（不加锁）
        activation_code = db.query(ActivationCode).filter_by(code=code).first()
        
        if not activation_code:
            logger.warning(f"用户 {user.username} 尝试使用不存在的激活码: {code}")
            return jsonify({'success': False, 'message': '激活码不存在'}), 400
        
        # 检查激活码是否已被使用
        if activation_code.is_used:
            logger.warning(f"用户 {user.username} 尝试使用已使用的激活码: {code}, 使用者: {activation_code.used_by}")
            return jsonify({'success': False, 'message': '激活码已被使用'}), 400
        
        # 重新查询并加锁，确保并发安全
        activation_code = db.query(ActivationCode).filter_by(code=code).with_for_update().first()
        
        # 再次检查（加锁后）
        if not activation_code or activation_code.is_used:
            logger.warning(f"用户 {user.username} 激活码已被其他请求使用: {code}")
            return jsonify({'success': False, 'message': '激活码已被使用'}), 400
        
        duration_seconds = activation_code.duration_seconds

        if duration_seconds == 0:  # 永久
            user.expiry_date = None
        else:
            # 从原过期时间基础上延长（如果存在过期时间且未过期）
            if user.expiry_date:
                now = datetime.now()
                if user.expiry_date > now:
                    # 原过期时间还未过期，在原有过期时间基础上延长
                    user.expiry_date = user.expiry_date + timedelta(seconds=duration_seconds)
                else:
                    # 原过期时间已过期（如管理员设置的立即到期），从当前时间开始计算
                    user.expiry_date = now + timedelta(seconds=duration_seconds)
            else:
                # 没有过期时间（可能是首次激活或永久用户），从当前时间开始
                user.expiry_date = datetime.now() + timedelta(seconds=duration_seconds)
        
        # 启用用户（仅当不是手动禁用时）
        user.is_active = True
        user.emby_access_disabled = False  # 用户已续期，清除Emby访问禁用标记

        # 标记激活码已使用
        activation_code.is_used = True
        activation_code.used_by = user.id
        activation_code.used_at = datetime.now()

        # 立即提交，确保激活码状态被保存
        db.commit()

        # 启用Emby用户
        if user.emby_user_id and EmbyAPI.is_configured():
            EmbyAPI.enable_user(user.emby_user_id)

        # 同步启用 WebDAV
        try:
            sync_webdav_user_status(user, True, db)
        except Exception as e:
            logger.error(f"用户续期时同步 WebDAV 状态失败: {user.username}, 错误: {e}")
        
        logger.info(f"用户续期成功: {user.username}, 激活码: {code}, 时长: {duration_seconds}秒, 新过期时间: {user.expiry_date}")
        
        return jsonify({
            'success': True,
            'message': '续期成功',
            'data': user.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"续期失败: {e}")
        return jsonify({'success': False, 'message': '续期失败'}), 500
    finally:
        db.close()

@app.route('/api/user/webdav', methods=['GET'])
@login_required_not_expired
def api_user_webdav():
    """当前登录用户查看自己的 WebDAV 信息"""
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        webdav_info = get_user_webdav_info(user, db)
        # 格式化容量显示
        for item in webdav_info:
            item['quota_display'] = _format_quota_bytes(item['quota_bytes'])
        return jsonify({
            'success': True,
            'data': webdav_info
        })
    except Exception as e:
        logger.error(f"获取用户 WebDAV 信息失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()

# ============== 页面路由 ==============
@app.route('/')
def index():
    """主页 - 未登录用户显示欢迎页，已登录用户重定向到仪表盘"""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    # 未登录用户显示主页
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    try:
        # 分页参数（近10天记录，每页固定10条）
        page = request.args.get('page', 1, type=int)
        per_page = 10

        # 近10天所有用户的观看历史
        ten_days_ago = datetime.now() - timedelta(days=10)
        query = db.query(WatchHistory).filter(WatchHistory.start_time >= ten_days_ago)
        total_records = query.count()
        history_items = query.order_by(WatchHistory.start_time.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        # 关联本地用户获取用户名
        user_ids = list(set([item.user_id for item in history_items]))
        users = db.query(User).filter(User.id.in_(user_ids)).all() if user_ids else []
        user_map = {u.id: u for u in users}

        # 批量获取Emby项目详情
        item_details = {}
        item_ids = [item.item_id for item in history_items if item.item_id]
        if item_ids and EmbyAPI.is_configured():
            try:
                details_data = EmbyAPI.get_items_by_ids_admin(item_ids)
                if details_data:
                    for detail in details_data.get('Items', []):
                        item_details[detail.get('Id')] = detail
            except Exception as e:
                logger.error(f"管理员仪表盘批量获取项目详情失败: {e}")

        # 格式化历史记录
        formatted_history = []
        for item in history_items:
            user = user_map.get(item.user_id)
            username = user.username if user else '未知用户'

            duration_str = '未知'
            if item.duration:
                hours = item.duration // 3600
                minutes = (item.duration % 3600) // 60
                if hours > 0:
                    duration_str = f'{hours}小时{minutes}分钟'
                else:
                    duration_str = f'{minutes}分钟'

            start_time_str = None
            if item.start_time:
                start_time_str = item.start_time.strftime('%Y-%m-%dT%H:%M:%S')

            end_time_str = None
            if item.end_time:
                end_time_str = item.end_time.strftime('%Y-%m-%dT%H:%M:%S')

            poster_url = None
            modal_image_url = None
            overview = ''
            if item.item_id and EmbyAPI.is_configured():
                detail = item_details.get(item.item_id)
                if detail:
                    overview = detail.get('Overview', '') or ''
                    server_url = EmbyAPI.get_server_url().rstrip('/')
                    api_key = EmbyAPI.get_api_key()
                    poster_url = f"{server_url}/emby/Items/{item.item_id}/Images/Primary?api_key={api_key}&maxHeight=120"
                    modal_image_url = f"{server_url}/emby/Items/{item.item_id}/Images/Primary?api_key={api_key}&maxHeight=600"

            formatted_history.append({
                'username': username,
                'movie_name': item.item_name,
                'start_time': start_time_str,
                'end_time': end_time_str,
                'watch_duration': duration_str,
                'poster_url': poster_url,
                'modal_image_url': modal_image_url,
                'overview': overview
            })

        total_pages = (total_records + per_page - 1) // per_page

        # 正在观看的用户
        active_sessions = []
        if EmbyAPI.is_configured():
            try:
                sessions = EmbyAPI.get_active_sessions()
                now_playing = [s for s in sessions if s.get('is_now_playing')]

                # 映射Emby用户ID到本地用户
                emby_user_ids = [s.get('user_id') for s in now_playing if s.get('user_id')]
                local_users = db.query(User).filter(User.emby_user_id.in_(emby_user_ids)).all() if emby_user_ids else []
                emby_to_local = {u.emby_user_id: u for u in local_users}

                # 批量获取正在播放项目详情
                active_item_ids = [s.get('item_id') for s in now_playing if s.get('item_id')]
                active_item_details = {}
                if active_item_ids:
                    try:
                        details_data = EmbyAPI.get_items_by_ids_admin(active_item_ids)
                        if details_data:
                            for detail in details_data.get('Items', []):
                                active_item_details[detail.get('Id')] = detail
                    except Exception as e:
                        logger.error(f"管理员仪表盘批量获取正在播放项目详情失败: {e}")

                for session in now_playing:
                    emby_user_id = session.get('user_id')
                    local_user = emby_to_local.get(emby_user_id)
                    username = local_user.username if local_user else '未知用户'
                    item_id = session.get('item_id')
                    detail = active_item_details.get(item_id, {})
                    overview = detail.get('Overview', '') or ''

                    server_url = EmbyAPI.get_server_url().rstrip('/')
                    api_key = EmbyAPI.get_api_key()
                    poster_url = None
                    modal_image_url = None
                    if item_id:
                        poster_url = f"{server_url}/emby/Items/{item_id}/Images/Primary?api_key={api_key}&maxHeight=120"
                        modal_image_url = f"{server_url}/emby/Items/{item_id}/Images/Primary?api_key={api_key}&maxHeight=600"

                    # 播放进度
                    position_ticks = session.get('position_ticks', 0)
                    position_seconds = position_ticks // 10000000 if position_ticks else 0
                    pos_hours = position_seconds // 3600
                    pos_minutes = (position_seconds % 3600) // 60
                    if pos_hours > 0:
                        progress_str = f'{pos_hours}小时{pos_minutes}分钟'
                    else:
                        progress_str = f'{pos_minutes}分钟'

                    display_name = session.get('item_name', '未知影片')
                    if session.get('series_name'):
                        display_name = f"{session.get('series_name')} - {display_name}"

                    active_sessions.append({
                        'username': username,
                        'movie_name': display_name,
                        'device_name': session.get('device_name', '未知设备'),
                        'client': session.get('client', '未知客户端'),
                        'is_paused': session.get('is_paused', False),
                        'progress': progress_str,
                        'poster_url': poster_url,
                        'modal_image_url': modal_image_url,
                        'overview': overview
                    })
            except Exception as e:
                logger.error(f"管理员仪表盘获取正在观看会话失败: {e}")

        return render_template('admin/dashboard.html',
            history_items=formatted_history,
            page=page,
            per_page=per_page,
            total_records=total_records,
            total_pages=total_pages,
            active_sessions=active_sessions
        )
    finally:
        db.close()

@app.route('/api/admin/active-sessions', methods=['GET'])
@admin_required
def api_admin_active_sessions():
    """实时获取正在观看的用户会话"""
    db = get_db()
    try:
        active_sessions = []
        if EmbyAPI.is_configured():
            try:
                sessions = EmbyAPI.get_active_sessions()
                now_playing = [s for s in sessions if s.get('is_now_playing')]

                emby_user_ids = [s.get('user_id') for s in now_playing if s.get('user_id')]
                local_users = db.query(User).filter(User.emby_user_id.in_(emby_user_ids)).all() if emby_user_ids else []
                emby_to_local = {u.emby_user_id: u for u in local_users}

                active_item_ids = [s.get('item_id') for s in now_playing if s.get('item_id')]
                active_item_details = {}
                if active_item_ids:
                    try:
                        details_data = EmbyAPI.get_items_by_ids_admin(active_item_ids)
                        if details_data:
                            for detail in details_data.get('Items', []):
                                active_item_details[detail.get('Id')] = detail
                    except Exception as e:
                        logger.error(f"实时会话批量获取项目详情失败: {e}")

                for session in now_playing:
                    emby_user_id = session.get('user_id')
                    local_user = emby_to_local.get(emby_user_id)
                    username = local_user.username if local_user else '未知用户'
                    item_id = session.get('item_id')
                    detail = active_item_details.get(item_id, {})
                    overview = detail.get('Overview', '') or ''

                    server_url = EmbyAPI.get_server_url().rstrip('/')
                    api_key = EmbyAPI.get_api_key()
                    poster_url = None
                    modal_image_url = None
                    if item_id:
                        poster_url = f"{server_url}/emby/Items/{item_id}/Images/Primary?api_key={api_key}&maxHeight=120"
                        modal_image_url = f"{server_url}/emby/Items/{item_id}/Images/Primary?api_key={api_key}&maxHeight=600"

                    position_ticks = session.get('position_ticks', 0)
                    position_seconds = position_ticks // 10000000 if position_ticks else 0
                    pos_hours = position_seconds // 3600
                    pos_minutes = (position_seconds % 3600) // 60
                    if pos_hours > 0:
                        progress_str = f'{pos_hours}小时{pos_minutes}分钟'
                    else:
                        progress_str = f'{pos_minutes}分钟'

                    # 计算播放进度百分比
                    progress_percent = 0
                    runtime_ticks = detail.get('RunTimeTicks', 0)
                    if runtime_ticks and position_ticks:
                        progress_percent = round((position_ticks / runtime_ticks) * 100, 1)

                    display_name = session.get('item_name', '未知影片')
                    if session.get('series_name'):
                        display_name = f"{session.get('series_name')} - {display_name}"

                    active_sessions.append({
                        'username': username,
                        'movie_name': display_name,
                        'device_name': session.get('device_name', '未知设备'),
                        'client': session.get('client', '未知客户端'),
                        'is_paused': session.get('is_paused', False),
                        'progress': progress_str,
                        'progress_percent': progress_percent,
                        'poster_url': poster_url,
                        'modal_image_url': modal_image_url,
                        'overview': overview
                    })
            except Exception as e:
                logger.error(f"实时获取正在观看会话失败: {e}")

        return jsonify({'success': True, 'data': active_sessions})
    finally:
        db.close()

@app.route('/admin/payment-audit')
@admin_required
def admin_payment_audit():
    """管理员支付审核页面"""
    return render_template('admin/payment_audit.html', cache_buster=int(time.time()))

@app.route('/admin/users')
@admin_required
def admin_users():
    return render_template('admin/users.html')

@app.route('/admin/bind')
@admin_required
def admin_bind():
    return render_template('admin/bind.html')

@app.route('/admin/activation')
@admin_required
def admin_activation():
    return render_template('admin/activation.html')

@app.route('/admin/profile')
@admin_required
def admin_profile():
    db = get_db()
    try:
        # 管理用户：非管理员用户总数
        managed_users = db.query(User).filter(User.role != UserRole.ADMIN).count()
        # 激活码：已生成的激活码总数
        activation_codes = db.query(ActivationCode).count()
        # 运行天数：从最早一个用户注册时间算起
        first_user = db.query(User).order_by(User.created_at.asc()).first()
        if first_user and first_user.created_at:
            running_days = (datetime.utcnow() - first_user.created_at).days
        else:
            running_days = 0
        # 在线率：登录成功次数 / 总登录次数
        total_logins = db.query(LoginLog).count()
        successful_logins = db.query(LoginLog).filter(LoginLog.success == 1).count()
        if total_logins > 0:
            online_rate = round((successful_logins / total_logins) * 100, 1)
        else:
            online_rate = 100.0
    finally:
        db.close()

    return render_template('admin/profile.html',
                           cache_buster=int(time.time()),
                           managed_users=managed_users,
                           activation_codes=activation_codes,
                           running_days=running_days,
                           online_rate=online_rate)

@app.route('/admin/settings')
@admin_required
def admin_settings():
    return render_template('admin/settings.html', active_menu='settings')

@app.route('/admin/client-downloads')
@admin_required
def admin_client_downloads():
    """管理员客户端管理页面"""
    import time
    return render_template('admin/client_downloads.html', active_menu='client_downloads', cache_buster=int(time.time()))

@app.route('/user/client-downloads')
@login_required_not_expired
def user_client_downloads():
    """用户客户端下载页面"""
    import time
    return render_template('user/client_downloads.html', cache_buster=int(time.time()))

@app.route('/admin/user-guide-docs')
@admin_required
def admin_user_guide_docs():
    """管理员使用文档管理页面"""
    import time
    return render_template('admin/user_guide_docs.html', active_menu='user_guide_docs', cache_buster=int(time.time()))

@app.route('/user/user-guide')
@login_required_not_expired
def user_user_guide():
    """用户使用文档页面"""
    import time
    return render_template('user/user_guide.html', cache_buster=int(time.time()))

# 管理员金币赠予API
@app.route('/api/admin/grant-coins', methods=['POST'])
@admin_required
def api_admin_grant_coins():
    """管理员赠予金币"""
    data = request.get_json()
    user_ids = data.get('user_ids', [])
    amount = data.get('amount', 0)
    reason = data.get('reason', '')
    
    if not user_ids or amount <= 0:
        return jsonify({'success': False, 'message': '参数错误'}), 400
    
    db = get_db()
    try:
        admin_id = session['user_id']
        granted_count = 0
        
        for uid in user_ids:
            user = db.query(User).get(uid)
            if user and user.role == UserRole.USER:
                # 获取或创建 UserCoin 记录
                user_coin = db.query(UserCoin).filter_by(user_id=uid).first()
                if not user_coin:
                    user_coin = UserCoin(user_id=uid, balance=0, total_recharged=0, total_spent=0)
                    db.add(user_coin)
                    db.flush()
                
                # 增加用户金币余额
                user_coin.balance += amount
                user_coin.total_recharged += amount
                
                # 同时更新 User.coins
                user.coins += amount
                
                # 生成订单号
                order_no = 'GRANT' + datetime.now().strftime('%Y%m%d%H%M%S') + str(uid).zfill(4) + str(granted_count).zfill(2)
                
                # 创建充值记录
                recharge_record = RechargeRecord(
                    user_id=uid,
                    order_no=order_no,
                    amount_yuan=0,
                    coin_amount=amount,
                    status='success',
                    pay_method='管理员赠予',
                    pay_time=datetime.now()
                )
                db.add(recharge_record)
                
                # 创建交易记录（用于通知）
                transaction = CoinTransaction(
                    user_id=uid,
                    amount=amount,
                    type='grant',
                    reason=reason,
                    created_by=admin_id,
                    is_read=False
                )
                db.add(transaction)
                granted_count += 1
        
        db.commit()
        logger.info(f"管理员赠予金币: {granted_count}个用户, 每人{amount}金币, 原因: {reason}")
        
        return jsonify({
            'success': True,
            'message': f'成功向 {granted_count} 个用户赠予 {amount} 金币',
            'granted_count': granted_count
        })
    except Exception as e:
        db.rollback()
        logger.error(f"金币赠予失败: {e}")
        return jsonify({'success': False, 'message': f'赠予失败: {str(e)}'}), 500
    finally:
        db.close()

# 管理员获取用户列表API（用于金币赠予）
@app.route('/api/admin/users-list', methods=['GET'])
@admin_required
def api_admin_users_list():
    """获取用户列表（支持搜索用户名或邮箱）"""
    db = get_db()
    try:
        search = request.args.get('search', '').strip()
        exclude_whitelist = request.args.get('exclude_whitelist', 'false').lower() == 'true'

        query = db.query(User).filter(User.role == UserRole.USER)

        if search:
            # 支持搜索用户名或邮箱
            query = query.filter(
                or_(
                    User.username.contains(search),
                    User.email.contains(search)
                )
            )

        # 如果 exclude_whitelist=true，排除已在白名单中的用户
        if exclude_whitelist:
            # 获取白名单中的用户ID
            whitelist_user_ids = [entry.user_id for entry in db.query(PolicyWhitelist).all()]
            if whitelist_user_ids:
                query = query.filter(~User.id.in_(whitelist_user_ids))

        users = query.order_by(User.created_at.desc()).limit(50).all()

        return jsonify({
            'success': True,
            'data': [{
                'id': u.id,
                'username': u.username,
                'email': u.email,
                'emby_user_id': u.emby_user_id,
                'coins': u.coins,
                'is_active': u.is_active
            } for u in users]
        })
    finally:
        db.close()

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        
        # 获取用户观看统计
        watch_history = db.query(WatchHistory).filter_by(user_id=user.id).all()
        total_watch_seconds = sum(h.duration for h in watch_history if h.duration)
        total_watch_hours = round(total_watch_seconds / 3600, 1)
        total_movies = len(watch_history)
        
        # 本月观看时长
        today = datetime.utcnow()
        month_start = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_watch = db.query(WatchHistory).filter(
            and_(
                WatchHistory.user_id == user.id,
                WatchHistory.start_time >= month_start
            )
        ).all()
        monthly_watch_seconds = sum(h.duration for h in monthly_watch if h.duration)
        monthly_watch_hours = round(monthly_watch_seconds / 3600, 1)
        
        # 最近观看记录
        recent_history_raw = db.query(WatchHistory).filter_by(user_id=user.id).order_by(
            WatchHistory.start_time.desc()
        ).limit(5).all()
        
        # 格式化为模板期望的格式
        recent_history = []
        for item in recent_history_raw:
            duration_str = '未知'
            if item.duration:
                hours = item.duration // 3600
                minutes = (item.duration % 3600) // 60
                if hours > 0:
                    duration_str = f'{hours}小时{minutes}分钟'
                else:
                    duration_str = f'{minutes}分钟'
            
            recent_history.append({
                'movie_name': item.item_name,
                'start_time': item.start_time,
                'watch_duration': duration_str
            })
        
        # 观看趋势数据（最近7天）
        trend_labels = []
        trend_data = []
        for i in range(6, -1, -1):
            date = today - timedelta(days=i)
            date_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
            date_end = date_start + timedelta(days=1)
            daily_watch = db.query(WatchHistory).filter(
                and_(
                    WatchHistory.user_id == user.id,
                    WatchHistory.start_time >= date_start,
                    WatchHistory.start_time < date_end
                )
            ).all()
            daily_seconds = sum(h.duration for h in daily_watch if h.duration)
            trend_labels.append(date.strftime('%m-%d'))
            trend_data.append(round(daily_seconds / 3600, 1))
        
        # 影片类型分布统计
        # 根据观看历史记录中的 item_type 字段统计
        genre_stats = {
            '电影': 0,
            '电视剧': 0,
            '动漫': 0,
            '纪录片': 0,
            '综艺': 0,
            '其他': 0
        }
        
        for item in watch_history:
            item_type = item.item_type
            if item_type:
                item_type_upper = item_type.upper()
                if item_type_upper == 'MOVIE':
                    genre_stats['电影'] += 1
                elif item_type_upper == 'EPISODE':
                    # 根据名称判断是电视剧还是动漫
                    item_name = item.item_name or ''
                    if any(keyword in item_name for keyword in ['动漫', '番剧', '动画']):
                        genre_stats['动漫'] += 1
                    else:
                        genre_stats['电视剧'] += 1
                else:
                    genre_stats['其他'] += 1
            else:
                # 如果没有类型，根据名称判断
                item_name = item.item_name or ''
                if any(keyword in item_name for keyword in ['动漫', '番剧', '动画']):
                    genre_stats['动漫'] += 1
                else:
                    genre_stats['其他'] += 1
        
        # 只保留有数据的类型
        genre_labels = []
        genre_data = []
        for genre, count in genre_stats.items():
            if count > 0:
                genre_labels.append(genre)
                genre_data.append(count)
        
        # 如果没有数据，显示默认空状态
        if not genre_labels:
            genre_labels = ['暂无数据']
            genre_data = [1]
        
        return render_template('user/dashboard.html',
            current_user=user,
            total_watch_hours=total_watch_hours,
            total_movies=total_movies,
            monthly_watch_hours=monthly_watch_hours,
            recent_history=recent_history,
            trend_labels=trend_labels,
            trend_data=trend_data,
            genre_labels=genre_labels,
            genre_data=genre_data
        )
    finally:
        db.close()

@app.route('/user/history')
@login_required
def user_history():
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        
        # 获取分页参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search_query = request.args.get('search', '')
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        
        # 构建查询
        query = db.query(WatchHistory).filter_by(user_id=user.id)
        
        # 搜索过滤（使用参数化查询防止SQL注入）
        if search_query:
            # 清理搜索词，防止SQL注入
            search_term = search_query.replace('%', '').replace('_', '').replace('[', '').replace(']', '')
            if search_term:
                query = query.filter(WatchHistory.item_name.like('%' + search_term + '%'))
        
        # 日期过滤
        if start_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d')
                query = query.filter(WatchHistory.start_time >= start)
            except:
                pass
        
        if end_date:
            try:
                end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(WatchHistory.start_time < end)
            except:
                pass
        
        # 获取总数
        total_records = query.count()
        
        # 分页
        history_items = query.order_by(WatchHistory.start_time.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        
        # 批量获取Emby项目详情（封面、简介等）
        item_details = {}
        if user.emby_user_id and EmbyAPI.is_configured():
            item_ids = [item.item_id for item in history_items if item.item_id]
            if item_ids:
                try:
                    details_data = EmbyAPI.get_items_by_ids(user.emby_user_id, item_ids)
                    if details_data:
                        for detail in details_data.get('Items', []):
                            item_details[detail.get('Id')] = detail
                except Exception as e:
                    logger.error(f"批量获取观看历史项目详情失败: {e}")

        # 格式化数据
        formatted_items = []
        for item in history_items:
            duration_str = '未知'
            if item.duration:
                hours = item.duration // 3600
                minutes = (item.duration % 3600) // 60
                if hours > 0:
                    duration_str = f'{hours}小时{minutes}分钟'
                else:
                    duration_str = f'{minutes}分钟'

            # 确保时间格式正确，避免时区转换问题
            # 将时间转换为字符串格式，不带时区信息
            start_time_str = None
            if item.start_time:
                start_time_str = item.start_time.strftime('%Y-%m-%dT%H:%M:%S')

            end_time_str = None
            if item.end_time:
                end_time_str = item.end_time.strftime('%Y-%m-%dT%H:%M:%S')

            # 组装Emby图片URL
            poster_url = None
            modal_image_url = None
            overview = ''
            if item.item_id and user.emby_user_id and EmbyAPI.is_configured():
                detail = item_details.get(item.item_id)
                if detail:
                    overview = detail.get('Overview', '') or ''
                    server_url = EmbyAPI.get_server_url().rstrip('/')
                    api_key = EmbyAPI.get_api_key()
                    poster_url = f"{server_url}/emby/Items/{item.item_id}/Images/Primary?api_key={api_key}&maxHeight=120"
                    modal_image_url = f"{server_url}/emby/Items/{item.item_id}/Images/Primary?api_key={api_key}&maxHeight=600"

            formatted_items.append({
                'movie_name': item.item_name,
                'start_time': start_time_str,
                'end_time': end_time_str,
                'watch_duration': duration_str,
                'poster_url': poster_url,
                'modal_image_url': modal_image_url,
                'overview': overview
            })
        
        # 计算总观看时长
        total_seconds = db.query(WatchHistory).filter_by(user_id=user.id).with_entities(
            func.sum(WatchHistory.duration)
        ).scalar() or 0
        total_hours = total_seconds // 3600
        total_minutes = (total_seconds % 3600) // 60
        total_duration = f'{total_hours}小时{total_minutes}分钟' if total_hours > 0 else f'{total_minutes}分钟'
        
        # 计算总页数
        total_pages = (total_records + per_page - 1) // per_page
        
        return render_template('user/history.html',
            current_user=user,
            total_records=total_records,
            total_duration=total_duration,
            history_items=formatted_items,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            search_query=search_query,
            start_date=start_date,
            end_date=end_date
        )
    finally:
        db.close()

@app.route('/user/shop')
@login_required
def user_shop():
    """用户金币商店页面"""
    return render_template('user/shop.html')

@app.route('/user/recharge')
@login_required
def user_recharge():
    """用户充值页面"""
    return render_template('user/recharge.html')

@app.route('/user/payment')
@login_required
def user_payment():
    """用户支付页面"""
    return render_template('user/payment.html')

@app.route('/user/server')
@login_required_not_expired
def user_server_page():
    """用户查看服务器信息页面"""
    db = get_db()
    try:
        config = db.query(SystemConfig).filter_by(key='emby_server_url').first()
        emby_server_url = config.value if config else ''
        
        config = db.query(SystemConfig).filter_by(key='emby_api_key').first()
        emby_api_key = config.value if config else ''
        
        # 解析URL获取域名/IP和端口
        server_host = ''
        server_port = ''
        if emby_server_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(emby_server_url)
                server_host = parsed.hostname or ''
                server_port = str(parsed.port) if parsed.port else '8096'
            except:
                server_host = emby_server_url
                server_port = ''
        
        # 获取默认弹幕API
        danmaku_api = db.query(DanmakuAPI).filter_by(is_active=True, is_default=True).first()
        if not danmaku_api:
            # 如果没有默认的，获取第一个启用的
            danmaku_api = db.query(DanmakuAPI).filter_by(is_active=True).order_by(DanmakuAPI.created_at.desc()).first()
        
        danmaku_api_name = danmaku_api.name if danmaku_api else None
        danmaku_api_url = danmaku_api.url if danmaku_api else None
        
        return render_template('user/server.html',
                             server_host=server_host,
                             server_port=server_port,
                             server_url=emby_server_url,
                             danmaku_api_name=danmaku_api_name,
                             danmaku_api_url=danmaku_api_url)
    finally:
        db.close()

@app.route('/user/profile')
@login_required_allow_expired
def user_profile_page():
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])

        # 计算到期时间
        if user.expiry_date:
            expiry_date = user.expiry_date
            # 计算剩余天数（向上取整，确保最后一天也算）
            now = datetime.now()
            time_diff = expiry_date - now
            # 使用与前端一致的计算方式：Math.ceil(timeDiff / (1000 * 60 * 60 * 24))
            total_seconds = time_diff.total_seconds()
            days_remaining = max(0, int(__import__('math').ceil(total_seconds / (24 * 3600))))
        else:
            expiry_date = None  # 永久有效
            days_remaining = 999999  # 永久有效显示为很大的数字
        
        # 获取登录日志
        login_logs = db.query(LoginLog).filter_by(user_id=user.id).order_by(
            LoginLog.login_time.desc()
        ).limit(10).all()
        
        return render_template('user/profile.html',
            current_user=user,
            expiry_date=expiry_date,
            days_remaining=days_remaining,
            login_logs=login_logs
        )
    finally:
        db.close()

# ============== 定时任务 ==============
def check_expired_users():
    """
    检查过期用户 - 自动禁用过期用户的Emby访问权限
    系统登录仍然允许（用于续期），但Emby媒体库访问会被禁止
    """
    while True:
        try:
            # 使用独立的 SessionLocal 而非 DBSession，避免 EmbyAPI.disable_user
            # 内部调用 get_config -> get_db -> DBSession 时复用并关闭同一线程的会话，
            # 导致本函数中的 db.commit() 失效、emby_access_disabled 标记无法持久化。
            db = SessionLocal()
            try:
                now = datetime.now()

                # 查找已过期且尚未被系统自动禁用Emby访问的用户
                expired_users = db.query(User).filter(
                    and_(
                        User.expiry_date != None,
                        User.expiry_date < now,  # 已过期
                        User.is_active == True,   # 当前是启用状态
                        User.role == UserRole.USER,
                        User.emby_access_disabled == False  # 避免重复禁用已处理的用户
                    )
                ).all()

                if expired_users:
                    for user in expired_users:
                        logger.info(f"检测到过期用户，正在禁用Emby访问权限: {user.username} (过期时间: {user.expiry_date})")

                        # 禁用Emby用户访问权限
                        if user.emby_user_id:
                            try:
                                if EmbyAPI.disable_user(user.emby_user_id):
                                    user.emby_access_disabled = True
                                    try:
                                        db.commit()
                                        logger.info(f"已禁用过期用户的Emby访问权限: {user.username} (Emby ID: {user.emby_user_id})")
                                    except Exception as commit_err:
                                        logger.error(f"持久化emby_access_disabled标记失败: {user.username}, 错误: {commit_err}")
                                        db.rollback()
                                else:
                                    logger.warning(f"禁用过期用户Emby访问权限未成功，将在下次检查时重试: {user.username}")
                            except Exception as e:
                                logger.error(f"禁用过期用户Emby访问权限失败: {user.username}, 错误: {e}")
                        else:
                            logger.warning(f"过期用户没有Emby ID，无法禁用Emby访问: {user.username}")

                        # 同步禁用 WebDAV
                        try:
                            sync_webdav_user_status(user, False, db)
                        except Exception as e:
                            logger.error(f"过期检查时同步 WebDAV 状态失败: {user.username}, 错误: {e}")
                
            except Exception as e:
                logger.error(f"检查过期用户失败: {e}")
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"定时任务异常: {e}")
        
        # 每10秒检查一次过期用户
        time.sleep(10)

def sync_watch_history_scheduler():
    """
    每日零时自动同步未过期用户的观看记录
    """
    while True:
        try:
            now = datetime.now()
            
            # 计算到下一个零时的时间
            next_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            seconds_until_midnight = (next_midnight - now).total_seconds()
            
            logger.info(f"观看记录同步定时任务：将在 {seconds_until_midnight/3600:.1f} 小时后（{next_midnight.strftime('%Y-%m-%d %H:%M:%S')}）执行同步")
            
            # 等待到零时
            time.sleep(seconds_until_midnight)
            
            # 执行同步
            logger.info("开始执行每日观看记录同步任务")
            
            db = DBSession()
            try:
                now = datetime.now()
                
                # 查找未过期的用户（包括永不过期的用户）
                active_users = db.query(User).filter(
                    and_(
                        User.is_active == True,
                        User.role == UserRole.USER,
                        or_(
                            User.expiry_date == None,  # 永不过期
                            User.expiry_date >= now    # 未过期
                        )
                    )
                ).all()
                
                logger.info(f"找到 {len(active_users)} 个未过期用户需要同步观看记录")
                
                synced_count = 0
                error_count = 0
                
                for user in active_users:
                    if user.emby_user_id:
                        try:
                            logger.info(f"正在同步用户 {user.username} 的观看记录")
                            success = EmbyAPI.sync_user_watch_history(user.id, user.emby_user_id)
                            if success:
                                synced_count += 1
                                logger.info(f"成功同步用户 {user.username} 的观看记录")
                            else:
                                error_count += 1
                                logger.warning(f"同步用户 {user.username} 的观看记录失败")
                            
                            # 添加短暂延迟，避免对Emby服务器造成过大压力
                            time.sleep(0.5)
                        except Exception as e:
                            error_count += 1
                            logger.error(f"同步用户 {user.username} 的观看记录时出错: {e}")
                    else:
                        logger.warning(f"用户 {user.username} 没有Emby ID，跳过同步")
                
                logger.info(f"每日观看记录同步完成：成功 {synced_count} 个，失败 {error_count} 个")
                
            except Exception as e:
                logger.error(f"执行观看记录同步任务失败: {e}")
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"观看记录同步定时任务异常: {e}")
            # 如果出错，等待1小时后重试
            time.sleep(3600)

def emby_policy_monitor_scheduler():
    """
    Emby用户策略自动巡查定时任务
    每5分钟执行一次策略巡查
    """
    while True:
        try:
            # 执行策略巡查
            monitor_emby_policies()

            # 清理过期的监控数据
            cleanup_policy_monitor_data()

        except Exception as e:
            logger.error(f"策略巡查定时任务异常: {e}")

        # 每5分钟执行一次
        time.sleep(300)


def start_scheduler():
    """启动定时任务线程"""
    global _scheduler_started

    with _scheduler_lock:
        if _scheduler_started:
            logger.info("定时任务已经启动，跳过重复启动")
            return
        _scheduler_started = True

    # 从数据库加载白名单到内存（必须在巡查任务启动前完成）
    load_policy_whitelist_from_db()

    # 启动 WebDAV 存量用户分配线程（一次性）
    def _bulk_assign_webdav_thread():
        try:
            # 等待数据库完全初始化
            time.sleep(2)
            bulk_assign_webdav_to_existing_users()
        except Exception as e:
            logger.error(f"启动 WebDAV 存量用户分配失败: {e}")

    bulk_assign_thread = Thread(target=_bulk_assign_webdav_thread, daemon=True)
    bulk_assign_thread.start()
    logger.info("WebDAV 存量用户分配任务已启动")

    # 启动过期用户检查线程
    scheduler_thread = Thread(target=check_expired_users, daemon=True)
    scheduler_thread.start()
    logger.info("过期用户检查定时任务已启动")

    # 启动观看记录同步线程
    sync_thread = Thread(target=sync_watch_history_scheduler, daemon=True)
    sync_thread.start()
    logger.info("观看记录同步定时任务已启动")

    # 启动Emby策略巡查线程
    policy_monitor_thread = Thread(target=emby_policy_monitor_scheduler, daemon=True)
    policy_monitor_thread.start()
    logger.info("Emby策略巡查定时任务已启动")

# ============== 错误处理 ==============
# ============== 系统设置 API ==============

# 公告管理 API
@app.route('/api/admin/announcements', methods=['GET'])
@admin_required
def api_get_announcements():
    """获取所有公告"""
    db = get_db()
    try:
        announcements = db.query(Announcement).order_by(Announcement.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [ann.to_dict() for ann in announcements]
        })
    finally:
        db.close()

@app.route('/api/admin/announcements', methods=['POST'])
@admin_required
def api_create_announcement():
    """创建公告"""
    data = request.get_json()
    db = get_db()
    try:
        # 解析时间字段
        start_time = None
        end_time = None
        
        if data.get('start_time'):
            try:
                start_time = datetime.fromisoformat(data.get('start_time').replace('Z', '+00:00').replace('+00:00', ''))
            except:
                pass
        
        if data.get('end_time'):
            try:
                end_time = datetime.fromisoformat(data.get('end_time').replace('Z', '+00:00').replace('+00:00', ''))
            except:
                pass
        
        announcement = Announcement(
            title=data.get('title'),
            content=data.get('content'),
            is_active=data.get('is_active', True),
            start_time=start_time,
            end_time=end_time
        )
        db.add(announcement)
        db.commit()
        logger.info(f"管理员创建公告: {announcement.title}")
        return jsonify({
            'success': True,
            'message': '公告创建成功',
            'data': announcement.to_dict()
        })
    finally:
        db.close()

@app.route('/api/admin/announcements/<int:ann_id>', methods=['PUT'])
@admin_required
def api_update_announcement(ann_id):
    """更新公告"""
    data = request.get_json()
    db = get_db()
    try:
        announcement = db.query(Announcement).get(ann_id)
        if not announcement:
            return jsonify({'success': False, 'message': '公告不存在'}), 404
        
        announcement.title = data.get('title', announcement.title)
        announcement.content = data.get('content', announcement.content)
        announcement.is_active = data.get('is_active', announcement.is_active)
        
        # 更新时间字段
        if 'start_time' in data:
            if data.get('start_time'):
                try:
                    announcement.start_time = datetime.fromisoformat(data.get('start_time').replace('Z', '+00:00').replace('+00:00', ''))
                except:
                    announcement.start_time = None
            else:
                announcement.start_time = None
        
        if 'end_time' in data:
            if data.get('end_time'):
                try:
                    announcement.end_time = datetime.fromisoformat(data.get('end_time').replace('Z', '+00:00').replace('+00:00', ''))
                except:
                    announcement.end_time = None
            else:
                announcement.end_time = None
        
        announcement.updated_at = datetime.now()
        db.commit()
        logger.info(f"管理员更新公告: {announcement.title}")
        return jsonify({
            'success': True,
            'message': '公告更新成功',
            'data': announcement.to_dict()
        })
    finally:
        db.close()

@app.route('/api/admin/announcements/<int:ann_id>', methods=['DELETE'])
@admin_required
def api_delete_announcement(ann_id):
    """删除公告"""
    db = get_db()
    try:
        announcement = db.query(Announcement).get(ann_id)
        if not announcement:
            return jsonify({'success': False, 'message': '公告不存在'}), 404
        
        db.delete(announcement)
        db.commit()
        logger.info(f"管理员删除公告: {announcement.title}")
        return jsonify({
            'success': True,
            'message': '公告删除成功'
        })
    finally:
        db.close()

# 法律条款页面 API
@app.route('/api/admin/legal-pages', methods=['GET'])
@admin_required
def api_get_legal_pages():
    """获取所有法律条款页面"""
    db = get_db()
    try:
        legal_pages = db.query(LegalPage).order_by(LegalPage.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [lp.to_dict() for lp in legal_pages]
        })
    finally:
        db.close()

@app.route('/api/admin/legal-pages', methods=['POST'])
@admin_required
def api_create_legal_page():
    """创建法律条款页面"""
    data = request.get_json()
    db = get_db()
    try:
        # 检查page_type是否已存在
        existing = db.query(LegalPage).filter_by(page_type=data.get('page_type')).first()
        if existing:
            return jsonify({'success': False, 'message': '该类型的页面已存在'}), 400
        
        legal_page = LegalPage(
            page_type=data.get('page_type'),
            title=data.get('title'),
            content=data.get('content', ''),
            is_active=data.get('is_active', True)
        )
        db.add(legal_page)
        db.commit()
        logger.info(f"管理员创建法律条款页面: {legal_page.title} ({legal_page.page_type})")
        return jsonify({
            'success': True,
            'message': '法律条款页面创建成功',
            'data': legal_page.to_dict()
        })
    finally:
        db.close()

@app.route('/api/admin/legal-pages/<int:page_id>', methods=['PUT'])
@admin_required
def api_update_legal_page(page_id):
    """更新法律条款页面"""
    data = request.get_json()
    db = get_db()
    try:
        legal_page = db.query(LegalPage).get(page_id)
        if not legal_page:
            return jsonify({'success': False, 'message': '页面不存在'}), 404
        
        legal_page.title = data.get('title', legal_page.title)
        legal_page.content = data.get('content', legal_page.content)
        legal_page.is_active = data.get('is_active', legal_page.is_active)
        legal_page.updated_at = datetime.now()
        db.commit()
        logger.info(f"管理员更新法律条款页面: {legal_page.title}")
        return jsonify({
            'success': True,
            'message': '法律条款页面更新成功',
            'data': legal_page.to_dict()
        })
    finally:
        db.close()

@app.route('/api/admin/legal-pages/<int:page_id>', methods=['DELETE'])
@admin_required
def api_delete_legal_page(page_id):
    """删除法律条款页面"""
    db = get_db()
    try:
        legal_page = db.query(LegalPage).get(page_id)
        if not legal_page:
            return jsonify({'success': False, 'message': '页面不存在'}), 404
        
        db.delete(legal_page)
        db.commit()
        logger.info(f"管理员删除法律条款页面: {legal_page.title}")
        return jsonify({
            'success': True,
            'message': '法律条款页面删除成功'
        })
    finally:
        db.close()

# 公开访问法律条款页面
@app.route('/terms')
def public_terms():
    """公开访问服务条款页面"""
    db = get_db()
    try:
        page = db.query(LegalPage).filter_by(page_type='terms', is_active=True).first()
        if not page:
            return render_template('legal_page.html', title='服务条款', content='<p>暂无内容</p>')
        return render_template('legal_page.html', title=page.title, content=page.content)
    finally:
        db.close()

@app.route('/privacy')
def public_privacy():
    """公开访问隐私政策页面"""
    db = get_db()
    try:
        page = db.query(LegalPage).filter_by(page_type='privacy', is_active=True).first()
        if not page:
            return render_template('legal_page.html', title='隐私政策', content='<p>暂无内容</p>')
        return render_template('legal_page.html', title=page.title, content=page.content)
    finally:
        db.close()

# Emby用户规则 API
@app.route('/api/admin/emby-policy', methods=['GET'])
@admin_required
def api_get_emby_policy():
    """获取Emby用户默认规则"""
    db = get_db()
    try:
        policy = db.query(EmbyUserPolicy).filter_by(is_default=True).first()
        if not policy:
            # 创建默认规则
            policy = EmbyUserPolicy(
                enable_download=True,
                enable_transcoding=True,
                max_active_devices=3,
                is_default=True
            )
            db.add(policy)
            db.commit()
        return jsonify({
            'success': True,
            'data': policy.to_dict()
        })
    finally:
        db.close()

@app.route('/api/admin/emby-policy', methods=['POST'])
@admin_required
def api_update_emby_policy():
    """更新Emby用户默认规则并应用到所有现有用户"""
    data = request.get_json()
    db = get_db()
    try:
        policy = db.query(EmbyUserPolicy).filter_by(is_default=True).first()
        if not policy:
            policy = EmbyUserPolicy(is_default=True)
            db.add(policy)

        policy.enable_download = data.get('enable_download', policy.enable_download)
        policy.enable_transcoding = data.get('enable_transcoding', policy.enable_transcoding)
        policy.max_active_devices = data.get('max_active_devices', policy.max_active_devices)
        policy.allowed_library_ids = json.dumps(data.get('allowed_library_ids', []))
        policy.updated_at = datetime.utcnow()
        db.commit()

        # 获取保存的allowed_library_ids用于日志
        allowed_ids = data.get('allowed_library_ids', [])
        logger.info(f"管理员更新Emby用户规则: 下载={policy.enable_download}, 转码={policy.enable_transcoding}, 媒体库={allowed_ids}")

        # 将新策略应用到所有现有Emby用户
        users_with_emby = db.query(User).filter(User.emby_user_id.isnot(None), User.emby_user_id != '').all()
        applied_count = 0
        failed_count = 0
        
        for user in users_with_emby:
            try:
                # 已过期或被标记为Emby访问禁用的用户必须保持禁用状态，避免规则更新后重新启用
                is_disabled = not user.is_active or user.is_expired() or user.emby_access_disabled
                if EmbyAPI.apply_default_policy(user.emby_user_id, is_disabled=is_disabled):
                    applied_count += 1
                    logger.info(f"已将新策略应用到用户 {user.username} (Emby ID: {user.emby_user_id}, 禁用={is_disabled})")
                else:
                    failed_count += 1
                    logger.warning(f"应用策略到用户 {user.username} 失败")
            except Exception as e:
                failed_count += 1
                logger.error(f"应用策略到用户 {user.username} 时出错: {e}")
        
        logger.info(f"策略应用完成: 成功={applied_count}, 失败={failed_count}")

        message = f'规则更新成功，已应用到 {applied_count} 个现有用户'
        if failed_count > 0:
            message += f'，{failed_count} 个用户应用失败'

        return jsonify({
            'success': True,
            'message': message,
            'data': policy.to_dict(),
            'applied_count': applied_count,
            'failed_count': failed_count
        })
    finally:
        db.close()


# ========== Emby策略巡查白名单管理API ==========

@app.route('/api/admin/emby-policy-whitelist', methods=['GET'])
@admin_required
def api_get_emby_policy_whitelist():
    """获取Emby策略巡查白名单列表（从数据库读取）"""
    db = get_db()
    try:
        # 从数据库获取白名单，包含添加者信息
        whitelist_entries = db.query(PolicyWhitelist).all()
        whitelist_users = []

        for entry in whitelist_entries:
            user = entry.user
            admin = entry.admin
            if user:
                whitelist_users.append({
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'emby_user_id': user.emby_user_id,
                    'added_by': admin.username if admin else 'Unknown',
                    'added_by_id': entry.added_by,
                    'reason': entry.reason,
                    'created_at': entry.created_at.isoformat() if entry.created_at else None
                })

        return jsonify({
            'success': True,
            'data': whitelist_users,
            'count': len(whitelist_users)
        })
    finally:
        db.close()


@app.route('/api/admin/emby-policy-whitelist', methods=['POST'])
@admin_required
def api_add_emby_policy_whitelist():
    """添加用户到Emby策略巡查白名单（持久化到数据库）"""
    data = request.get_json()
    user_id = data.get('user_id')
    reason = data.get('reason', '').strip()

    if not user_id:
        return jsonify({
            'success': False,
            'message': '缺少user_id参数'
        }), 400

    # 获取当前管理员ID
    admin_id = session.get('user_id')
    if not admin_id:
        return jsonify({
            'success': False,
            'message': '无法获取管理员信息'
        }), 403

    db = get_db()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'message': '用户不存在'
            }), 404

        # 检查是否已在白名单中
        existing = db.query(PolicyWhitelist).filter_by(user_id=user_id).first()
        if existing:
            return jsonify({
                'success': False,
                'message': f'用户 {user.username} 已在白名单中'
            }), 400

        # 添加到数据库白名单
        whitelist_entry = PolicyWhitelist(
            user_id=user_id,
            added_by=admin_id,
            reason=reason if reason else None
        )
        db.add(whitelist_entry)
        db.commit()

        # 同时更新内存中的白名单（用于巡查时快速检查）
        emby_policy_whitelist[user_id] = True

        logger.info(f"管理员 {session.get('username')} 将用户添加到Emby策略巡查白名单: {user.username} (ID: {user_id}), 原因: {reason or '无'}")

        return jsonify({
            'success': True,
            'message': f'用户 {user.username} 已添加到白名单',
            'data': {
                'user_id': user.id,
                'username': user.username,
                'added_by': session.get('username'),
                'reason': reason
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"添加用户到白名单失败: {e}")
        return jsonify({
            'success': False,
            'message': f'添加失败: {str(e)}'
        }), 500
    finally:
        db.close()


@app.route('/api/admin/emby-policy-whitelist/<int:user_id>', methods=['DELETE'])
@admin_required
def api_remove_emby_policy_whitelist(user_id):
    """从Emby策略巡查白名单移除用户（从数据库删除）"""
    # 获取当前管理员ID
    admin_id = session.get('user_id')
    if not admin_id:
        return jsonify({
            'success': False,
            'message': '无法获取管理员信息'
        }), 403

    db = get_db()
    try:
        # 从数据库查找白名单记录
        whitelist_entry = db.query(PolicyWhitelist).filter_by(user_id=user_id).first()
        if not whitelist_entry:
            return jsonify({
                'success': False,
                'message': '用户不在白名单中'
            }), 404

        user = db.query(User).get(user_id)
        username = user.username if user else f"ID:{user_id}"

        # 从数据库删除
        db.delete(whitelist_entry)
        db.commit()

        # 同时从内存白名单中移除
        if user_id in emby_policy_whitelist:
            del emby_policy_whitelist[user_id]

        logger.warning(f"管理员 {session.get('username')} 将用户从Emby策略巡查白名单移除: {username} (ID: {user_id})")

        return jsonify({
            'success': True,
            'message': f'用户 {username} 已从白名单移除'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"从白名单移除用户失败: {e}")
        return jsonify({
            'success': False,
            'message': f'移除失败: {str(e)}'
        }), 500
    finally:
        db.close()


@app.route('/api/admin/emby-policy-whitelist/batch', methods=['DELETE'])
@admin_required
def api_batch_remove_emby_policy_whitelist():
    """批量从Emby策略巡查白名单移除用户"""
    admin_id = session.get('user_id')
    if not admin_id:
        return jsonify({
            'success': False,
            'message': '无法获取管理员信息'
        }), 403

    data = request.get_json()
    user_ids = data.get('user_ids', [])

    if not user_ids or not isinstance(user_ids, list):
        return jsonify({
            'success': False,
            'message': '请提供要移除的用户ID列表'
        }), 400

    db = get_db()
    try:
        removed_count = 0
        failed_users = []

        for user_id in user_ids:
            try:
                whitelist_entry = db.query(PolicyWhitelist).filter_by(user_id=user_id).first()
                if whitelist_entry:
                    user = db.query(User).get(user_id)
                    username = user.username if user else f"ID:{user_id}"

                    db.delete(whitelist_entry)
                    removed_count += 1

                    # 同时从内存白名单中移除
                    if user_id in emby_policy_whitelist:
                        del emby_policy_whitelist[user_id]

                    logger.warning(f"管理员 {session.get('username')} 批量移除用户从白名单: {username} (ID: {user_id})")
            except Exception as e:
                failed_users.append({'user_id': user_id, 'error': str(e)})
                logger.error(f"批量移除用户 {user_id} 失败: {e}")

        db.commit()

        return jsonify({
            'success': True,
            'message': f'成功移除 {removed_count} 个用户，失败 {len(failed_users)} 个',
            'data': {
                'removed_count': removed_count,
                'failed_count': len(failed_users),
                'failed_users': failed_users
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"批量移除白名单用户失败: {e}")
        return jsonify({
            'success': False,
            'message': f'批量移除失败: {str(e)}'
        }), 500
    finally:
        db.close()


@app.route('/api/admin/emby-policy-whitelist/reset', methods=['POST'])
@admin_required
def api_reset_emby_policy_whitelist():
    """重置Emby策略巡查白名单（清空所有）"""
    admin_id = session.get('user_id')
    if not admin_id:
        return jsonify({
            'success': False,
            'message': '无法获取管理员信息'
        }), 403

    db = get_db()
    try:
        # 获取当前白名单数量
        count = db.query(PolicyWhitelist).count()

        if count == 0:
            return jsonify({
                'success': True,
                'message': '白名单已经是空的',
                'data': {'removed_count': 0}
            })

        # 确认参数
        data = request.get_json() or {}
        confirm = data.get('confirm', False)

        if not confirm:
            return jsonify({
                'success': False,
                'message': f'确定要清空白名单吗？这将移除 {count} 个用户。请在请求中设置 confirm: true 确认操作'
            }), 400

        # 清空数据库白名单
        db.query(PolicyWhitelist).delete()
        db.commit()

        # 清空内存白名单
        global emby_policy_whitelist
        emby_policy_whitelist = {}

        logger.warning(f"管理员 {session.get('username')} 重置了Emby策略巡查白名单，移除了 {count} 个用户")

        return jsonify({
            'success': True,
            'message': f'白名单已重置，移除了 {count} 个用户',
            'data': {'removed_count': count}
        })
    except Exception as e:
        db.rollback()
        logger.error(f"重置白名单失败: {e}")
        return jsonify({
            'success': False,
            'message': f'重置失败: {str(e)}'
        }), 500
    finally:
        db.close()


# 金币套餐 API
@app.route('/api/admin/coin-packages', methods=['GET'])
@admin_required
def api_get_coin_packages():
    """获取所有金币套餐"""
    db = get_db()
    try:
        packages = db.query(CoinPackage).filter_by(is_active=True).order_by(CoinPackage.coin_amount).all()
        return jsonify({
            'success': True,
            'data': [pkg.to_dict(db_session=db) for pkg in packages]
        })
    finally:
        db.close()

@app.route('/api/admin/coin-packages', methods=['POST'])
@admin_required
def api_create_coin_package():
    """创建金币套餐"""
    data = request.get_json()
    db = get_db()
    try:
        duration_type = DurationType(data.get('duration_type'))
        duration_value = data.get('duration_days', 30)

        # 根据时长类型转换时长数值为天数
        if duration_type == DurationType.HOUR:
            actual_days = max(1, duration_value // 24)  # 小时转天，至少1天
        elif duration_type == DurationType.DAY:
            actual_days = duration_value
        elif duration_type == DurationType.WEEK:
            actual_days = duration_value * 7
        elif duration_type == DurationType.MONTH:
            actual_days = duration_value * 30
        elif duration_type == DurationType.QUARTER:
            actual_days = duration_value * 90
        elif duration_type == DurationType.YEAR:
            actual_days = duration_value * 365
        elif duration_type == DurationType.PERMANENT:
            actual_days = 36500  # 永久设为100年
        else:
            actual_days = duration_value

        package = CoinPackage(
            name=data.get('name'),
            description=data.get('description'),
            duration_type=duration_type,
            duration_days=actual_days,
            coin_amount=data.get('coin_amount'),
            price_yuan=data.get('price_yuan'),
            sort_order=data.get('sort_order', 0),
            is_recommended=data.get('is_recommended', False),
            is_gift_card=data.get('is_gift_card', False)
        )
        db.add(package)
        db.commit()
        db.refresh(package)  # 刷新以获取新插入的id
        logger.info(f"管理员创建套餐: {package.name}")
        return jsonify({
            'success': True,
            'message': '套餐创建成功',
            'data': package.to_dict(db_session=db)
        })
    except Exception as e:
        db.rollback()
        logger.error(f"创建套餐失败: {e}")
        return jsonify({'success': False, 'message': '创建失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>', methods=['PUT'])
@admin_required
def api_update_coin_package(pkg_id):
    """更新金币套餐"""
    data = request.get_json()
    db = get_db()
    try:
        package = db.query(CoinPackage).get(pkg_id)
        if not package:
            return jsonify({'success': False, 'message': '套餐不存在'}), 404

        package.name = data.get('name', package.name)
        package.description = data.get('description', package.description)

        # 处理时长类型和数值的转换
        new_duration_type = DurationType(data.get('duration_type', package.duration_type.value))
        new_duration_value = data.get('duration_days', package.duration_days)

        # 如果时长类型或数值有变化，重新计算实际天数
        if new_duration_type != package.duration_type or new_duration_value != package.duration_days:
            if new_duration_type == DurationType.HOUR:
                actual_days = max(1, new_duration_value // 24)
            elif new_duration_type == DurationType.DAY:
                actual_days = new_duration_value
            elif new_duration_type == DurationType.WEEK:
                actual_days = new_duration_value * 7
            elif new_duration_type == DurationType.MONTH:
                actual_days = new_duration_value * 30
            elif new_duration_type == DurationType.QUARTER:
                actual_days = new_duration_value * 90
            elif new_duration_type == DurationType.YEAR:
                actual_days = new_duration_value * 365
            elif new_duration_type == DurationType.PERMANENT:
                actual_days = 36500
            else:
                actual_days = new_duration_value

            package.duration_type = new_duration_type
            package.duration_days = actual_days

        package.coin_amount = data.get('coin_amount', package.coin_amount)
        package.price_yuan = data.get('price_yuan', package.price_yuan)
        package.sort_order = data.get('sort_order', package.sort_order)
        package.is_recommended = data.get('is_recommended', package.is_recommended)
        package.is_gift_card = data.get('is_gift_card', package.is_gift_card)
        db.commit()
        logger.info(f"管理员更新套餐: {package.name}")
        return jsonify({
            'success': True,
            'message': '套餐更新成功',
            'data': package.to_dict(db_session=db)
        })
    except Exception as e:
        db.rollback()
        logger.error(f"更新套餐失败: {e}")
        return jsonify({'success': False, 'message': '更新失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>', methods=['DELETE'])
@admin_required
def api_delete_coin_package(pkg_id):
    """删除金币套餐"""
    db = get_db()
    try:
        package = db.query(CoinPackage).get(pkg_id)
        if not package:
            return jsonify({'success': False, 'message': '套餐不存在'}), 404
        
        # 检查是否有订阅记录引用此套餐
        subscription_count = db.query(SubscriptionRecord).filter_by(package_id=pkg_id).count()

        if subscription_count > 0:
            # 存在订阅记录时，级联删除关联记录后再删除套餐
            logger.info(f"管理员删除套餐（含 {subscription_count} 条订阅记录）: {package.name}")
            db.query(PackageTag).filter_by(package_id=pkg_id).delete()
            db.query(SubscriptionRecord).filter_by(package_id=pkg_id).delete()
            db.delete(package)
            db.commit()
            return jsonify({
                'success': True,
                'message': f'套餐已删除（同时清理了 {subscription_count} 条关联订阅记录）'
            })
        else:
            # 如果没有订阅记录，则直接删除
            db.query(PackageTag).filter_by(package_id=pkg_id).delete()
            db.delete(package)
            db.commit()
            logger.info(f"管理员删除套餐: {package.name}")
            return jsonify({
                'success': True,
                'message': '套餐删除成功'
            })
    except Exception as e:
        db.rollback()
        logger.error(f"删除套餐失败: {e}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>/recommend', methods=['POST'])
@admin_required
def api_toggle_package_recommend(pkg_id):
    """切换套餐推荐状态"""
    data = request.get_json()
    db = get_db()
    try:
        package = db.query(CoinPackage).get(pkg_id)
        if not package:
            return jsonify({'success': False, 'message': '套餐不存在'}), 404
        
        is_recommended = data.get('is_recommended', not package.is_recommended)
        package.is_recommended = is_recommended
        db.commit()
        logger.info(f"管理员更新套餐推荐状态: {package.name} -> {is_recommended}")
        return jsonify({
            'success': True,
            'message': '推荐状态更新成功',
            'data': package.to_dict(db_session=db)
        })
    except Exception as e:
        db.rollback()
        logger.error(f"更新推荐状态失败: {e}")
        return jsonify({'success': False, 'message': '更新失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>/sort', methods=['POST'])
@admin_required
def api_update_package_sort(pkg_id):
    """更新套餐排序"""
    data = request.get_json()
    db = get_db()
    try:
        package = db.query(CoinPackage).get(pkg_id)
        if not package:
            return jsonify({'success': False, 'message': '套餐不存在'}), 404
        
        sort_order = data.get('sort_order', package.sort_order)
        package.sort_order = sort_order
        db.commit()
        logger.info(f"管理员更新套餐排序: {package.name} -> {sort_order}")
        return jsonify({
            'success': True,
            'message': '排序更新成功',
            'data': package.to_dict(db_session=db)
        })
    except Exception as e:
        db.rollback()
        logger.error(f"更新排序失败: {e}")
        return jsonify({'success': False, 'message': '更新失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>/tags', methods=['GET'])
@admin_required
def api_get_package_tags(pkg_id):
    """获取套餐标签列表"""
    db = get_db()
    try:
        package = db.query(CoinPackage).get(pkg_id)
        if not package:
            return jsonify({'success': False, 'message': '套餐不存在'}), 404
        
        tags = db.query(PackageTag).filter_by(package_id=pkg_id).order_by(PackageTag.sort_order).all()
        return jsonify({
            'success': True,
            'data': [tag.to_dict() for tag in tags]
        })
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>/tags', methods=['POST'])
@admin_required
def api_create_package_tag(pkg_id):
    """为套餐添加标签"""
    data = request.get_json()
    db = get_db()
    try:
        package = db.query(CoinPackage).get(pkg_id)
        if not package:
            return jsonify({'success': False, 'message': '套餐不存在'}), 404
        
        tag = PackageTag(
            package_id=pkg_id,
            tag_text=data.get('tag_text'),
            tag_color=data.get('tag_color', '#FF69B4'),
            sort_order=data.get('sort_order', 0)
        )
        db.add(tag)
        db.commit()
        logger.info(f"管理员为套餐添加标签: {package.name} -> {tag.tag_text}")
        return jsonify({
            'success': True,
            'message': '标签添加成功',
            'data': tag.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"添加标签失败: {e}")
        return jsonify({'success': False, 'message': '添加失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>/tags/<int:tag_id>', methods=['PUT'])
@admin_required
def api_update_package_tag(pkg_id, tag_id):
    """更新套餐标签"""
    data = request.get_json()
    db = get_db()
    try:
        tag = db.query(PackageTag).filter_by(id=tag_id, package_id=pkg_id).first()
        if not tag:
            return jsonify({'success': False, 'message': '标签不存在'}), 404
        
        tag.tag_text = data.get('tag_text', tag.tag_text)
        tag.tag_color = data.get('tag_color', tag.tag_color)
        tag.sort_order = data.get('sort_order', tag.sort_order)
        db.commit()
        logger.info(f"管理员更新套餐标签: {tag.tag_text}")
        return jsonify({
            'success': True,
            'message': '标签更新成功',
            'data': tag.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"更新标签失败: {e}")
        return jsonify({'success': False, 'message': '更新失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/<int:pkg_id>/tags/<int:tag_id>', methods=['DELETE'])
@admin_required
def api_delete_package_tag(pkg_id, tag_id):
    """删除套餐标签"""
    db = get_db()
    try:
        tag = db.query(PackageTag).filter_by(id=tag_id, package_id=pkg_id).first()
        if not tag:
            return jsonify({'success': False, 'message': '标签不存在'}), 404
        
        db.delete(tag)
        db.commit()
        logger.info(f"管理员删除套餐标签: {tag.tag_text}")
        return jsonify({
            'success': True,
            'message': '标签删除成功'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"删除标签失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()

@app.route('/api/admin/coin-packages/all', methods=['GET'])
@admin_required
def api_get_all_packages():
    """获取所有金币套餐（包含 inactive）"""
    db = get_db()
    try:
        packages = db.query(CoinPackage).order_by(CoinPackage.sort_order, CoinPackage.coin_amount).all()
        return jsonify({
            'success': True,
            'data': [pkg.to_dict(db_session=db) for pkg in packages]
        })
    finally:
        db.close()


# ============== 优惠码管理 API ==============

@app.route('/api/admin/coupons', methods=['GET'])
@admin_required
def api_get_coupons():
    """获取所有优惠码（分页）"""
    db = get_db()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)
        
        query = db.query(CouponCode).order_by(CouponCode.created_at.desc())
        total = query.count()
        coupons = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'success': True,
            'data': [c.to_dict() for c in coupons],
            'total': total,
            'page': page,
            'per_page': per_page
        })
    finally:
        db.close()


@app.route('/api/admin/coupons', methods=['POST'])
@admin_required
def api_create_coupon():
    """创建优惠码"""
    data = request.get_json()
    db = get_db()
    try:
        code = data.get('code', '').strip()
        discount_percent = data.get('discount_percent', 0)
        max_uses = data.get('max_uses', 1)
        beneficiary_type = data.get('beneficiary_type', 'all')
        beneficiary_user_ids = data.get('beneficiary_user_ids', [])
        valid_from = data.get('valid_from')
        valid_until = data.get('valid_until')
        
        # 验证必填字段
        if not code:
            return jsonify({'success': False, 'message': '优惠码不能为空'}), 400
        if discount_percent < 1 or discount_percent > 100:
            return jsonify({'success': False, 'message': '折扣百分比必须在1-100之间'}), 400
        if max_uses < 1:
            return jsonify({'success': False, 'message': '使用次数必须大于0'}), 400
        
        # 检查优惠码是否已存在
        if db.query(CouponCode).filter_by(code=code).first():
            return jsonify({'success': False, 'message': '优惠码已存在'}), 400
        
        # 解析日期
        valid_from_dt = None
        valid_until_dt = None
        if valid_from:
            valid_from_dt = datetime.fromisoformat(valid_from.replace('Z', '+00:00'))
            # 如果 valid_from 是当前时间或过去时间，设置为 None（立即生效）
            if valid_from_dt <= datetime.now():
                valid_from_dt = None
        if valid_until:
            valid_until_dt = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
        
        # 创建优惠码
        coupon = CouponCode(
            code=code,
            discount_percent=discount_percent,
            max_uses=max_uses,
            current_uses=0,
            beneficiary_type=CouponBeneficiary(beneficiary_type),
            beneficiary_user_ids=json.dumps(beneficiary_user_ids) if beneficiary_user_ids else None,
            valid_from=valid_from_dt,
            valid_until=valid_until_dt,
            is_active=True,
            created_by=session.get('user_id')
        )
        db.add(coupon)
        db.commit()
        
        logger.info(f"管理员创建优惠码: {code}")
        return jsonify({
            'success': True,
            'message': '优惠码创建成功',
            'data': coupon.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"创建优惠码失败: {e}")
        return jsonify({'success': False, 'message': '创建失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/coupons/<int:coupon_id>', methods=['PUT'])
@admin_required
def api_update_coupon(coupon_id):
    """更新优惠码"""
    data = request.get_json()
    db = get_db()
    try:
        coupon = db.query(CouponCode).filter_by(id=coupon_id).first()
        if not coupon:
            return jsonify({'success': False, 'message': '优惠码不存在'}), 404
        
        # 更新字段
        if 'discount_percent' in data:
            coupon.discount_percent = data['discount_percent']
        if 'max_uses' in data:
            coupon.max_uses = data['max_uses']
        if 'beneficiary_type' in data:
            coupon.beneficiary_type = CouponBeneficiary(data['beneficiary_type'])
        if 'beneficiary_user_ids' in data:
            coupon.beneficiary_user_ids = json.dumps(data['beneficiary_user_ids']) if data['beneficiary_user_ids'] else None
        if 'valid_from' in data:
            coupon.valid_from = datetime.fromisoformat(data['valid_from'].replace('Z', '+00:00')) if data['valid_from'] else None
        if 'valid_until' in data:
            coupon.valid_until = datetime.fromisoformat(data['valid_until'].replace('Z', '+00:00')) if data['valid_until'] else None
        if 'is_active' in data:
            coupon.is_active = data['is_active']
        
        db.commit()
        logger.info(f"管理员更新优惠码: {coupon.code}")
        return jsonify({
            'success': True,
            'message': '优惠码更新成功',
            'data': coupon.to_dict()
        })
    except Exception as e:
        db.rollback()
        logger.error(f"更新优惠码失败: {e}")
        return jsonify({'success': False, 'message': '更新失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/coupons/<int:coupon_id>', methods=['DELETE'])
@admin_required
def api_delete_coupon(coupon_id):
    """删除优惠码"""
    db = get_db()
    try:
        coupon = db.query(CouponCode).filter_by(id=coupon_id).first()
        if not coupon:
            return jsonify({'success': False, 'message': '优惠码不存在'}), 404
        
        db.delete(coupon)
        db.commit()
        logger.info(f"管理员删除优惠码: {coupon.code}")
        return jsonify({'success': True, 'message': '优惠码删除成功'})
    except Exception as e:
        db.rollback()
        logger.error(f"删除优惠码失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/coupons/batch-delete', methods=['POST'])
@admin_required
def api_batch_delete_coupons():
    """批量删除优惠码"""
    data = request.get_json()
    coupon_ids = data.get('coupon_ids', [])
    db = get_db()
    try:
        if not coupon_ids:
            return jsonify({'success': False, 'message': '请选择要删除的优惠码'}), 400
        
        deleted_count = db.query(CouponCode).filter(CouponCode.id.in_(coupon_ids)).delete(synchronize_session=False)
        db.commit()
        logger.info(f"管理员批量删除优惠码: {deleted_count} 个")
        return jsonify({
            'success': True,
            'message': f'成功删除 {deleted_count} 个优惠码'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"批量删除优惠码失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()


@app.route('/api/admin/coupons/<int:coupon_id>/usage', methods=['GET'])
@admin_required
def api_get_coupon_usage(coupon_id):
    """获取优惠码使用记录"""
    db = get_db()
    try:
        coupon = db.query(CouponCode).filter_by(id=coupon_id).first()
        if not coupon:
            return jsonify({'success': False, 'message': '优惠码不存在'}), 404
        
        usage_records = db.query(CouponUsageRecord).filter_by(coupon_id=coupon_id).order_by(CouponUsageRecord.used_at.desc()).all()
        
        return jsonify({
            'success': True,
            'data': {
                'coupon': coupon.to_dict(),
                'usage_records': [r.to_dict() for r in usage_records]
            }
        })
    finally:
        db.close()


@app.route('/api/user/coupons/validate', methods=['POST'])
@login_required
def api_validate_coupon():
    """验证优惠码是否可用"""
    data = request.get_json()
    code = data.get('code', '').strip()
    db = get_db()
    try:
        if not code:
            return jsonify({'success': False, 'message': '请输入优惠码'}), 400
        
        coupon = db.query(CouponCode).filter_by(code=code).first()
        if not coupon:
            return jsonify({'success': False, 'message': '优惠码不存在'}), 404
        
        if not coupon.is_valid():
            return jsonify({'success': False, 'message': '优惠码已失效或已用完'}), 400
        
        # 检查受益人规则
        user_id = session.get('user_id')
        user = db.query(User).filter_by(id=user_id).first()
        
        if coupon.beneficiary_type == CouponBeneficiary.NEW_USER:
            # 检查是否为新用户（注册7天内）
            if user.created_at:
                days_since_registration = (datetime.utcnow() - user.created_at).days
                if days_since_registration > 7:
                    return jsonify({'success': False, 'message': '此优惠码仅限新用户使用'}), 400
        
        elif coupon.beneficiary_type == CouponBeneficiary.SPECIFIC:
            # 检查是否在指定用户列表中
            allowed_user_ids = json.loads(coupon.beneficiary_user_ids) if coupon.beneficiary_user_ids else []
            if user_id not in allowed_user_ids:
                return jsonify({'success': False, 'message': '您不在该优惠码的使用范围内'}), 400
        
        return jsonify({
            'success': True,
            'data': {
                'discount_percent': coupon.discount_percent,
                'code': coupon.code
            }
        })
    finally:
        db.close()


# 获取Emby媒体库列表
@app.route('/api/admin/emby-libraries', methods=['GET'])
@admin_required
def api_get_emby_libraries():
    """获取Emby媒体库列表"""
    try:
        if not EmbyAPI.is_configured():
            return jsonify({'success': False, 'message': 'Emby未配置'}), 400
        
        libraries = EmbyAPI.get_libraries()
        if libraries is None:
            logger.warning("获取Emby媒体库列表返回None")
            return jsonify({'success': False, 'message': '无法从Emby服务器获取媒体库列表'}), 500
        
        return jsonify({
            'success': True,
            'data': libraries
        })
    except Exception as e:
        logger.error(f"获取媒体库列表失败: {e}")
        return jsonify({'success': False, 'message': f'获取失败: {str(e)}'}), 500

# ============== 用户商店和充值 API ==============

# 获取用户金币余额
@app.route('/api/user/coins', methods=['GET'])
@login_required
def api_get_user_coins():
    """获取用户金币余额"""
    db = get_db()
    try:
        user_coin = db.query(UserCoin).filter_by(user_id=session['user_id']).first()
        if not user_coin:
            # 创建用户金币记录
            user_coin = UserCoin(user_id=session['user_id'], balance=0, total_recharged=0, total_spent=0)
            db.add(user_coin)
            db.commit()
        
        return jsonify({
            'success': True,
            'data': user_coin.to_dict()
        })
    finally:
        db.close()

# 获取金币套餐列表（用户端）
@app.route('/api/coin-packages', methods=['GET'])
@login_required
def api_get_coin_packages_user():
    """获取所有可用的金币套餐"""
    db = get_db()
    try:
        packages = db.query(CoinPackage).filter_by(is_active=True).order_by(CoinPackage.sort_order.desc(), CoinPackage.coin_amount).all()
        return jsonify({
            'success': True,
            'data': [pkg.to_dict(db_session=db) for pkg in packages]
        })
    finally:
        db.close()

# 购买套餐
@app.route('/api/user/purchase-package', methods=['POST'])
@login_required
def api_purchase_package():
    """用户购买套餐"""
    data = request.get_json()
    package_id = data.get('package_id')

    db = get_db()
    try:
        # 获取套餐信息
        package = db.query(CoinPackage).get(package_id)
        if not package or not package.is_active:
            return jsonify({'success': False, 'message': '套餐不存在或已下架'}), 404

        # 获取用户金币余额
        user_coin = db.query(UserCoin).filter_by(user_id=session['user_id']).first()
        if not user_coin:
            user_coin = UserCoin(user_id=session['user_id'], balance=0, total_recharged=0, total_spent=0)
            db.add(user_coin)
            db.commit()

        # 检查金币是否足够
        if user_coin.balance < package.coin_amount:
            return jsonify({'success': False, 'message': '金币余额不足'}), 400

        # 扣除金币
        user_coin.balance -= package.coin_amount
        user_coin.total_spent += package.coin_amount

        user = db.query(User).get(session['user_id'])

        if package.is_gift_card:
            # 礼品卡购买流程：生成激活码，不延长会员时间
            order_no = 'GIFT' + datetime.now().strftime('%Y%m%d%H%M%S') + str(session['user_id']).zfill(4)

            # 生成唯一激活码
            code_str = generate_activation_code()
            while db.query(ActivationCode).filter_by(code=code_str).first():
                code_str = generate_activation_code()

            # 计算激活码时长（秒）
            duration_seconds = package.duration_days * 86400 if package.duration_type != DurationType.PERMANENT else 0

            activation = ActivationCode(
                code=code_str,
                duration_type=package.duration_type,
                duration_seconds=duration_seconds,
                is_used=False
            )
            db.add(activation)
            db.flush()  # 获取 activation.id

            record = GiftCardPurchaseRecord(
                user_id=session['user_id'],
                package_id=package.id,
                order_no=order_no,
                coin_spent=package.coin_amount,
                activation_code_id=activation.id,
                code=code_str
            )
            db.add(record)

            # 创建金币交易记录
            transaction = CoinTransaction(
                user_id=session['user_id'],
                amount=-package.coin_amount,
                type='gift_card',
                reason=f'购买礼品卡：{package.name}',
                gift_card_code=code_str
            )
            db.add(transaction)

            db.commit()
            db.refresh(user_coin)

            logger.info(f"用户 {user.username} 购买礼品卡 {package.name}，消耗 {package.coin_amount} 金币，卡密 {code_str}")

            return jsonify({
                'success': True,
                'message': '购买成功，请保存您的礼品卡激活码',
                'data': {
                    'is_gift_card': True,
                    'order_no': order_no,
                    'code': code_str,
                    'duration_type': package.duration_type.value,
                    'duration_days': package.duration_days
                }
            })
        else:
            # 普通会员套餐购买流程
            order_no = 'SUB' + datetime.now().strftime('%Y%m%d%H%M%S') + str(session['user_id']).zfill(4)

            # 创建开通套餐记录
            subscription = SubscriptionRecord(
                user_id=session['user_id'],
                package_id=package.id,
                order_no=order_no,
                coin_spent=package.coin_amount,
                duration_days=package.duration_days,
                status='success'
            )
            db.add(subscription)

            # 延长用户激活时间
            now = datetime.now()
            if user.expiry_date and user.expiry_date > now:
                user.expiry_date = user.expiry_date + timedelta(days=package.duration_days)
            else:
                user.expiry_date = now + timedelta(days=package.duration_days)

            # 启用用户
            user.is_active = True
            user.emby_access_disabled = False

            db.commit()
            db.refresh(user_coin)
            db.refresh(user)

            logger.info(f"用户 {user.username} 购买套餐 {package.name}，消耗 {package.coin_amount} 金币")

            # 同步到Emby媒体库 - 启用用户（异步执行，不阻塞主流程）
            if user.emby_user_id:
                try:
                    import threading
                    def sync_emby():
                        try:
                            EmbyAPI.enable_user(user.emby_user_id)
                            logger.info(f"已同步启用Emby用户: {user.emby_user_id}")
                        except Exception as e:
                            logger.error(f"同步启用Emby用户失败: {e}")

                    thread = threading.Thread(target=sync_emby)
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    logger.error(f"启动Emby同步线程失败: {e}")

            # 同步到 WebDAV - 启用用户（异步执行）
            try:
                import threading
                def sync_webdav():
                    try:
                        sync_webdav_user_status(user, True)
                        logger.info(f"已同步启用WebDAV用户: {user.username}")
                    except Exception as e:
                        logger.error(f"同步启用WebDAV用户失败: {e}")

                thread = threading.Thread(target=sync_webdav)
                thread.daemon = True
                thread.start()
            except Exception as e:
                logger.error(f"启动WebDAV同步线程失败: {e}")

            return jsonify({
                'success': True,
                'message': '购买成功',
                'data': {
                    'order_no': order_no,
                    'new_expiry': user.expiry_date.isoformat()
                }
            })
    except Exception as e:
        db.rollback()
        logger.error(f"购买套餐失败: {e}")
        return jsonify({'success': False, 'message': '购买失败，请稍后重试'}), 500
    finally:
        db.close()

# 创建支付订单（新支付流程）- 使用 /api/user/payment-orders 避免与 /api/user/payment-order/<order_no> 冲突
@app.route('/api/user/payment-orders', methods=['POST'])
@login_required
def api_create_payment_order():
    """创建支付订单"""
    try:
        data = request.get_json()
        logger.info(f"创建支付订单 - 接收到的数据: {data}")
        
        if not data:
            return jsonify({'success': False, 'message': '请求数据无效'}), 400
        
        amount = data.get('amount')
        payment_method = data.get('payment_method', 'alipay')
        coupon_code = data.get('coupon_code', '').strip()
        
        logger.info(f"创建支付订单 - 金额: {amount}, 支付方式: {payment_method}, 优惠码: {coupon_code}")
        
        if not amount or amount <= 0:
            return jsonify({'success': False, 'message': '充值金额无效'}), 400
        
        if payment_method not in ['wechat', 'alipay']:
            return jsonify({'success': False, 'message': '支付方式无效'}), 400
    except Exception as e:
        logger.error(f"创建支付订单 - 解析请求数据失败: {e}")
        return jsonify({'success': False, 'message': '请求数据格式错误'}), 400
    
    db = get_db()
    try:
        # 处理优惠码
        original_amount = amount
        discount_amount = 0
        coupon_id = None
        
        if coupon_code:
            coupon = db.query(CouponCode).filter_by(code=coupon_code).first()
            if not coupon:
                return jsonify({'success': False, 'message': '优惠码不存在'}), 400
            
            if not coupon.is_valid():
                return jsonify({'success': False, 'message': '优惠码已失效或已用完'}), 400
            
            # 检查受益人规则
            user_id = session.get('user_id')
            user = db.query(User).filter_by(id=user_id).first()
            
            if coupon.beneficiary_type == CouponBeneficiary.NEW_USER:
                if user.created_at:
                    days_since_registration = (datetime.utcnow() - user.created_at).days
                    if days_since_registration > 7:
                        return jsonify({'success': False, 'message': '此优惠码仅限新用户使用'}), 400
            
            elif coupon.beneficiary_type == CouponBeneficiary.SPECIFIC:
                allowed_user_ids = json.loads(coupon.beneficiary_user_ids) if coupon.beneficiary_user_ids else []
                if user_id not in allowed_user_ids:
                    return jsonify({'success': False, 'message': '您不在该优惠码的使用范围内'}), 400
            
            # 计算优惠金额（保留两位小数，四舍五入）
            from decimal import Decimal, ROUND_HALF_UP
            amount_dec = Decimal(str(amount))
            discount_amount = (amount_dec * Decimal(str(coupon.discount_percent)) / Decimal('100')).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            final_amount = amount_dec - discount_amount
            coupon_id = coupon.id
        
        # 生成订单号
        order_no = 'PAY' + datetime.now().strftime('%Y%m%d%H%M%S') + str(session['user_id']).zfill(4)
        
        # 创建支付订单
        # 金币数量应该基于原始金额（优惠前的金额），因为优惠只是价格优惠，不影响获得的金币数
        coin_amount = original_amount
        order_amount = float(final_amount) if coupon_code else amount
        order_original_amount = float(amount_dec) if coupon_code else None
        order_discount_amount = float(discount_amount) if coupon_code else None
        order = PaymentOrder(
            order_no=order_no,
            user_id=session['user_id'],
            amount=order_amount,  # 实际支付金额
            coin_amount=coin_amount,  # 获得的金币数量（基于原始金额）
            payment_method=payment_method,
            status='pending',
            coupon_code=coupon_code if coupon_code else None,
            original_amount=order_original_amount,
            discount_amount=order_discount_amount,
            coupon_id=coupon_id
        )
        db.add(order)
        db.commit()

        actual_amount = final_amount if coupon_code else amount
        logger.info(f"用户 {session['user_id']} 创建支付订单 {order_no}，支付 {actual_amount} 元（原价 {original_amount}，优惠 {discount_amount}），获得 {coin_amount} 金币，方式 {payment_method}")

        return jsonify({
            'success': True,
            'message': '订单创建成功',
            'data': {
                'order_no': order_no,
                'amount': order_amount,
                'original_amount': order_original_amount,
                'discount_amount': order_discount_amount,
                'coin_amount': coin_amount,
                'payment_method': payment_method,
                'coupon_code': coupon_code if coupon_code else None
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"创建支付订单失败: {e}")
        return jsonify({'success': False, 'message': '创建订单失败'}), 500
    finally:
        db.close()

# 上传退款收款码
@app.route('/api/user/payment-order/<string:order_no>/refund-qrcode', methods=['POST'])
@login_required
def api_upload_refund_qrcode(order_no):
    """上传退款收款码"""
    if 'qrcode' not in request.files:
        return jsonify({'success': False, 'message': '请选择图片文件'}), 400
    
    file = request.files['qrcode']
    if file.filename == '':
        return jsonify({'success': False, 'message': '请选择图片文件'}), 400
    
    # 检查文件类型
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({'success': False, 'message': '只支持 PNG、JPG、JPEG、GIF 格式的图片'}), 400
    
    # 文件魔数校验 - 防止伪装成图片的恶意文件
    # 读取文件头部进行验证
    file_head = file.read(16)
    file.seek(0)  # 重置文件指针
    
    # 图片文件魔数签名
    image_signatures = {
        b'\x89PNG\r\n\x1a\n': 'png',  # PNG
        b'\xff\xd8\xff': 'jpg',  # JPEG/JPG
        b'GIF87a': 'gif',  # GIF
        b'GIF89a': 'gif',  # GIF
        b'BM': 'bmp',  # BMP
        b'RIFF': 'webp',  # WebP (RIFF....WEBP)
    }
    
    is_valid_image = False
    detected_format = None
    
    for signature, img_format in image_signatures.items():
        if file_head.startswith(signature):
            is_valid_image = True
            detected_format = img_format
            break
    
    # 特殊处理WebP格式
    if file_head.startswith(b'RIFF') and b'WEBP' in file_head:
        is_valid_image = True
        detected_format = 'webp'
    
    if not is_valid_image:
        logger.warning(f"用户 {session['user_id']} 尝试上传非图片文件，文件名: {file.filename}")
        return jsonify({'success': False, 'message': '文件内容不是有效的图片格式，请勿上传伪装成图片的可执行文件'}), 400
    
    # 验证文件扩展名与内容是否匹配
    file_ext = file.filename.rsplit('.', 1)[1].lower()
    if file_ext in ['jpg', 'jpeg'] and detected_format not in ['jpg', 'jpeg']:
        return jsonify({'success': False, 'message': f'文件扩展名与内容不匹配，检测到格式: {detected_format}'}), 400
    if file_ext == 'png' and detected_format != 'png':
        return jsonify({'success': False, 'message': f'文件扩展名与内容不匹配，检测到格式: {detected_format}'}), 400
    if file_ext == 'gif' and detected_format != 'gif':
        return jsonify({'success': False, 'message': f'文件扩展名与内容不匹配，检测到格式: {detected_format}'}), 400
    
    # 检查文件大小（最大5MB）
    file.seek(0, 2)  # 移动到文件末尾
    file_size = file.tell()
    file.seek(0)  # 重置文件指针
    
    if file_size > 5 * 1024 * 1024:  # 5MB
        return jsonify({'success': False, 'message': '图片大小不能超过5MB'}), 400
    
    db = get_db()
    try:
        # 检查订单是否存在且属于当前用户
        order = db.query(PaymentOrder).filter_by(order_no=order_no, user_id=session['user_id']).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404
        
        # 确保目录存在
        upload_dir = os.path.join('static', 'images', 'refund_qrcodes')
        os.makedirs(upload_dir, exist_ok=True)
        
        # 保存文件（使用安全的文件扩展名）
        safe_ext = 'jpg' if detected_format in ['jpg', 'jpeg'] else detected_format
        filename = f"refund_{order_no}_{int(datetime.now().timestamp())}.{safe_ext}"
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)
        
        # 更新订单
        order.refund_qrcode_path = filepath
        db.commit()
        
        logger.info(f"用户 {session['user_id']} 上传退款收款码，订单 {order_no}")
        
        return jsonify({
            'success': True,
            'message': '收款码上传成功',
            'data': {'path': filepath}
        })
    except Exception as e:
        db.rollback()
        logger.error(f"上传退款收款码失败: {e}")
        return jsonify({'success': False, 'message': '上传失败'}), 500
    finally:
        db.close()

# 确认已支付
@app.route('/api/user/payment-order/<string:order_no>/confirm-paid', methods=['POST'])
@login_required
def api_confirm_paid(order_no):
    """用户确认已支付"""
    db = get_db()
    try:
        # 检查订单是否存在且属于当前用户
        order = db.query(PaymentOrder).filter_by(order_no=order_no, user_id=session['user_id']).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404
        
        if order.status != 'pending':
            return jsonify({'success': False, 'message': '订单状态错误'}), 400
        
        # 检查是否上传了退款收款码
        if not order.refund_qrcode_path:
            return jsonify({'success': False, 'message': '请先上传退款收款码'}), 400
        
        # 更新订单状态为已支付（待审核）
        order.status = 'paid'
        order.paid_at = datetime.now()
        db.commit()
        
        logger.info(f"用户 {session['user_id']} 确认已支付，订单 {order_no}，等待管理员审核")
        
        return jsonify({
            'success': True,
            'message': '支付确认成功，等待管理员审核'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"确认支付失败: {e}")
        return jsonify({'success': False, 'message': '确认失败'}), 500
    finally:
        db.close()

# 获取支付订单详情
@app.route('/api/user/payment-order/<string:order_no>', methods=['GET'])
@login_required
def api_get_payment_order(order_no):
    """获取支付订单详情"""
    db = get_db()
    try:
        order = db.query(PaymentOrder).filter_by(order_no=order_no, user_id=session['user_id']).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404

        return jsonify({
            'success': True,
            'data': order.to_dict()
        })
    finally:
        db.close()

# 用户撤销支付订单
@app.route('/api/user/payment-order/<string:order_no>/cancel', methods=['POST'])
@login_required
def api_cancel_payment_order(order_no):
    """用户撤销支付订单"""
    db = get_db()
    try:
        order = db.query(PaymentOrder).filter_by(order_no=order_no, user_id=session['user_id']).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404

        # 检查订单状态，只有 pending 或 paid 状态的订单可以撤销
        if order.status not in ['pending', 'paid']:
            return jsonify({'success': False, 'message': '该订单状态不允许撤销'}), 400

        # 更新订单状态为已撤销
        order.status = 'cancelled'
        order.cancelled_at = datetime.now()
        order.refund_status = 'pending'  # 设置退款状态为待处理

        db.commit()
        logger.info(f"用户 {session['user_id']} 撤销订单 {order_no}")

        return jsonify({
            'success': True,
            'message': '订单已撤销，等待管理员处理退款'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"撤销订单失败: {e}")
        return jsonify({'success': False, 'message': '撤销订单失败'}), 500
    finally:
        db.close()

# 获取用户支付订单列表
@app.route('/api/user/payment-orders/list', methods=['GET'])
@login_required
def api_get_user_payment_orders():
    """获取用户所有支付订单"""
    db = get_db()
    try:
        orders = db.query(PaymentOrder).filter_by(user_id=session['user_id']).order_by(PaymentOrder.created_at.desc()).all()
        logger.info(f"获取用户 {session['user_id']} 的支付订单，共 {len(orders)} 条")
        return jsonify({
            'success': True,
            'data': [order.to_dict() for order in orders]
        })
    finally:
        db.close()

# 获取支付二维码图片
@app.route('/api/payment-qrcode/<string:payment_method>', methods=['GET'])
@login_required
def api_get_payment_qrcode(payment_method):
    """获取支付二维码图片"""
    if payment_method not in ['wechat', 'alipay']:
        return jsonify({'success': False, 'message': '支付方式无效'}), 400
    
    # 查找二维码图片
    qrcode_dir = os.path.join('static', 'images', 'payment_qrcodes', payment_method)
    if not os.path.exists(qrcode_dir):
        return jsonify({'success': False, 'message': '二维码图片不存在'}), 404
    
    # 获取第一个图片文件
    files = [f for f in os.listdir(qrcode_dir) if f.endswith(('.png', '.jpg', '.jpeg', '.gif'))]
    if not files:
        return jsonify({'success': False, 'message': '二维码图片不存在'}), 404
    
    qrcode_path = os.path.join('static', 'images', 'payment_qrcodes', payment_method, files[0])
    
    return jsonify({
        'success': True,
        'data': {'qrcode_url': '/' + qrcode_path.replace('\\', '/')}
    })

# 旧的充值API（已废弃，保留兼容性但不自动充值）
@app.route('/api/user/recharge', methods=['POST'])
@login_required
def api_create_recharge():
    """创建充值订单（已废弃，请使用 /api/user/payment-order）"""
    return jsonify({
        'success': False,
        'message': '请使用新的支付流程'
    }), 400

# ================= 管理员支付审核 API =================

# 获取待审核的支付订单列表
@app.route('/api/admin/payment-orders', methods=['GET'])
@admin_required
def api_get_payment_orders():
    """获取支付订单列表（管理员，支持分页）"""
    status = request.args.get('status', 'paid')  # 默认获取已支付待审核的
    
    # 获取分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 限制每页最大记录数
    if per_page > 100:
        per_page = 100
    
    # 计算偏移量
    offset = (page - 1) * per_page
    
    db = get_db()
    try:
        query = db.query(PaymentOrder)
        # 只有当status不是'all'时才过滤
        if status and status != 'all':
            query = query.filter_by(status=status)
        
        # 获取总记录数
        total = query.count()
        
        # 获取分页数据
        orders = query.order_by(PaymentOrder.created_at.desc()).offset(offset).limit(per_page).all()
        
        # 计算总页数
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'success': True,
            'data': [order.to_dict() for order in orders],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': total_pages
            }
        })
    finally:
        db.close()

# 审核通过支付订单
@app.route('/api/admin/payment-orders/<string:order_no>/approve', methods=['POST'])
@admin_required
def api_approve_payment_order(order_no):
    """审核通过支付订单"""
    db = get_db()
    try:
        order = db.query(PaymentOrder).filter_by(order_no=order_no).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404
        
        if order.status != 'paid':
            return jsonify({'success': False, 'message': '订单状态错误'}), 400
        
        # 更新订单状态
        order.status = 'approved'
        order.approved_at = datetime.now()
        order.approved_by = session['user_id']
        
        # 增加用户金币
        user_coin = db.query(UserCoin).filter_by(user_id=order.user_id).first()
        if not user_coin:
            user_coin = UserCoin(user_id=order.user_id, balance=0, total_recharged=0, total_spent=0)
            db.add(user_coin)
        
        user_coin.balance += order.coin_amount
        user_coin.total_recharged += order.coin_amount
        
        # 创建金币交易记录
        transaction = CoinTransaction(
            user_id=order.user_id,
            amount=order.coin_amount,
            type='recharge',
            reason=f'充值订单 {order_no} 审核通过',
            created_by=session['user_id']
        )
        db.add(transaction)
        
        # 如果使用了优惠码，记录使用情况
        if order.coupon_id and order.coupon_code:
            coupon = db.query(CouponCode).filter_by(id=order.coupon_id).first()
            if coupon:
                # 增加优惠码使用次数
                coupon.current_uses += 1
                
                # 创建优惠码使用记录
                usage_record = CouponUsageRecord(
                    coupon_id=coupon.id,
                    user_id=order.user_id,
                    order_no=order.order_no,
                    original_amount=order.original_amount or order.amount,
                    discount_amount=order.discount_amount or 0,
                    final_amount=order.amount,
                    used_at=datetime.now()
                )
                db.add(usage_record)
                
                logger.info(f"优惠码 {order.coupon_code} 被使用，订单 {order_no}，优惠金额 {order.discount_amount} 元")
        
        db.commit()
        
        logger.info(f"管理员 {session['user_id']} 审核通过支付订单 {order_no}，用户 {order.user_id} 获得 {order.coin_amount} 金币")
        
        return jsonify({
            'success': True,
            'message': '审核通过成功'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"审核支付订单失败: {e}")
        return jsonify({'success': False, 'message': '审核失败'}), 500
    finally:
        db.close()

# 拒绝支付订单
@app.route('/api/admin/payment-orders/<string:order_no>/reject', methods=['POST'])
@admin_required
def api_reject_payment_order(order_no):
    """拒绝支付订单"""
    db = get_db()
    try:
        order = db.query(PaymentOrder).filter_by(order_no=order_no).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404
        
        if order.status != 'paid':
            return jsonify({'success': False, 'message': '订单状态错误'}), 400
        
        order.status = 'rejected'
        db.commit()
        
        logger.info(f"管理员 {session['user_id']} 拒绝支付订单 {order_no}")
        
        return jsonify({
            'success': True,
            'message': '已拒绝该支付订单'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"拒绝支付订单失败: {e}")
        return jsonify({'success': False, 'message': '操作失败'}), 500
    finally:
        db.close()

# 删除支付订单
@app.route('/api/admin/payment-orders/<string:order_no>', methods=['DELETE'])
@admin_required
def api_delete_payment_order(order_no):
    """删除支付订单"""
    db = get_db()
    try:
        order = db.query(PaymentOrder).filter_by(order_no=order_no).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404
        
        # 删除关联的退款收款码图片
        if order.refund_qrcode_path and os.path.exists(order.refund_qrcode_path):
            try:
                os.remove(order.refund_qrcode_path)
            except:
                pass
        
        db.delete(order)
        db.commit()
        
        logger.info(f"管理员 {session['user_id']} 删除支付订单 {order_no}")
        
        return jsonify({
            'success': True,
            'message': '订单删除成功'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"删除支付订单失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()

# 批量删除支付订单
@app.route('/api/admin/payment-orders/batch-delete', methods=['POST'])
@admin_required
def api_batch_delete_payment_orders():
    """批量删除支付订单"""
    data = request.get_json()
    order_nos = data.get('order_nos', [])
    
    if not order_nos:
        return jsonify({'success': False, 'message': '请选择要删除的订单'}), 400
    
    db = get_db()
    try:
        deleted_count = 0
        for order_no in order_nos:
            order = db.query(PaymentOrder).filter_by(order_no=order_no).first()
            if order:
                # 删除关联的退款收款码图片
                if order.refund_qrcode_path and os.path.exists(order.refund_qrcode_path):
                    try:
                        os.remove(order.refund_qrcode_path)
                    except:
                        pass
                db.delete(order)
                deleted_count += 1
        
        db.commit()
        
        logger.info(f"管理员 {session['user_id']} 批量删除 {deleted_count} 个支付订单")
        
        return jsonify({
            'success': True,
            'message': f'成功删除 {deleted_count} 个订单'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"批量删除支付订单失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()

# 处理退款申请
@app.route('/api/admin/payment-orders/<string:order_no>/refund', methods=['POST'])
@admin_required
def api_process_refund(order_no):
    """处理退款申请"""
    data = request.get_json()
    refund_status = data.get('refund_status')
    
    if refund_status not in ['refunded', 'rejected']:
        return jsonify({'success': False, 'message': '无效的退款状态'}), 400
    
    db = get_db()
    try:
        order = db.query(PaymentOrder).filter_by(order_no=order_no).first()
        if not order:
            return jsonify({'success': False, 'message': '订单不存在'}), 404
        
        if order.status != 'cancelled':
            return jsonify({'success': False, 'message': '该订单状态不允许处理退款'}), 400
        
        if order.refund_status != 'pending':
            return jsonify({'success': False, 'message': '该订单退款已处理'}), 400
        
        # 更新退款状态
        order.refund_status = refund_status
        order.refund_processed_at = datetime.now()
        order.refund_processed_by = session['user_id']
        
        db.commit()
        
        action_text = '确认退款' if refund_status == 'refunded' else '拒绝退款'
        logger.info(f"管理员 {session['user_id']} {action_text} 订单 {order_no}")
        
        return jsonify({
            'success': True,
            'message': f'{action_text}成功'
        })
    except Exception as e:
        db.rollback()
        logger.error(f"处理退款失败: {e}")
        return jsonify({'success': False, 'message': '处理退款失败'}), 500
    finally:
        db.close()

# 获取充值记录
@app.route('/api/user/recharge-records', methods=['GET'])
@login_required
def api_get_recharge_records():
    """获取用户充值记录"""
    db = get_db()
    try:
        records = db.query(RechargeRecord).filter_by(user_id=session['user_id']).order_by(RechargeRecord.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [record.to_dict() for record in records]
        })
    finally:
        db.close()

# 获取开通套餐记录
@app.route('/api/user/subscription-records', methods=['GET'])
@login_required
def api_get_subscription_records():
    """获取用户开通套餐记录"""
    db = get_db()
    try:
        records = db.query(SubscriptionRecord).filter_by(user_id=session['user_id']).order_by(SubscriptionRecord.created_at.desc()).all()
        
        # 获取套餐名称
        result = []
        for record in records:
            record_dict = record.to_dict()
            package = db.query(CoinPackage).get(record.package_id)
            record_dict['package_name'] = package.name if package else '未知套餐'
            result.append(record_dict)
        
        return jsonify({
            'success': True,
            'data': result
        })
    finally:
        db.close()

# 获取礼品卡购买记录
@app.route('/api/user/gift-card-records', methods=['GET'])
@login_required
def api_get_gift_card_records():
    """获取用户礼品卡购买记录"""
    db = get_db()
    try:
        records = db.query(GiftCardPurchaseRecord).filter_by(user_id=session['user_id']).order_by(GiftCardPurchaseRecord.created_at.desc()).all()

        result = []
        for record in records:
            record_dict = record.to_dict()
            package = db.query(CoinPackage).get(record.package_id) if record.package_id else None
            record_dict['package_name'] = package.name if package else '已删除套餐'
            if record.activation_code:
                record_dict['is_used'] = record.activation_code.is_used
                record_dict['used_at'] = record.activation_code.used_at.isoformat() if record.activation_code.used_at else None
                record_dict['used_by'] = record.activation_code.used_by
            else:
                record_dict['is_used'] = False
            result.append(record_dict)

        return jsonify({
            'success': True,
            'data': result
        })
    finally:
        db.close()

# 获取用户公告（未读且有效的）
@app.route('/api/user/announcements', methods=['GET'])
@login_required
def api_get_user_announcements():
    """获取用户需要显示的公告"""
    db = get_db()
    try:
        now = datetime.now()
        
        # 获取所有有效的公告，并检查时间范围
        announcements = db.query(Announcement).filter_by(is_active=True).all()
        
        # 过滤掉不在有效时间范围内、用户已读或选择今日不再显示的公告
        result = []
        today = now.date()
        
        for ann in announcements:
            # 检查公告是否在有效时间范围内
            # 如果有开始时间，且当前时间早于开始时间，则跳过
            if ann.start_time and now < ann.start_time:
                continue
            
            # 如果有结束时间，且当前时间晚于结束时间，则跳过
            if ann.end_time and now > ann.end_time:
                continue
            
            # 检查用户阅读记录
            user_ann = db.query(UserAnnouncement).filter_by(
                user_id=session['user_id'],
                announcement_id=ann.id
            ).first()
            
            # 如果用户选择今日不再显示，且是今天设置的，则跳过
            if user_ann and user_ann.dont_show_today:
                if user_ann.updated_at and user_ann.updated_at.date() == today:
                    continue
            
            # 如果用户已读，检查公告是否在用户阅读后更新过
            if user_ann and user_ann.is_read:
                # 如果用户阅读时间晚于或等于公告更新时间，则跳过
                if user_ann.read_at and ann.updated_at and user_ann.read_at >= ann.updated_at:
                    continue
                # 如果没有阅读时间或公告更新时间，视为已读
                if not ann.updated_at or not user_ann.read_at:
                    continue
            
            result.append(ann.to_dict())
        
        return jsonify({
            'success': True,
            'data': result
        })
    finally:
        db.close()

# 获取公共公告（不需要登录）
@app.route('/api/public/announcements', methods=['GET'])
def api_get_public_announcements():
    """获取当前有效的公告（公共接口，不需要登录）"""
    db = get_db()
    try:
        now = datetime.now()
        
        # 获取所有有效的公告，并检查时间范围
        announcements = db.query(Announcement).filter_by(is_active=True).all()
        
        # 过滤掉不在有效时间范围内的公告
        result = []
        
        for ann in announcements:
            # 检查公告是否在有效时间范围内
            # 如果有开始时间，且当前时间早于开始时间，则跳过
            if ann.start_time and now < ann.start_time:
                continue
            
            # 如果有结束时间，且当前时间晚于结束时间，则跳过
            if ann.end_time and now > ann.end_time:
                continue
            
            result.append(ann.to_dict())
        
        return jsonify({
            'success': True,
            'data': result
        })
    finally:
        db.close()

# 标记公告今日不再显示
@app.route('/api/user/announcements/<int:ann_id>/dont-show-today', methods=['POST'])
@login_required
def api_mark_announcement_dont_show_today(ann_id):
    """标记公告今日不再显示（不标记为已读）"""
    data = request.get_json() or {}
    dont_show_today = data.get('dont_show_today', True)
    
    db = get_db()
    try:
        # 查找或创建用户公告记录
        user_ann = db.query(UserAnnouncement).filter_by(
            user_id=session['user_id'],
            announcement_id=ann_id
        ).first()
        
        if not user_ann:
            user_ann = UserAnnouncement(
                user_id=session['user_id'],
                announcement_id=ann_id,
                is_read=False  # 不标记为已读
            )
            db.add(user_ann)
        else:
            # 不修改is_read状态，只更新dont_show_today
            user_ann.is_read = False  # 确保不标记为已读
        
        user_ann.dont_show_today = dont_show_today
        user_ann.updated_at = datetime.now()
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': '已设置今日不再显示'
        })
    finally:
        db.close()

# 标记公告已读
@app.route('/api/user/announcements/<int:ann_id>/read', methods=['POST'])
@login_required
def api_mark_announcement_read(ann_id):
    """标记公告为已读"""
    data = request.get_json() or {}
    dont_show_today = data.get('dont_show_today', False)
    
    db = get_db()
    try:
        # 查找或创建用户公告记录
        user_ann = db.query(UserAnnouncement).filter_by(
            user_id=session['user_id'],
            announcement_id=ann_id
        ).first()
        
        if not user_ann:
            user_ann = UserAnnouncement(
                user_id=session['user_id'],
                announcement_id=ann_id
            )
            db.add(user_ann)
        
        user_ann.is_read = True
        user_ann.dont_show_today = dont_show_today
        user_ann.read_at = datetime.now()
        user_ann.updated_at = datetime.now()
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': '已标记为已读'
        })
    finally:
        db.close()

# ============== 图片上传 API ==============

@app.route('/api/admin/upload-image', methods=['POST'])
@admin_required
def api_admin_upload_image():
    """上传图片（用于公告编辑器等）"""
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'message': '未找到图片文件'}), 400

        file = request.files['image']
        if file.filename == '':
            return jsonify({'success': False, 'message': '未选择文件'}), 400

        # 验证文件类型
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if file_ext not in allowed_extensions:
            return jsonify({'success': False, 'message': '不支持的文件类型，请上传图片文件'}), 400

        # 验证文件大小（最大5MB）
        file.seek(0, 2)  # 移动到文件末尾
        file_size = file.tell()  # 获取文件大小
        file.seek(0)  # 重置文件指针
        if file_size > 5 * 1024 * 1024:  # 5MB
            return jsonify({'success': False, 'message': '文件大小不能超过5MB'}), 400

        # 魔数验证 - 检查文件头以确保是真正的图片文件
        file_head = file.read(16)
        file.seek(0)  # 重置文件指针

        # 定义图片文件的魔数签名
        image_signatures = {
            'png': [b'\x89PNG\r\n\x1a\n'],
            'jpg': [b'\xff\xd8\xff', b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xe8'],
            'jpeg': [b'\xff\xd8\xff', b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xe8'],
            'gif': [b'GIF87a', b'GIF89a'],
            'webp': [b'RIFF'],  # WebP 以 RIFF 开头
            'bmp': [b'BM'],
        }

        # 检查文件头是否匹配对应的图片类型
        valid_signature = False
        expected_signatures = image_signatures.get(file_ext, [])
        for sig in expected_signatures:
            if file_head.startswith(sig):
                valid_signature = True
                break

        # 对于 WebP 需要额外检查 WEBP 标识
        if file_ext == 'webp' and file_head.startswith(b'RIFF'):
            # WebP 文件格式: RIFF....WEBP
            if b'WEBP' in file_head[:12]:
                valid_signature = True
            else:
                valid_signature = False

        if not valid_signature:
            return jsonify({'success': False, 'message': '文件内容不是有效的图片格式，可能已被篡改'}), 400

        # 检查是否为可执行文件伪装（额外的安全检查）
        executable_signatures = [
            b'\x4d\x5a',  # Windows EXE/DLL (MZ)
            b'\x7f\x45\x4c\x46',  # ELF (Linux可执行文件)
            b'\xca\xfe\xba\xbe',  # Java class文件
            b'%PDF',  # PDF 文件
            b'<?xml',  # XML 文件（可能包含恶意脚本）
            b'<?php',  # PHP 文件
            b'#!/',    # Shebang 脚本
        ]

        for sig in executable_signatures:
            if file_head.startswith(sig):
                return jsonify({'success': False, 'message': '检测到可疑文件类型，不允许上传可执行文件或脚本'}), 400

        # 生成安全的文件名（使用UUID避免文件名冲突和路径遍历）
        import uuid
        filename = f"{uuid.uuid4().hex}.{file_ext}"

        # 确保上传目录存在
        upload_dir = os.path.join(BASE_DIR, 'static', 'uploads', 'images')
        os.makedirs(upload_dir, exist_ok=True)

        # 保存文件
        file_path = os.path.join(upload_dir, filename)

        # 验证保存路径是否在允许的目录内（防止路径遍历）
        real_upload_dir = os.path.realpath(upload_dir)
        real_file_path = os.path.realpath(file_path)
        if not real_file_path.startswith(real_upload_dir):
            return jsonify({'success': False, 'message': '无效的文件路径'}), 400

        file.save(file_path)

        # 返回图片URL
        image_url = f"/static/uploads/images/{filename}"

        logger.info(f"管理员上传图片: {filename}")
        return jsonify({
            'success': True,
            'data': {
                'filePath': image_url,  # EasyMDE 需要的字段
                'url': image_url
            }
        })
    except Exception as e:
        logger.error(f"上传图片失败: {e}")
        return jsonify({'success': False, 'message': '上传失败'}), 500


# ============== 邮件系统 API ==============

@app.route('/api/admin/email/config', methods=['GET'])
@admin_required
def api_admin_email_config_get():
    """获取邮件配置"""
    try:
        config = EmailService.get_config()
        if not config:
            # 初始化默认配置
            default_config = {
                'system_email': '',
                'smtp_server': '',
                'smtp_port': 587,
                'smtp_password': '',
                'sender_name': 'Emby Manager',
                'email_template': '''<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <p>亲爱的 {{username}}，您好！</p>
    
    <p>您的验证码是：</p>
    <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; font-weight: bold; color: #ff6b9d; margin: 20px 0;">
        {{code}}
    </div>
    
    <p>该验证码将在 <strong>{{expire_minutes}} 分钟</strong>后过期，请尽快使用。</p>
    
    <p>如非本人操作，请忽略此邮件。</p>
    
    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="color: #999; font-size: 12px;">{{site_name}} 团队</p>
</div>''',
                'email_subject': '验证码通知',
                'is_enabled': False
            }
            return jsonify({
                'success': True,
                'data': default_config
            })
        return jsonify({
            'success': True,
            'data': config
        })
    except Exception as e:
        logger.error(f"获取邮件配置失败: {e}")
        return jsonify({'success': False, 'message': f'获取邮件配置失败: {str(e)}'}), 500


@app.route('/api/admin/email/test', methods=['POST'])
@admin_required
def api_admin_email_test():
    """测试邮件连接"""
    data = request.get_json()
    success, message = EmailService.test_connection(data)
    return jsonify({
        'success': success,
        'message': message
    })


@app.route('/api/admin/email/save', methods=['POST'])
@admin_required
def api_admin_email_save():
    """保存邮件配置"""
    data = request.get_json()
    success, message = EmailService.save_config(data)
    if success:
        logger.info(f"管理员保存邮件配置: {session.get('user_id')}")
        return jsonify({
            'success': True,
            'message': message,
            'data': EmailService.get_config()
        })
    else:
        return jsonify({
            'success': False,
            'message': message
        }), 500


@app.route('/api/admin/clear-email-config', methods=['POST'])
@admin_required
def api_clear_email_config():
    """清除邮箱配置"""
    db = get_db()
    try:
        config = db.query(EmailConfig).first()
        if config:
            # 清空所有邮箱配置字段
            config.provider = 'resend'
            config.system_email = None
            config.resend_api_key = None
            config.smtp_server = None
            config.smtp_port = 587
            config.smtp_password = None
            config.sender_name = 'Emby Manager'
            config.email_template = None
            config.email_subject = '验证码通知'
            config.is_enabled = False
            config.updated_at = datetime.now()
            db.commit()
            logger.info(f"管理员清除邮件配置: {session.get('user_id')}")
            return jsonify({
                'success': True,
                'message': '邮箱配置已清除'
            })
        else:
            return jsonify({
                'success': True,
                'message': '没有需要清除的配置'
            })
    except Exception as e:
        db.rollback()
        logger.error(f"清除邮件配置失败: {e}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500
    finally:
        db.close()


@app.route('/api/admin/email-logs', methods=['GET'])
@admin_required
def api_admin_email_logs_get():
    """获取邮件发送记录（支持分页）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20
    
    try:
        result = EmailService.get_email_logs(page, per_page)
        return jsonify({
            'success': True,
            'data': {
                'items': result['logs'],
                'total': result['total'],
                'page': result['page'],
                'per_page': result['per_page'],
                'total_pages': (result['total'] + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"获取邮件日志失败: {e}")
        return jsonify({'success': False, 'message': f'获取邮件日志失败: {str(e)}'}), 500


@app.route('/api/admin/email-logs', methods=['DELETE'])
@admin_required
def api_admin_email_logs_delete():
    """批量删除邮件记录"""
    data = request.get_json()
    ids = data.get('ids', [])
    
    if not ids or not isinstance(ids, list):
        return jsonify({'success': False, 'message': '请提供要删除的记录ID列表'}), 400
    
    success, message = EmailService.delete_email_logs(ids)
    if success:
        logger.info(f"管理员批量删除邮件记录: {len(ids)}条")
        return jsonify({
            'success': True,
            'message': message,
            'deleted_count': len(ids)
        })
    else:
        return jsonify({
            'success': False,
            'message': message
        }), 500


# ============== 验证码发送与验证 API ==============

def generate_verification_code():
    """生成6位数字验证码"""
    return ''.join(random.choices(string.digits, k=6))


def check_email_send_limit(db, email):
    """检查邮箱发送限制（3次/天，只计算成功发送）
    返回: (是否允许发送, 已发送次数, 剩余次数)
    """
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    count = db.query(EmailSendLog).filter(
        EmailSendLog.email == email,
        EmailSendLog.created_at >= today_start,
        EmailSendLog.created_at < today_end,
        EmailSendLog.is_success == True  # 只计算成功发送的次数
    ).count()
    
    remaining = max(0, 3 - count)
    return count < 3, count, remaining


def check_cooldown(db, email):
    """检查60秒冷却时间"""
    cooldown_time = datetime.now() - timedelta(seconds=60)
    recent_send = db.query(EmailSendLog).filter(
        EmailSendLog.email == email,
        EmailSendLog.created_at >= cooldown_time
    ).first()
    
    return recent_send is None


@app.route('/api/send-verification-code', methods=['POST'])
def send_verification_code():
    """发送验证码"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    purpose = data.get('purpose', '').strip()
    username = data.get('username', '').strip() or '用户'
    
    if not email:
        return jsonify({'success': False, 'message': '请提供邮箱地址'}), 400
    
    if not purpose or purpose not in ['register', 'bind', 'forgot_password']:
        return jsonify({'success': False, 'message': '无效的用途参数'}), 400
    
    # 检查邮件服务是否配置
    if not EmailService.is_configured():
        return jsonify({'success': False, 'message': '邮件服务未配置，请联系管理员'}), 503
    
    db = get_db()
    try:
        # 检查每日发送限制
        can_send, sent_count, remaining_count = check_email_send_limit(db, email)
        if not can_send:
            return jsonify({
                'success': False, 
                'message': f'该邮箱今日发送次数已达上限（{sent_count}/3次），请明天再试',
                'data': {
                    'sent_count': sent_count,
                    'limit': 3,
                    'remaining': remaining_count,
                    'reset_time': '次日00:00'
                }
            }), 429
        
        # 检查冷却时间
        if not check_cooldown(db, email):
            return jsonify({'success': False, 'message': '发送过于频繁，请60秒后再试'}), 429
        
        # 根据用途进行额外验证
        if purpose == 'register':
            # 检查邮箱是否已被注册
            existing_user = db.query(User).filter_by(email=email).first()
            if existing_user:
                return jsonify({'success': False, 'message': '该邮箱已被注册'}), 400
        elif purpose == 'forgot_password':
            # 检查邮箱是否存在
            existing_user = db.query(User).filter_by(email=email).first()
            if not existing_user:
                return jsonify({'success': False, 'message': '该邮箱未绑定任何账号'}), 400
        
        # 生成6位数字验证码
        code = generate_verification_code()
        
        # 获取用户ID（如果已登录）
        user_id = session.get('user_id')
        if not user_id and username:
            user = db.query(User).filter_by(username=username).first()
            if user:
                user_id = user.id
        
        # 发送邮件
        print(f"[DEBUG] 即将发送邮件: email={email}, code={code}")
        success, message = EmailService.send_verification_code(email, code, purpose, username)
        print(f"[DEBUG] 邮件发送结果: success={success}, message={message}")
        
        # 保存验证码到数据库 - 单独事务确保验证码一定被保存
        print(f"[DEBUG] 准备保存验证码: email={email}, code={code}")
        try:
            verification = EmailVerificationCode(
                user_id=user_id,  # 允许为None（未登录用户注册场景）
                email=email,
                code=code,
                purpose=purpose,
                expires_at=datetime.now() + timedelta(minutes=5),
                ip_address=request.remote_addr
            )
            db.add(verification)
            db.commit()  # 立即提交，确保验证码被保存
            print(f"[DEBUG] 验证码保存成功! ID={verification.id}")
            logger.info(f"验证码已保存到数据库: {email}, code={code}, id={verification.id}")
        except Exception as e:
            db.rollback()
            print(f"[DEBUG] 保存验证码失败: {e}")
            logger.error(f"保存验证码到数据库失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise
        
        # 记录发送日志 - 使用新的会话，不影响验证码保存
        try:
            config = EmailService.get_config()
            template = config.get('email_template', '')
            site_name = get_config('site_name', 'Emby Manager')
            content = EmailService.render_template(
                template,
                username=username,
                code=code,
                expire_minutes=5,
                site_name=site_name
            )
            
            send_log = EmailSendLog(
                user_id=user_id,
                email=email,
                send_type=purpose,
                content=content,
                code=code,
                is_success=success,
                error_message=message if not success else None
            )
            db.add(send_log)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"记录邮件发送日志失败: {e}")
            # 记录日志失败不影响主流程
        
        if success:
            logger.info(f"验证码已发送: {email}, 用途: {purpose}")
            return jsonify({
                'success': True,
                'message': '验证码已发送，请查收邮件',
                'data': {
                    'email': email,
                    'expires_in': 300  # 5分钟有效期
                }
            })
        else:
            logger.error(f"发送验证码失败: {email}, 错误: {message}")
            return jsonify({
                'success': False,
                'message': f'发送失败: {message}'
            }), 500
    except Exception as e:
        db.rollback()
        logger.error(f"发送验证码失败: {e}")
        return jsonify({'success': False, 'message': f'发送验证码失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/verify-email-code', methods=['POST'])
def verify_email_code():
    """验证邮箱验证码"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    code = data.get('code', '').strip()
    purpose = data.get('purpose', '').strip()
    
    if not email or not code or not purpose:
        return jsonify({'success': False, 'message': '请提供完整的验证信息'}), 400
    
    db = get_db()
    try:
        # 查找有效的验证码
        verification = db.query(EmailVerificationCode).filter(
            EmailVerificationCode.email == email,
            EmailVerificationCode.code == code,
            EmailVerificationCode.purpose == purpose,
            EmailVerificationCode.is_used == False,
            EmailVerificationCode.expires_at > datetime.now()
        ).order_by(EmailVerificationCode.created_at.desc()).first()
        
        if not verification:
            return jsonify({'success': False, 'message': '验证码无效或已过期'}), 400
        
        # 标记验证码为已使用
        verification.is_used = True
        verification.used_at = datetime.now()
        db.commit()
        
        logger.info(f"验证码验证成功: {email}, 用途: {purpose}")
        
        return jsonify({
            'success': True,
            'message': '验证码验证成功',
            'data': {
                'email': email,
                'purpose': purpose
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"验证验证码失败: {e}")
        return jsonify({'success': False, 'message': f'验证验证码失败: {str(e)}'}), 500
    finally:
        db.close()


# ============== 用户邮箱绑定 API ==============

@app.route('/api/user/bind-email', methods=['POST'])
@login_required
def bind_email():
    """绑定/更换邮箱"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    code = data.get('code', '').strip()
    
    if not email or not code:
        return jsonify({'success': False, 'message': '请提供邮箱和验证码'}), 400
    
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        # 验证验证码 - 先查找记录，再检查过期时间
        verification = db.query(EmailVerificationCode).filter(
            EmailVerificationCode.email == email,
            EmailVerificationCode.code == code,
            EmailVerificationCode.purpose == 'bind'
        ).order_by(EmailVerificationCode.created_at.desc()).first()
        
        if not verification:
            return jsonify({'success': False, 'message': '验证码不存在，请重新发送'}), 400
        
        # 检查是否已使用
        if verification.is_used:
            return jsonify({'success': False, 'message': '验证码已被使用，请重新发送'}), 400
        
        # 检查是否过期
        now = datetime.now()
        if verification.expires_at <= now:
            remaining_seconds = (verification.expires_at - now).total_seconds()
            return jsonify({
                'success': False, 
                'message': f'验证码已过期，请重新发送',
                'data': {
                    'expires_at': verification.expires_at.isoformat() if verification.expires_at else None,
                    'current_time': now.isoformat()
                }
            }), 400
        
        # 检查邮箱是否已被其他用户绑定
        existing_user = db.query(User).filter(
            User.email == email,
            User.id != user.id
        ).first()
        if existing_user:
            return jsonify({'success': False, 'message': '该邮箱已被其他用户绑定'}), 400
        
        # 更新用户邮箱
        user.email = email
        user.email_verified = True
        
        # 标记验证码为已使用
        verification.is_used = True
        verification.used_at = datetime.now()
        
        db.commit()
        logger.info(f"用户绑定邮箱成功: {user.username} -> {email}")
        
        return jsonify({
            'success': True,
            'message': '邮箱绑定成功',
            'data': {
                'email': email,
                'email_verified': True
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"绑定邮箱失败: {e}")
        return jsonify({'success': False, 'message': f'绑定邮箱失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/user/email-status', methods=['GET'])
@login_required
def get_email_status():
    """获取当前登录用户的邮箱绑定状态"""
    db = get_db()
    try:
        user = db.query(User).get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        return jsonify({
            'success': True,
            'data': {
                'email': user.email,
                'email_verified': user.email_verified,
                'is_bound': bool(user.email and user.email_verified)
            }
        })
    except Exception as e:
        logger.error(f"获取邮箱状态失败: {e}")
        return jsonify({'success': False, 'message': f'获取邮箱状态失败: {str(e)}'}), 500
    finally:
        db.close()


# ============== 忘记密码 API ==============

@app.route('/api/forgot-password/step1', methods=['POST'])
def forgot_password_step1():
    """验证邮箱是否存在"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'message': '请提供邮箱地址'}), 400
    
    db = get_db()
    try:
        user = db.query(User).filter_by(email=email, email_verified=True).first()
        if not user:
            return jsonify({'success': False, 'message': '该邮箱未绑定任何账号或未验证'}), 404
        
        return jsonify({
            'success': True,
            'message': '邮箱验证通过',
            'data': {
                'email': email,
                'username': user.username
            }
        })
    except Exception as e:
        logger.error(f"忘记密码步骤1失败: {e}")
        return jsonify({'success': False, 'message': f'验证失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/forgot-password/step2', methods=['POST'])
def forgot_password_step2():
    """验证验证码"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    code = data.get('code', '').strip()
    
    if not email or not code:
        return jsonify({'success': False, 'message': '请提供邮箱和验证码'}), 400
    
    db = get_db()
    try:
        # 验证验证码
        verification = db.query(EmailVerificationCode).filter(
            EmailVerificationCode.email == email,
            EmailVerificationCode.code == code,
            EmailVerificationCode.purpose == 'forgot_password',
            EmailVerificationCode.is_used == False,
            EmailVerificationCode.expires_at > datetime.now()
        ).order_by(EmailVerificationCode.created_at.desc()).first()
        
        if not verification:
            return jsonify({'success': False, 'message': '验证码无效或已过期'}), 400
        
        # 标记验证码为已使用（一次性使用）
        verification.is_used = True
        verification.used_at = datetime.now()
        db.commit()
        
        # 生成临时token用于步骤3
        reset_token = secrets.token_urlsafe(32)
        
        # 将token保存到session或临时存储（这里使用简单的内存存储）
        if not hasattr(app, '_password_reset_tokens'):
            app._password_reset_tokens = {}
        app._password_reset_tokens[reset_token] = {
            'email': email,
            'expires_at': datetime.now() + timedelta(minutes=10)
        }
        
        logger.info(f"忘记密码验证码验证成功: {email}")
        
        return jsonify({
            'success': True,
            'message': '验证码验证成功',
            'data': {
                'reset_token': reset_token
            }
        })
    except Exception as e:
        db.rollback()
        logger.error(f"忘记密码步骤2失败: {e}")
        return jsonify({'success': False, 'message': f'验证失败: {str(e)}'}), 500
    finally:
        db.close()


@app.route('/api/forgot-password/step3', methods=['POST'])
def forgot_password_step3():
    """重置密码（同步更新Emby密码）"""
    data = request.get_json()
    reset_token = data.get('reset_token', '').strip()
    new_password = data.get('new_password', '')

    if not reset_token or not new_password:
        return jsonify({'success': False, 'message': '请提供重置令牌和新密码'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': '密码至少6位'}), 400

    # 验证token
    if not hasattr(app, '_password_reset_tokens'):
        return jsonify({'success': False, 'message': '无效的重置令牌'}), 400

    token_data = app._password_reset_tokens.get(reset_token)
    if not token_data or token_data['expires_at'] < datetime.now():
        return jsonify({'success': False, 'message': '重置令牌已过期或无效'}), 400

    email = token_data['email']
    username = None
    emby_user_id = None

    # 第一步：更新本地密码
    db = get_db()
    try:
        user = db.query(User).filter_by(email=email).first()
        if not user:
            # 清除token防止重用
            if reset_token in app._password_reset_tokens:
                del app._password_reset_tokens[reset_token]
            logger.warning(f"密码重置失败 - 用户不存在: {email}")
            db.close()
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        username = user.username
        emby_user_id = user.emby_user_id

        # 生成新密码哈希并更新
        new_hash = generate_password_hash(new_password)
        logger.info(f"准备重置密码 - 用户名: {username}, 新哈希前50位: {new_hash[:50]}...")

        user.password_hash = new_hash
        db.commit()
        logger.info(f"本地密码重置成功并已提交到数据库: {username}")
    except Exception as e:
        db.rollback()
        # 清除token防止重用
        if reset_token in app._password_reset_tokens:
            del app._password_reset_tokens[reset_token]
        logger.error(f"重置本地密码失败: {e}")
        db.close()
        return jsonify({'success': False, 'message': f'重置密码失败: {str(e)}'}), 500
    finally:
        db.close()

    # 第二步：验证密码是否正确写入
    db = get_db()
    try:
        user_check = db.query(User).filter_by(email=email).first()
        if not user_check:
            # 清除token防止重用
            if reset_token in app._password_reset_tokens:
                del app._password_reset_tokens[reset_token]
            logger.error(f"验证失败 - 用户不存在: {email}")
            return jsonify({'success': False, 'message': '验证失败'}), 500

        logger.info(f"数据库验证 - 提交后的密码哈希前50位: {user_check.password_hash[:50]}...")
        verify_result = check_password_hash(user_check.password_hash, new_password)
        logger.info(f"密码验证测试 - 使用新密码验证: {verify_result}")

        if not verify_result:
            # 清除token防止重用
            if reset_token in app._password_reset_tokens:
                del app._password_reset_tokens[reset_token]
            logger.error(f"密码验证失败 - 新密码无法通过验证: {username}")
            return jsonify({'success': False, 'message': '密码重置后验证失败'}), 500
    except Exception as e:
        # 清除token防止重用
        if reset_token in app._password_reset_tokens:
            del app._password_reset_tokens[reset_token]
        logger.error(f"验证密码失败: {e}")
        return jsonify({'success': False, 'message': '验证失败'}), 500
    finally:
        db.close()

    # 第三步：同步到Emby（不影响本地密码修改结果）
    emby_sync_success = True
    if emby_user_id and EmbyAPI.is_configured():
        try:
            emby_sync_success = EmbyAPI.update_password(emby_user_id, new_password)
            if emby_sync_success:
                logger.info(f"Emby密码同步成功: {username}")
            else:
                logger.warning(f"Emby密码同步失败: {username}")
        except Exception as e:
            logger.error(f"Emby密码同步异常: {e}")
            emby_sync_success = False

    # 清除token（必须在所有可能的成功路径中执行）
    if reset_token in app._password_reset_tokens:
        del app._password_reset_tokens[reset_token]

    logger.info(f"密码重置完成: {username}")

    message = '密码重置成功，请使用新密码登录'
    if not emby_sync_success:
        message = '密码重置成功，但Emby密码同步失败'

    return jsonify({
        'success': True,
        'message': message
    })


@app.errorhandler(404)
def not_found(error):
    if request.is_json:
        return jsonify({'success': False, 'message': '接口不存在'}), 404
    try:
        return render_template('errors/404.html'), 404
    except:
        return '<h1>404 - 页面未找到</h1><p>请检查URL是否正确</p>', 404

@app.errorhandler(500)
def internal_error(error):
    if request.is_json:
        return jsonify({'success': False, 'message': '服务器内部错误'}), 500
    try:
        return render_template('errors/500.html'), 500
    except:
        return '<h1>500 - 服务器内部错误</h1><p>请稍后重试</p>', 500


# ============== 客户端下载管理API ==============

# 管理员获取客户端列表
@app.route('/api/admin/clients', methods=['GET'])
@admin_required
def api_admin_get_clients():
    """获取所有客户端列表"""
    db = get_db()
    try:
        clients = db.query(ClientDownload).order_by(ClientDownload.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [client.to_dict() for client in clients]
        })
    finally:
        db.close()


# 管理员添加客户端
@app.route('/api/admin/clients', methods=['POST'])
@admin_required
def api_admin_add_client():
    """添加新客户端"""
    try:
        name = request.form.get('name')
        client_type = request.form.get('client_type')
        version = request.form.get('version')
        description = request.form.get('description')
        app_store_url = request.form.get('app_store_url')
        is_active = request.form.get('is_active') == 'on'

        if not name or not client_type:
            return jsonify({'success': False, 'message': '请填写必填项'}), 400

        # 验证客户端类型
        try:
            client_type_enum = ClientType(client_type)
        except ValueError:
            return jsonify({'success': False, 'message': '无效的客户端类型'}), 400

        db = get_db()
        try:
            # 创建客户端记录
            client = ClientDownload(
                name=name,
                client_type=client_type_enum,
                version=version,
                description=description,
                is_active=is_active
            )

            # 处理iOS类型的App Store链接
            if client_type == 'ios':
                if not app_store_url:
                    return jsonify({'success': False, 'message': '请输入App Store链接'}), 400
                client.app_store_url = app_store_url
            else:
                # 处理非iOS类型：可以是文件上传或下载链接
                download_url = request.form.get('download_url')
                
                if download_url:
                    # 使用外部下载链接
                    client.download_url = download_url
                    client.file_size = 0
                elif 'file' in request.files:
                    # 处理文件上传
                    file = request.files['file']
                    if file.filename == '':
                        return jsonify({'success': False, 'message': '请选择文件'}), 400

                    # 保存原始文件名
                    original_filename = file.filename
                    
                    # 检查文件扩展名（安全限制）
                    allowed_extensions = {
                        'apk', 'xapk',  # Android
                        'ipa',  # iOS (虽然通常从App Store下载，但允许上传ipa用于企业分发)
                        'exe', 'msi', 'msix',  # Windows
                        'dmg', 'pkg',  # macOS
                        'deb', 'rpm', 'appimage', 'snap', 'flatpak',  # Linux
                        'zip', 'tar', 'gz', 'bz2', 'xz', '7z',  # 压缩包
                    }
                    file_ext = original_filename.rsplit('.', 1)[-1].lower() if '.' in original_filename else ''
                    if file_ext not in allowed_extensions:
                        return jsonify({
                            'success': False, 
                            'message': f'不支持的文件类型: .{file_ext}。只允许: {", ".join(allowed_extensions)}'
                        }), 400
                    
                    # 检查文件内容类型（防止伪装的可执行文件）
                    # 读取文件头部进行魔数检查
                    file_head = file.read(8)
                    file.seek(0)  # 重置文件指针
                    
                    # 检查常见的可执行文件魔数
                    executable_signatures = [
                        b'\x4d\x5a',  # Windows EXE/DLL (MZ)
                        b'\x7f\x45\x4c\x46',  # ELF (Linux可执行文件)
                        b'\xca\xfe\xba\xbe',  # Java class文件
                        b'\x50\x4b\x03\x04',  # ZIP/JAR/APK (需要进一步检查)
                    ]
                    
                    is_potentially_executable = any(file_head.startswith(sig) for sig in executable_signatures)
                    
                    # 对于ZIP文件（APK、IPA等），检查扩展名是否合法
                    if file_head.startswith(b'\x50\x4b\x03\x04') and file_ext not in ['apk', 'ipa', 'zip', 'xapk', 'msix']:
                        return jsonify({
                            'success': False,
                            'message': 'ZIP格式的文件只允许: apk, ipa, zip, xapk, msix'
                        }), 400
                    
                    # 保存文件（使用时间戳前缀避免重名）
                    safe_filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    stored_filename = f"{timestamp}_{safe_filename}"
                    file_path = os.path.join(CLIENT_DOWNLOADS_DIR, stored_filename)
                    file.save(file_path)

                    # 获取文件大小
                    file_size = os.path.getsize(file_path)

                    client.file_path = stored_filename
                    client.original_filename = original_filename  # 保存原始文件名
                    client.file_size = file_size
                else:
                    return jsonify({'success': False, 'message': '请上传安装包文件或提供下载链接'}), 400

            db.add(client)
            db.commit()

            logger.info(f"管理员添加客户端: {name} ({client_type})")
            return jsonify({
                'success': True,
                'message': '添加成功',
                'data': client.to_dict()
            })
        finally:
            db.close()

    except Exception as e:
        logger.error(f"添加客户端失败: {e}")
        return jsonify({'success': False, 'message': f'添加失败: {str(e)}'}), 500


# 管理员编辑客户端
@app.route('/api/admin/clients/<int:client_id>', methods=['PUT'])
@admin_required
def api_admin_update_client(client_id):
    """更新客户端信息"""
    try:
        db = get_db()
        try:
            client = db.query(ClientDownload).get(client_id)
            if not client:
                return jsonify({'success': False, 'message': '客户端不存在'}), 404

            name = request.form.get('name')
            client_type = request.form.get('client_type')
            version = request.form.get('version')
            description = request.form.get('description')
            app_store_url = request.form.get('app_store_url')
            is_active = request.form.get('is_active') == 'on'

            if not name or not client_type:
                return jsonify({'success': False, 'message': '请填写必填项'}), 400

            logger.info(f"更新客户端 ID={client_id}, name={name}, type={client_type}")
            logger.info(f"更新前 - download_url={client.download_url}, file_path={client.file_path}")

            # 更新基本信息
            client.name = name
            client.version = version
            client.description = description
            client.is_active = is_active
            client.updated_at = datetime.utcnow()

            # 处理iOS类型的App Store链接
            if client_type == 'ios':
                if not app_store_url:
                    return jsonify({'success': False, 'message': '请输入App Store链接'}), 400
                client.app_store_url = app_store_url
                # 删除旧文件（如果存在）
                if client.file_path:
                    old_file_path = os.path.join(CLIENT_DOWNLOADS_DIR, client.file_path)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                    client.file_path = None
                    client.file_size = 0
                client.download_url = None
            else:
                # 检查是上传文件还是提供下载链接
                provide_type = request.form.get('provide_type', 'upload')
                download_url = request.form.get('download_url', '').strip()
                
                logger.info(f"提供方式: {provide_type}, 下载链接: {download_url}")
                
                if provide_type == 'link':
                    # 提供下载链接模式
                    if not download_url:
                        return jsonify({'success': False, 'message': '请输入下载链接'}), 400
                    
                    client.download_url = download_url
                    # 删除旧文件（如果存在）
                    if client.file_path:
                        old_file_path = os.path.join(CLIENT_DOWNLOADS_DIR, client.file_path)
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)
                        client.file_path = None
                        client.file_size = 0
                    logger.info(f"已设置下载链接: {download_url}")
                else:
                    # 上传文件模式
                    
                    # 处理新文件上传
                    if 'file' in request.files:
                        file = request.files['file']
                        if file.filename != '':
                            # 删除旧文件
                            if client.file_path:
                                old_file_path = os.path.join(CLIENT_DOWNLOADS_DIR, client.file_path)
                                if os.path.exists(old_file_path):
                                    os.remove(old_file_path)

                            # 保存新文件
                            filename = secure_filename(file.filename)
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            filename = f"{timestamp}_{filename}"
                            file_path = os.path.join(CLIENT_DOWNLOADS_DIR, filename)
                            file.save(file_path)

                            client.file_path = filename
                            client.file_size = os.path.getsize(file_path)
                            # 有新文件上传时才清空下载链接
                            client.download_url = None
                            logger.info(f"已上传新文件: {filename}")

            db.commit()
            
            logger.info(f"更新后 - download_url={client.download_url}, file_path={client.file_path}")
            logger.info(f"管理员更新客户端: {name} (ID: {client_id})")
            
            return jsonify({
                'success': True,
                'message': '更新成功',
                'data': client.to_dict()
            })
        finally:
            db.close()

    except Exception as e:
        logger.error(f"更新客户端失败: {e}")
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'}), 500


# 管理员删除客户端
@app.route('/api/admin/clients/<int:client_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_client(client_id):
    """删除客户端"""
    try:
        db = get_db()
        try:
            client = db.query(ClientDownload).get(client_id)
            if not client:
                return jsonify({'success': False, 'message': '客户端不存在'}), 404

            # 删除关联的文件
            if client.file_path:
                file_path = os.path.join(CLIENT_DOWNLOADS_DIR, client.file_path)
                if os.path.exists(file_path):
                    os.remove(file_path)

            db.delete(client)
            db.commit()

            logger.info(f"管理员删除客户端: {client.name} (ID: {client_id})")
            return jsonify({'success': True, 'message': '删除成功'})
        finally:
            db.close()

    except Exception as e:
        logger.error(f"删除客户端失败: {e}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500


# 用户获取客户端列表
@app.route('/api/user/clients', methods=['GET'])
@login_required
def api_user_get_clients():
    """获取启用的客户端列表"""
    db = get_db()
    try:
        clients = db.query(ClientDownload).filter_by(is_active=True).order_by(
            ClientDownload.client_type,
            ClientDownload.created_at.desc()
        ).all()
        return jsonify({
            'success': True,
            'data': [client.to_dict() for client in clients]
        })
    finally:
        db.close()


# 用户下载客户端
@app.route('/api/user/clients/<int:client_id>/download', methods=['GET'])
@login_required
def api_user_download_client(client_id):
    """下载客户端文件"""
    try:
        db = get_db()
        try:
            client = db.query(ClientDownload).get(client_id)
            if not client:
                return jsonify({'success': False, 'message': '客户端不存在'}), 404

            if not client.is_active:
                return jsonify({'success': False, 'message': '该客户端已停用'}), 403

            # iOS类型直接返回App Store链接
            if client.client_type == ClientType.IOS:
                if client.app_store_url:
                    return jsonify({
                        'success': True,
                        'data': {'app_store_url': client.app_store_url}
                    })
                else:
                    return jsonify({'success': False, 'message': 'App Store链接未配置'}), 404

            # 检查文件是否存在
            if not client.file_path:
                return jsonify({'success': False, 'message': '文件不存在'}), 404

            file_path = os.path.join(CLIENT_DOWNLOADS_DIR, client.file_path)
            if not os.path.exists(file_path):
                return jsonify({'success': False, 'message': '文件不存在'}), 404

            # 增加下载次数
            client.download_count += 1
            db.commit()

            # 返回文件
            # 根据文件扩展名确定 MIME 类型
            file_ext = os.path.splitext(client.file_path)[1].lower()
            mime_types = {
                '.apk': 'application/vnd.android.package-archive',
                '.exe': 'application/x-msdownload',
                '.msi': 'application/x-msi',
                '.dmg': 'application/x-apple-diskimage',
                '.pkg': 'application/x-newton-compatible-pkg'
            }
            mimetype = mime_types.get(file_ext, 'application/octet-stream')

            # 使用保存的原始文件名作为下载文件名
            # 如果没有原始文件名（旧数据），则从存储的文件名中提取
            if client.original_filename:
                download_filename = client.original_filename
            else:
                # 兼容旧数据：从存储的文件名中移除时间戳前缀
                stored_filename = client.file_path
                parts = stored_filename.split('_', 2)
                if len(parts) >= 3:
                    download_filename = parts[2]
                else:
                    download_filename = stored_filename

            response = send_file(
                file_path,
                as_attachment=True,
                download_name=download_filename,
                mimetype=mimetype
            )
            
            # 确保 Content-Disposition 头正确设置（处理中文文件名）
            from urllib.parse import quote
            encoded_filename = quote(download_filename)
            response.headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_filename}"
            
            return response
        finally:
            db.close()

    except Exception as e:
        logger.error(f"下载客户端失败: {e}")
        return jsonify({'success': False, 'message': f'下载失败: {str(e)}'}), 500


# ============== 使用文档管理API ==============

# 管理员获取使用文档列表
@app.route('/api/admin/user-guide-docs', methods=['GET'])
@admin_required
def api_admin_get_user_guide_docs():
    """获取所有使用文档列表（管理员），支持搜索"""
    db = get_db()
    try:
        # 获取搜索参数
        keyword = request.args.get('keyword', '').strip()
        platform = request.args.get('platform', '').strip()
        
        # 构建查询
        query = db.query(UserGuideDoc)
        
        # 平台过滤
        if platform:
            try:
                platform_enum = DocPlatform(platform)
                query = query.filter_by(platform=platform_enum)
            except ValueError:
                pass
        
        # 关键词搜索（标题和内容）
        if keyword:
            search_pattern = f"%{keyword}%"
            query = query.filter(
                or_(
                    UserGuideDoc.title.ilike(search_pattern),
                    UserGuideDoc.content.ilike(search_pattern),
                    UserGuideDoc.link_url.ilike(search_pattern)
                )
            )
        
        docs = query.order_by(UserGuideDoc.sort_order.asc(), UserGuideDoc.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [doc.to_dict() for doc in docs]
        })
    except Exception as e:
        logger.error(f"获取使用文档列表失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()


# 管理员添加使用文档
@app.route('/api/admin/user-guide-docs', methods=['POST'])
@admin_required
def api_admin_add_user_guide_doc():
    """添加使用文档"""
    data = request.get_json() or {}
    csrf_token = data.get('csrf_token', '')

    # 验证CSRF token
    if not verify_csrf_token(csrf_token):
        logger.warning(f"CSRF验证失败 - 添加使用文档 - 管理员: {session.get('username', 'unknown')}")
        return jsonify({'success': False, 'message': '安全验证失败，请刷新页面后重试'}), 403

    platform_str = data.get('platform', '').strip()
    title = data.get('title', '').strip()
    content_type = data.get('content_type', 'html')
    content = data.get('content', '').strip()
    link_url = data.get('link_url', '').strip()
    sort_order = data.get('sort_order', 0)

    if not platform_str or not title:
        return jsonify({'success': False, 'message': '平台类型和标题不能为空'}), 400

    # 验证平台类型
    try:
        platform = DocPlatform(platform_str)
    except ValueError:
        return jsonify({'success': False, 'message': '无效的平台类型'}), 400

    # 验证内容
    if content_type == 'html' and not content:
        return jsonify({'success': False, 'message': 'HTML内容不能为空'}), 400
    if content_type == 'link' and not link_url:
        return jsonify({'success': False, 'message': '外部链接不能为空'}), 400

    db = get_db()
    try:
        doc = UserGuideDoc(
            platform=platform,
            title=title,
            content_type=content_type,
            content=content if content_type == 'html' else None,
            link_url=link_url if content_type == 'link' else None,
            sort_order=sort_order,
            is_active=True
        )
        db.add(doc)
        db.commit()

        logger.info(f"管理员添加使用文档: {title} ({platform.value})")
        return jsonify({'success': True, 'message': '添加成功', 'data': doc.to_dict()})
    except Exception as e:
        db.rollback()
        logger.error(f"添加使用文档失败: {e}")
        return jsonify({'success': False, 'message': '添加失败'}), 500
    finally:
        db.close()


# 管理员更新使用文档
@app.route('/api/admin/user-guide-docs/<int:doc_id>', methods=['PUT'])
@admin_required
def api_admin_update_user_guide_doc(doc_id):
    """更新使用文档"""
    data = request.get_json() or {}
    csrf_token = data.get('csrf_token', '')

    # 验证CSRF token
    if not verify_csrf_token(csrf_token):
        logger.warning(f"CSRF验证失败 - 更新使用文档 - 管理员: {session.get('username', 'unknown')}")
        return jsonify({'success': False, 'message': '安全验证失败，请刷新页面后重试'}), 403

    db = get_db()
    try:
        doc = db.query(UserGuideDoc).filter_by(id=doc_id).first()
        if not doc:
            return jsonify({'success': False, 'message': '文档不存在'}), 404

        # 支持部分更新
        if 'platform' in data:
            try:
                doc.platform = DocPlatform(data['platform'])
            except ValueError:
                return jsonify({'success': False, 'message': '无效的平台类型'}), 400

        if 'title' in data:
            title = data['title'].strip()
            if not title:
                return jsonify({'success': False, 'message': '标题不能为空'}), 400
            doc.title = title

        if 'content_type' in data:
            doc.content_type = data['content_type']

        if 'content' in data and doc.content_type == 'html':
            doc.content = data['content'].strip()

        if 'link_url' in data and doc.content_type == 'link':
            doc.link_url = data['link_url'].strip()

        if 'is_active' in data:
            doc.is_active = bool(data['is_active'])

        if 'sort_order' in data:
            doc.sort_order = int(data['sort_order'])

        doc.updated_at = datetime.now()
        db.commit()

        logger.info(f"管理员更新使用文档: {doc.title} (ID: {doc_id})")
        return jsonify({'success': True, 'message': '更新成功', 'data': doc.to_dict()})
    except Exception as e:
        db.rollback()
        logger.error(f"更新使用文档失败: {e}")
        return jsonify({'success': False, 'message': '更新失败'}), 500
    finally:
        db.close()


# 管理员删除使用文档
@app.route('/api/admin/user-guide-docs/<int:doc_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user_guide_doc(doc_id):
    """删除使用文档"""
    data = request.get_json() or {}
    csrf_token = data.get('csrf_token', '')

    # 验证CSRF token
    if not verify_csrf_token(csrf_token):
        logger.warning(f"CSRF验证失败 - 删除使用文档 - 管理员: {session.get('username', 'unknown')}")
        return jsonify({'success': False, 'message': '安全验证失败，请刷新页面后重试'}), 403

    db = get_db()
    try:
        doc = db.query(UserGuideDoc).filter_by(id=doc_id).first()
        if not doc:
            return jsonify({'success': False, 'message': '文档不存在'}), 404

        db.delete(doc)
        db.commit()

        logger.info(f"管理员删除使用文档: {doc.title} (ID: {doc_id})")
        return jsonify({'success': True, 'message': '删除成功'})
    except Exception as e:
        db.rollback()
        logger.error(f"删除使用文档失败: {e}")
        return jsonify({'success': False, 'message': '删除失败'}), 500
    finally:
        db.close()


# 用户获取使用文档列表
@app.route('/api/user-guide-docs', methods=['GET'])
@login_required
def api_user_get_guide_docs():
    """获取启用的使用文档列表（用户），支持搜索"""
    db = get_db()
    try:
        # 获取搜索参数
        keyword = request.args.get('keyword', '').strip()
        platform = request.args.get('platform', '').strip()
        
        # 构建查询（只查询启用的文档）
        query = db.query(UserGuideDoc).filter_by(is_active=True)
        
        # 平台过滤
        if platform:
            try:
                platform_enum = DocPlatform(platform)
                query = query.filter_by(platform=platform_enum)
            except ValueError:
                pass
        
        # 关键词搜索（标题和内容）
        if keyword:
            search_pattern = f"%{keyword}%"
            query = query.filter(
                or_(
                    UserGuideDoc.title.ilike(search_pattern),
                    UserGuideDoc.content.ilike(search_pattern),
                    UserGuideDoc.link_url.ilike(search_pattern)
                )
            )
        
        docs = query.order_by(UserGuideDoc.sort_order.asc(), UserGuideDoc.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [doc.to_dict() for doc in docs]
        })
    except Exception as e:
        logger.error(f"获取使用文档列表失败: {e}")
        return jsonify({'success': False, 'message': '获取失败'}), 500
    finally:
        db.close()


# 用户查看使用文档详情（HTML类型）
@app.route('/user/user-guide/<int:doc_id>')
@login_required_not_expired
def user_view_guide_doc(doc_id):
    """用户查看使用文档详情（在新标签页中打开）"""
    db = get_db()
    try:
        doc = db.query(UserGuideDoc).filter_by(id=doc_id, is_active=True).first()
        if not doc:
            return "文档不存在或已禁用", 404

        if doc.content_type == 'link':
            # 外部链接直接跳转
            return redirect(doc.link_url)
        else:
            # HTML内容进行安全净化后返回，防止XSS攻击
            html_content = doc.content or '<p style="text-align: center; padding: 50px;">暂无内容</p>'
            sanitized_content = sanitize_html(html_content)
            return sanitized_content
    except Exception as e:
        logger.error(f"查看使用文档失败: {e}")
        return "加载文档失败", 500
    finally:
        db.close()


# ============== 工单系统API ==============

# 用户获取工单列表
@app.route('/api/user/tickets', methods=['GET'])
@login_required
def api_user_get_tickets():
    """获取当前用户的工单列表"""
    db = get_db()
    try:
        tickets = db.query(Ticket).filter_by(user_id=session['user_id']).order_by(Ticket.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [ticket.to_dict() for ticket in tickets]
        })
    finally:
        db.close()


# 用户创建工单
@app.route('/api/user/tickets', methods=['POST'])
@login_required
def api_user_create_ticket():
    """创建新工单"""
    try:
        data = request.get_json()
        
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        ticket_type = data.get('type', 'other')
        priority = data.get('priority', 'medium')
        
        if not title:
            return jsonify({'success': False, 'message': '请输入工单标题'}), 400
        if not content:
            return jsonify({'success': False, 'message': '请输入工单内容'}), 400
        
        # 验证类型和优先级
        try:
            ticket_type_enum = TicketType(ticket_type)
        except ValueError:
            ticket_type_enum = TicketType.OTHER
            
        try:
            priority_enum = TicketPriority(priority)
        except ValueError:
            priority_enum = TicketPriority.MEDIUM
        
        db = get_db()
        try:
            ticket = Ticket(
                user_id=session['user_id'],
                title=title,
                content=content,
                type=ticket_type_enum,
                priority=priority_enum,
                status=TicketStatus.PENDING
            )
            db.add(ticket)
            db.commit()
            
            logger.info(f"用户 {session['user_id']} 创建工单: {title}")
            return jsonify({
                'success': True,
                'message': '工单创建成功',
                'data': ticket.to_dict()
            })
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"创建工单失败: {e}")
        return jsonify({'success': False, 'message': f'创建失败: {str(e)}'}), 500


# 用户获取工单详情
@app.route('/api/user/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def api_user_get_ticket(ticket_id):
    """获取工单详情（包含消息）"""
    db = get_db()
    try:
        ticket = db.query(Ticket).filter_by(id=ticket_id, user_id=session['user_id']).first()
        if not ticket:
            return jsonify({'success': False, 'message': '工单不存在'}), 404
        
        # 自动标记管理员发送的未读消息为已读
        unread_admin_messages = db.query(TicketMessage).filter_by(
            ticket_id=ticket_id,
            sender_type='admin',
            is_read=False
        ).all()
        
        for msg in unread_admin_messages:
            msg.is_read = True
        
        if unread_admin_messages:
            db.commit()
        
        return jsonify({
            'success': True,
            'data': ticket.to_dict(include_messages=True)
        })
    finally:
        db.close()


# 用户发送消息
@app.route('/api/user/tickets/<int:ticket_id>/messages', methods=['POST'])
@login_required
def api_user_send_message(ticket_id):
    """用户发送工单消息"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'success': False, 'message': '请输入消息内容'}), 400
        
        db = get_db()
        try:
            ticket = db.query(Ticket).filter_by(id=ticket_id, user_id=session['user_id']).first()
            if not ticket:
                return jsonify({'success': False, 'message': '工单不存在'}), 404
            
            if ticket.status == TicketStatus.COMPLETED:
                return jsonify({'success': False, 'message': '工单已关闭，无法回复'}), 400
            
            message = TicketMessage(
                ticket_id=ticket_id,
                sender_id=session['user_id'],
                sender_type='user',
                content=content,
                is_read=False
            )
            db.add(message)
            
            # 更新工单状态为处理中
            if ticket.status == TicketStatus.PENDING:
                ticket.status = TicketStatus.PROCESSING
            
            ticket.updated_at = datetime.utcnow()
            db.commit()
            
            return jsonify({
                'success': True,
                'message': '发送成功',
                'data': message.to_dict()
            })
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"发送消息失败: {e}")
        return jsonify({'success': False, 'message': f'发送失败: {str(e)}'}), 500


# 用户关闭工单
@app.route('/api/user/tickets/<int:ticket_id>/close', methods=['POST'])
@login_required
def api_user_close_ticket(ticket_id):
    """用户关闭工单"""
    db = get_db()
    try:
        ticket = db.query(Ticket).filter_by(id=ticket_id, user_id=session['user_id']).first()
        if not ticket:
            return jsonify({'success': False, 'message': '工单不存在'}), 404
        
        ticket.status = TicketStatus.COMPLETED
        ticket.closed_at = datetime.utcnow()
        ticket.updated_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"用户 {session['user_id']} 关闭工单 {ticket_id}")
        return jsonify({
            'success': True,
            'message': '工单已关闭'
        })
    finally:
        db.close()


# 用户标记消息已读
@app.route('/api/user/tickets/<int:ticket_id>/read', methods=['PUT'])
@login_required
def api_user_mark_ticket_read(ticket_id):
    """用户标记工单消息为已读"""
    db = get_db()
    try:
        ticket = db.query(Ticket).filter_by(id=ticket_id, user_id=session['user_id']).first()
        if not ticket:
            return jsonify({'success': False, 'message': '工单不存在'}), 404
        
        # 将所有管理员发送的未读消息标记为已读
        unread_messages = db.query(TicketMessage).filter_by(
            ticket_id=ticket_id, 
            sender_type='admin', 
            is_read=False
        ).all()
        
        for msg in unread_messages:
            msg.is_read = True
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': '已标记为已读',
            'count': len(unread_messages)
        })
    finally:
        db.close()


# 管理员获取工单列表
@app.route('/api/admin/tickets', methods=['GET'])
@admin_required
def api_admin_get_tickets():
    """获取所有工单列表（支持分页、筛选、搜索）"""
    db = get_db()
    try:
        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        status = request.args.get('status', '')
        search = request.args.get('search', '').strip()
        
        # 构建查询
        query = db.query(Ticket)
        
        # 状态筛选
        if status:
            try:
                status_enum = TicketStatus(status)
                query = query.filter(Ticket.status == status_enum)
            except ValueError:
                pass
        
        # 搜索（按用户名称或工单标题）
        if search:
            query = query.join(User).filter(
                or_(
                    User.username.contains(search),
                    Ticket.title.contains(search)
                )
            )
        
        # 获取总数
        total = query.count()
        
        # 分页
        tickets = query.order_by(Ticket.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'success': True,
            'data': {
                'tickets': [ticket.to_dict() for ticket in tickets],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': (total + per_page - 1) // per_page
                }
            }
        })
    finally:
        db.close()


# 管理员获取工单详情
@app.route('/api/admin/tickets/<int:ticket_id>', methods=['GET'])
@admin_required
def api_admin_get_ticket(ticket_id):
    """获取工单详情"""
    db = get_db()
    try:
        ticket = db.query(Ticket).get(ticket_id)
        if not ticket:
            return jsonify({'success': False, 'message': '工单不存在'}), 404
        
        # 自动标记用户发送的未读消息为已读
        unread_user_messages = db.query(TicketMessage).filter_by(
            ticket_id=ticket_id,
            sender_type='user',
            is_read=False
        ).all()
        
        for msg in unread_user_messages:
            msg.is_read = True
        
        if unread_user_messages:
            db.commit()
        
        return jsonify({
            'success': True,
            'data': ticket.to_dict(include_messages=True)
        })
    finally:
        db.close()


# 管理员更新工单
@app.route('/api/admin/tickets/<int:ticket_id>', methods=['PUT'])
@admin_required
def api_admin_update_ticket(ticket_id):
    """更新工单信息（状态、优先级）"""
    try:
        data = request.get_json()
        
        db = get_db()
        try:
            ticket = db.query(Ticket).get(ticket_id)
            if not ticket:
                return jsonify({'success': False, 'message': '工单不存在'}), 404
            
            # 更新状态
            if 'status' in data:
                try:
                    ticket.status = TicketStatus(data['status'])
                    if data['status'] == 'completed':
                        ticket.closed_at = datetime.utcnow()
                except ValueError:
                    pass
            
            # 更新优先级
            if 'priority' in data:
                try:
                    ticket.priority = TicketPriority(data['priority'])
                except ValueError:
                    pass
            
            ticket.updated_at = datetime.utcnow()
            db.commit()
            
            logger.info(f"管理员更新工单 {ticket_id}")
            return jsonify({
                'success': True,
                'message': '更新成功',
                'data': ticket.to_dict()
            })
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"更新工单失败: {e}")
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'}), 500


# 管理员回复消息
@app.route('/api/admin/tickets/<int:ticket_id>/messages', methods=['POST'])
@admin_required
def api_admin_send_message(ticket_id):
    """管理员回复工单"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'success': False, 'message': '请输入消息内容'}), 400
        
        db = get_db()
        try:
            ticket = db.query(Ticket).get(ticket_id)
            if not ticket:
                return jsonify({'success': False, 'message': '工单不存在'}), 404
            
            if ticket.status == TicketStatus.COMPLETED:
                return jsonify({'success': False, 'message': '工单已关闭，无法回复'}), 400
            
            message = TicketMessage(
                ticket_id=ticket_id,
                sender_id=session['user_id'],
                sender_type='admin',
                content=content,
                is_read=False
            )
            db.add(message)
            
            # 更新工单状态为处理中
            if ticket.status == TicketStatus.PENDING:
                ticket.status = TicketStatus.PROCESSING
            
            ticket.updated_at = datetime.utcnow()
            db.commit()
            
            logger.info(f"管理员回复工单 {ticket_id}")
            return jsonify({
                'success': True,
                'message': '回复成功',
                'data': message.to_dict()
            })
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"回复工单失败: {e}")
        return jsonify({'success': False, 'message': f'回复失败: {str(e)}'}), 500


# 管理员完成工单
@app.route('/api/admin/tickets/<int:ticket_id>/complete', methods=['POST'])
@admin_required
def api_admin_complete_ticket(ticket_id):
    """管理员完成工单"""
    db = get_db()
    try:
        ticket = db.query(Ticket).get(ticket_id)
        if not ticket:
            return jsonify({'success': False, 'message': '工单不存在'}), 404
        
        ticket.status = TicketStatus.COMPLETED
        ticket.closed_at = datetime.utcnow()
        ticket.updated_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"管理员完成工单 {ticket_id}")
        return jsonify({
            'success': True,
            'message': '工单已完成'
        })
    finally:
        db.close()


# 管理员删除工单
@app.route('/api/admin/tickets/<int:ticket_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_ticket(ticket_id):
    """删除单个工单"""
    db = get_db()
    try:
        ticket = db.query(Ticket).get(ticket_id)
        if not ticket:
            return jsonify({'success': False, 'message': '工单不存在'}), 404
        
        db.delete(ticket)
        db.commit()
        
        logger.info(f"管理员删除工单 {ticket_id}")
        return jsonify({
            'success': True,
            'message': '删除成功'
        })
    finally:
        db.close()


# 管理员批量删除工单
@app.route('/api/admin/tickets/batch-delete', methods=['POST'])
@admin_required
def api_admin_batch_delete_tickets():
    """批量删除工单"""
    try:
        data = request.get_json()
        ticket_ids = data.get('ids', [])
        
        if not ticket_ids:
            return jsonify({'success': False, 'message': '请选择要删除的工单'}), 400
        
        db = get_db()
        try:
            deleted_count = db.query(Ticket).filter(Ticket.id.in_(ticket_ids)).delete(synchronize_session=False)
            db.commit()
            
            logger.info(f"管理员批量删除工单: {ticket_ids}")
            return jsonify({
                'success': True,
                'message': f'成功删除 {deleted_count} 个工单'
            })
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"批量删除工单失败: {e}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500


# ============== 页面路由 ==============

# 用户工单页面
@app.route('/user/tickets')
@login_required
def user_tickets_page():
    """用户工单页面"""
    return render_template('user/tickets.html')


# 管理员工单管理页面
@app.route('/admin/tickets')
@admin_required
def admin_tickets_page():
    """管理员工单管理页面"""
    return render_template('admin/tickets.html')


# ============== 启动应用 ==============
if __name__ == '__main__':
    # 直接运行app.py时，立即初始化并启动定时任务
    init_db()
    start_scheduler()
    logger.info("Emby Manager 启动中...")
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.jinja_env.auto_reload = True
    app.run(host='0.0.0.0', port=5001, debug=True)
