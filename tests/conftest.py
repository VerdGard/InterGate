"""pytest 共享 fixtures。"""
from __future__ import annotations

import os
import sys
import tempfile

# 将项目根目录加入 sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 使用临时目录避免污染真实数据
os.environ["INTERGATE_DATA_DIR"] = tempfile.mkdtemp(prefix="ig_test_")

import pytest  # noqa: E402

from db.database import Database  # noqa: E402


@pytest.fixture
def db():
    """提供一个干净的临时数据库。"""
    d = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], "test.db"))
    yield d


@pytest.fixture
def settings():
    from config.settings import UserSettings
    return UserSettings()
