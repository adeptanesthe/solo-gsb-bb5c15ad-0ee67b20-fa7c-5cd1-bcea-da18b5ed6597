from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """运行参数，全部可通过环境变量覆盖。"""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(
        default="postgresql+asyncpg://dropbox:dropbox@db:5432/dropbox",
        description="SQLAlchemy 异步数据库 DSN",
    )
    redis_url: str = Field(default="redis://redis:6379/0", description="Redis 连接地址")

    # 内容与有效期约束
    max_content_bytes: int = Field(default=1 * 1024 * 1024, description="单条投递内容/文件大小上限")
    ttl_min_seconds: int = Field(default=60, description="允许设置的最短有效期")
    ttl_max_seconds: int = Field(default=7 * 24 * 3600, description="允许设置的最长有效期")

    # Redis 终态标记（consumed/revoked/expired）保留时长
    redis_flag_ttl_seconds: int = Field(default=30 * 24 * 3600)
    # 过期清扫协程的轮询间隔
    sweep_interval_seconds: int = Field(default=30)

    service_name: str = "one-time-dropbox"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
