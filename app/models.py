from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_user: Mapped[str] = mapped_column(String(80), default="root")
    auth_type: Mapped[str] = mapped_column(String(24), default="password")
    credential_enc: Mapped[str] = mapped_column(Text, default="")
    host_key_fingerprint: Mapped[str] = mapped_column(String(255), default="")
    state: Mapped[str] = mapped_column(String(32), default="new")
    last_error: Mapped[str] = mapped_column(Text, default="")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    proxies: Mapped[list["Proxy"]] = relationship(back_populates="server", cascade="all, delete-orphan")


class Sponsor(Base):
    __tablename__ = "sponsors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    channel: Mapped[str] = mapped_column(String(120), default="")
    proxy_tag: Mapped[str] = mapped_column(String(64), unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    proxies: Mapped[list["Proxy"]] = relationship(back_populates="sponsor")


class Proxy(Base):
    __tablename__ = "proxies"
    __table_args__ = (
        UniqueConstraint("server_id", "public_port", name="uq_proxy_server_public_port"),
        UniqueConstraint("server_id", "stats_port", name="uq_proxy_server_stats_port"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    sponsor_id: Mapped[int | None] = mapped_column(ForeignKey("sponsors.id", ondelete="SET NULL"), nullable=True)
    public_host: Mapped[str] = mapped_column(String(255))
    public_port: Mapped[int] = mapped_column(Integer)
    stats_port: Mapped[int] = mapped_column(Integer)
    secret_enc: Mapped[str] = mapped_column(Text)
    padding_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    workers: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(32), default="provisioning")
    last_error: Mapped[str] = mapped_column(Text, default="")
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_connections: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    server: Mapped[Server] = relationship(back_populates="proxies")
    sponsor: Mapped[Sponsor | None] = relationship(back_populates="proxies")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_email: Mapped[str] = mapped_column(String(255), default="system")
    action: Mapped[str] = mapped_column(String(120))
    target_type: Mapped[str] = mapped_column(String(80), default="")
    target_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    ip_address: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
