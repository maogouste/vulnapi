"""Flag model for challenge system."""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from datetime import datetime, timezone

from app.database import Base


class Flag(Base):
    """Flag model for tracking challenge completions."""

    __tablename__ = "flags"

    id = Column(Integer, primary_key=True, index=True)
    challenge_id = Column(String(10), nullable=False)  # V01, V02, etc.
    flag_value = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    def __repr__(self):
        return f"<Flag(challenge_id='{self.challenge_id}')>"


class FlagSubmission(Base):
    """Track user flag submissions."""

    __tablename__ = "flag_submissions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    challenge_id = Column(String(10), nullable=False)
    submitted_flag = Column(String(100), nullable=False)
    is_correct = Column(Integer, default=0)  # 0 = wrong, 1 = correct
    submitted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<FlagSubmission(user_id={self.user_id}, challenge='{self.challenge_id}', correct={self.is_correct})>"
