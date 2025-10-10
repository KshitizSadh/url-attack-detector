from sqlalchemy import Column, Integer, String, Text, DateTime, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import datetime
import os

Base = declarative_base()

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    src_ip = Column(String(64))
    dst_ip = Column(String(64))
    http_method = Column(String(10))
    url = Column(Text)
    params = Column(Text)
    user_agent = Column(Text)
    attack_type = Column(String(100))
    confidence = Column(Integer, default=50)  # 0-100
    raw = Column(Text)

# ✅ Define safe database path
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "alerts.db")

# ✅ Ensure folder exists before DB creation
os.makedirs(DB_DIR, exist_ok=True)

# ✅ Create engine (SQLite inside data folder)
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, future=True, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

def init_db():
    Base.metadata.create_all(engine)
