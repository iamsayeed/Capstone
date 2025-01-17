from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

# Define TrafficLog table
class TrafficLog(Base):
    __tablename__ = 'traffic_log'
    id = Column(Integer, primary_key=True)
    src_ip = Column(String)
    dest_ip = Column(String)
    protocol = Column(String)
    packet_size = Column(Integer)
    timestamp = Column(DateTime)

# Define AttackLog table
class AttackLog(Base):
    __tablename__ = 'attack_log'
    id = Column(Integer, primary_key=True)
    src_ip = Column(String)
    dest_ip = Column(String)
    alert_message = Column(String)
    severity = Column(String)
    timestamp = Column(DateTime)

# Set up the database
engine = create_engine('sqlite:///nide_project.db')
Base.metadata.create_all(engine)

# Create a session factory
Session = sessionmaker(bind=engine)
session = Session()
