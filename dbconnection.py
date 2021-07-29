from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class cert_data_sagar(Base):
    __tablename__ = 'cert_data_sagar'
    cert_name = Column(String(50), primary_key=True)
    common_name = Column(String(50))
    orangnisation = Column(String(20))
    ou = Column(String(25))
    country= Column(String(2))
    locality = Column(String(20))
    email = Column(String(50))
    state = Column(String(20))
    technical_owner = Column(String(20))
    expiration_date = Column(DateTime)
    renewal_status = Column(String(20))
    serverip = Column(String(36))
    partition =Column(String(20))
    verifier_email =Column(String(50))
    dateTime1 =Column(DateTime)
    dateTime2 =Column(DateTime)

engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db' )
Base.metadata.create_all(engine)
