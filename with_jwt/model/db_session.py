from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker


db_url = 'mysql://root:123456@127.0.0.1:3306/grpc'
engine = create_engine(db_url, pool_size=20, max_overflow=0)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

session = Session()
