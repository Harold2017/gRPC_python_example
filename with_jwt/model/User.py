from datetime import datetime, timedelta
from sqlalchemy import Column, String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound
import hashlib
import binascii
from .db_session import session, engine

import jwt


JWT_EXPIRATION = 24 * 1

with open('keys/server.key') as f:
    JWT_SECRET = f.read()


def generate_password_hash(password):
    return binascii.hexlify(hashlib.pbkdf2_hmac(hash_name='sha256', password=password.encode('utf-8'),
                                                salt='tasty salt'.encode('utf-8'), iterations=10000)).decode('ascii')


def check_password_hash(password_hash, password):
    return password_hash == generate_password_hash(password)


def generate_token(user):
    user_info = {
        'user_id': user.id,
        'email': user.email,
        'username': user.username,
        'is_admin': user.is_admin
    }

    return jwt.encode({
        'user_info': user_info,
        'exp': datetime.utcnow() + timedelta(JWT_EXPIRATION)
    }, JWT_SECRET, algorithm='HS256')


Base = declarative_base()


class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True)
    default = Column(Boolean, default=False, index=True)
    permissions = Column(Integer)
    users = relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = session.query(Role).filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            session.add(role)
        session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(64), unique=True, index=True)
    username = Column(String(64), unique=True, index=True)
    role_id = Column(Integer, ForeignKey('roles.id'))
    password_hash = Column(String(64))
    is_admin = Column(Boolean, default=False)

    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word())
            session.add(u)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == 'abc@abc.com':
                self.role = session.query(Role).filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = session.query(Role).filter_by(default=True).first()
        session.add(self)
        session.commit()

    @validates('email')
    def validate_email(self, key, address):
        assert '@' in address
        return address

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def __repr__(self):
        return '<User %r>' % self.username

    @staticmethod
    def create(email, username, password, is_admin=False):
        try:
            new_user = User(email=email,
                            username=username,
                            password=password,
                            is_admin=is_admin)
            session.add(new_user)
            session.commit()
            token = generate_token(new_user)
            return token, True
        except SQLAlchemyError as e:
            print(e)
            session.rollback()
            return str(e), False

    @staticmethod
    def login(username, password):
        try:
            user = session.query(User).filter_by(username=username).one()
            if not user.verify_password(password):
                return None
            token = generate_token(user)
            return token
        except NoResultFound:
            return None


Base.metadata.create_all(engine)
Role.insert_roles()
print('table created')
