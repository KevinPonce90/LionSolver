from werkzeug.security import check_password_hash
from flask_login import UserMixin

class User(UserMixin):

    def __init__(self, cod, password, campus="", fullname="", email="", career="", active="") -> None:
        self.id = cod
        self.password = password
        self.campus = campus
        self.fullname = fullname
        self.email = email
        self.career = career
        self.active = active

    @classmethod
    def check_password(self, hashed_password, password):
        return check_password_hash(hashed_password, password)
