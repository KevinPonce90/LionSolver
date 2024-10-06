from werkzeug.security import check_password_hash
from flask_login import UserMixin

class Admin(UserMixin):

    def __init__(self, cod, password, campus="", office="", fullname="",  email="", priv="") -> None:
        self.id = cod
        self.password = password
        self.campus = campus
        self.career = office
        self.fullname = fullname
        self.email = email
        self.priv = priv
        

    @classmethod
    def check_password(self, hashed_password, password):
        return check_password_hash(hashed_password, password)
