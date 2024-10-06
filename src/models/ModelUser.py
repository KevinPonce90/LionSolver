from .entities.User import User
class ModelUser():  

    @classmethod
    def login(self,db,user):
        try:
            cursor = db.connection.cursor()
            cursor.execute(" SELECT user_cod, user_password, user_campus, user_fullname, user_email, user_career, user_active FROM users WHERE user_cod = %s", (user.id,))
            us = cursor.fetchone()
            cursor.close()

            if us != None:
                user = User(us[0], User.check_password(us[1], user.password), us[2], us[3], us[4], us[5], us[6])
                return user
            else:
                return None

        except Exception as ex:
            raise Exception(ex)
        
    @classmethod
    def get_by_cod(self, db, cod):
        try:
            cursor = db.connection.cursor()
            cursor.execute(" SELECT user_cod, user_campus, user_fullname, user_email, user_career, user_active FROM users WHERE user_cod = %s", (cod,))
            us = cursor.fetchone()
            cursor.close()

            if us != None:
                return User(us[0], None, us[1], us[2], us[3], us[4], us[5])
            else:
                return None

        except Exception as ex:
            raise Exception(ex)