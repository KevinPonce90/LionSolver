from .entities.Admin import Admin
class ModelAdmin():  

    @classmethod
    def login(self,db,admin):
        try:
            cursor = db.connection.cursor()
            cursor.execute(" SELECT admin_cod, admin_password, admin_campus, admin_office, admin_fullname, admin_email, admin_priv FROM admins WHERE admin_cod = %s", (admin.id,))
            ad = cursor.fetchone()
            cursor.close()

            if ad != None:
                admin = Admin(ad[0], Admin.check_password(ad[1], admin.password), ad[2], ad[3], ad[4], ad[5], ad[6])
                return admin
            else:
                return None

        except Exception as ex:
            raise Exception(ex)
        
    @classmethod
    def get_by_cod(self, db, cod):
        try:
            cursor = db.connection.cursor()
            cursor.execute(" SELECT admin_cod, admin_campus, admin_office, admin_fullname, admin_email, admin_priv FROM admins WHERE admin_cod = %s", (cod,))
            us = cursor.fetchone()
            cursor.close()

            if us != None:
                return Admin(us[0], None, us[1], us[2], us[3], us[4], us[5])
            else:
                return None

        except Exception as ex:
            raise Exception(ex)