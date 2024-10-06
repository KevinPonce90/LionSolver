# ~~~~~~~~~~~~~~~~~~~~ LIBS ~~~~~~~~~~~~~~~~~~~~
from flask import Flask, render_template, request, redirect, url_for, render_template_string, flash
from flask_wtf.csrf import CSRFProtect
from flask_mysqldb import MySQL, MySQLdb
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import config
from werkzeug.security import generate_password_hash

import folium
import json
import PyPDF2

# ~~~~~~~~~~~~~~~~~~~~ MODELS ~~~~~~~~~~~~~~~~~~~~
from models.ModelUser import ModelUser
from models.ModelAdmin import ModelAdmin

# ~~~~~~~~~~~~~~~~~~~~ ENTITIES ~~~~~~~~~~~~~~~~~~~~
from models.entities.User import User
from models.entities.Admin import Admin


app = Flask(__name__, template_folder='template')

csrf = CSRFProtect()
db = MySQL(app)
login_manager_app = LoginManager(app)


# ~~~~~~~~~~~~~~~~~~~~ LOGIN VALIDATION ~~~~~~~~~~~~~~~~~~~~
@login_manager_app.user_loader
def load_user(id):
    user = ModelUser.get_by_cod(db,id)
    if user is not None:
        return user
    
    admin = ModelAdmin.get_by_cod(db,id)
    if admin is not None:
        return admin
    
    return None

# ~~~~~~~~~~~~~~~~~~~~ RUTAS ~~~~~~~~~~~~~~~~~~~~

@app.route('/')
def index():
    return redirect(url_for('home'))

# ~~~~~~~~~~~~~~~~~~~~ LOGIN ~~~~~~~~~~~~~~~~~~~~
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        user = User(request.form['codigo'], request.form['password'])
        logged_user = ModelUser.login(db,user)

        admin = Admin(request.form['codigo'], request.form['password'])
        logged_admin = ModelAdmin.login(db,admin)

        if logged_user != None:
            if logged_user.password and (logged_user.active == 1):
                login_user(logged_user)
                return redirect(url_for('home'))
            else: 
                flash("Contraseña incorrecta o Estudiante no activo")
                return render_template('auth/login.html')
        
        elif logged_admin != None:
            if logged_admin.password:
                login_user(logged_admin)
                return redirect(url_for('admin'))
            else: 
                flash("Contraseña incorrecta")
                return render_template('auth/login.html')
        
        else:
            flash("Usurario no encontrado")
            return render_template('auth/login.html')
    else:
        return render_template('auth/login.html')

# ~~~~~~~~~~~~~~~~~~~~ LOGOUT ~~~~~~~~~~~~~~~~~~~~
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# ~~~~~~~~~~~~~~~~~~~~ MAP ~~~~~~~~~~~~~~~~~~~~
@app.route('/home')
@login_required
def home():
    user = current_user
    priv = False
    if isinstance(current_user, Admin):
        priv = True
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM campus C INNER JOIN offices O ON C.campus_name = O.office_campus INNER JOIN admins A ON O.office_id = A.admin_office WHERE campus_name = %s", (user.campus,))
    cam = cursor.fetchone()
    cursor.close()



    if cam:
        m = folium.Map([cam['campus_lat'], cam['campus_lon']], zoom_start=17, max_zoom=30)
        html = """

        <style> 
            h1 {{
                font-size: 24px;
                font-family: bold, sans-serif;
            }}
            p {{
                font-size: 16px;
                color: darkblue;
                margin-bottom: 10px;
            }}
        </style>
        <h1>{office_name}</h1>
        <p>{office_desc}</p>
        <p>{office_phone}</p>
        <p>{office_hours}</p>
        """.format(
            office_name=cam['office_name'], 
            office_desc=cam['office_desc'], 
            office_phone=cam['office_phone'], 
            office_hours=cam['office_hours']
        )
        
        folium.Marker([cam['office_lat'], cam['office_lon']], tooltip=cam['office_name'], popup=folium.Popup(html, max_width=2650), icon=folium.Icon(color='red')).add_to(m)

        if isinstance(cam['campus_coords'], dict):
            geojson_data = json.dumps(cam['campus_coords'])
        else:
            geojson_data = cam['campus_coords']
        
        folium.GeoJson(geojson_data, style_function=lambda feature: {
            "color": "black",
            "weight": 4,
        },).add_to(m)

        m.get_root().html.add_child(folium.Element("<style>#map {width: 100%; height: 100%; position: absolute; top: 0; bottom: 0; left: 0; right: 0;}</style>"))
        iframe = m._repr_html_()

        return render_template('home.html', campus=cam, iframe=iframe, priv = priv)
    else:
        return "Campus not found", 404

# ~~~~~~~~~~~~~~~~~~~~ CAMPUS CRUD ~~~~~~~~~~~~~~~~~~~~
@app.route('/campus_view', methods=["GET"])
@login_required
def campus_view():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM campus")
    campus_list = cursor.fetchall()
    cursor.close()
    priv = True
    return render_template('campus_view.html', campus_list=campus_list, priv = priv )


@app.route('/campus_Add', methods=["GET", "POST"])
@login_required
def campus_Add():
    if request.method == "POST":
        campus_name = request.form['campus_name'].encode('utf-8')
        campus_lat = request.form['campus_lat'].encode('utf-8')
        campus_lon = request.form['campus_lon'].encode('utf-8')
        campus_coords_file = request.files.get('campus_coords')
        if campus_coords_file:
            try:
                campus_coords_content = campus_coords_file.read().decode('utf-8')
                campus_coords_json = json.loads(campus_coords_content)
                cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("INSERT INTO campus (campus_name, campus_coords, campus_lat, campus_lon) VALUES (%s, %s, %s, %s)", (campus_name, campus_coords_json, campus_lat, campus_lon,))
                db.connection.commit()
                cursor.close()
                flash('Campus creado con éxito.')
                return redirect(url_for('admin'))
            except ValueError as e:
                flash('El archivo JSON no es válido.', e)
                return redirect(url_for('admin'))
            except Exception as e:
                flash('Ocurrió un error al agregar el campus.', e)
                return redirect(url_for('admin'))
        else:
            flash('Por favor, carga un archivo JSON válido.')
            return redirect(url_for('admin'))

    return redirect(url_for('admin'))

@app.route('/campus_Edit', methods=["GET", "POST"])
@login_required
def campus_Edit():
    campus_name = request.form['campus_name'].encode('utf-8')
    campus_lat = request.form['campus_lat'].encode('utf-8')
    campus_lon = request.form['campus_lon'].encode('utf-8')

    campus_coords_file = request.files['campus_coords']
    if campus_coords_file:
        try:
            campus_coords_content = campus_coords_file.read().decode('utf-8')
            campus_coords_json = json.loads(campus_coords_content)
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("UPDATE campus SET campus_coords = %s, campus_lat = %s, campus_lon = %s WHERE campus_name = %s", (campus_coords_json, campus_lat, campus_lon, campus_name,))
            db.connection.commit()
            cursor.close()
            flash('Campus editado con éxito.')
            return redirect(url_for('admin'))
        except ValueError as e:
            flash('El archivo JSON no es válido.', e)
            return redirect(url_for('campus_Edit'))

    else:
        flash('Por favor, carga un archivo JSON válido.')
        return redirect(url_for('admin'))
    
    
@app.route('/campus_Delete', methods=["GET", "POST"])
@login_required
def campus_Delete():
    campus_name = request.form['campus_name']
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("DELETE FROM campus WHERE campus_name = %s", (campus_name,))
    db.connection.commit()
    cursor.close()
    flash('Campus eliminado con éxito.')
    return redirect(url_for('admin'))


# ~~~~~~~~~~~~~~~~~~~~ OFFICE CRUD ~~~~~~~~~~~~~~~~~~~~
@app.route('/office_Add', methods=["GET", "POST"])
@login_required
def office_Add():
    office_campus = request.form['office_campues'].encode('utf-8')
    office_name = request.form['office_name'].encode('utf-8')
    office_lat = request.form['office_lat'].encode('utf-8')
    office_lon = request.form['office_lon'].encode('utf-8')
    office_career = request.form['office_career'].encode('utf-8')

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("INSERT INTO offices (office_campus, office_name, office_lat, office_lon, office_career) VALUES (%s, %s, %s, %s, %s)", (office_campus, office_name, office_lat, office_lon, office_career,))
    db.connection.commit()
    cursor.close()
    flash('Oficina creada con exito.')
    return redirect(url_for('admin'))

@app.route('/office_Edit', methods=["GET", "POST"])
@login_required
def office_Edit():

    office_name = request.form['office_name'].encode('utf-8')
    office_desc = request.form['office_desc'].encode('utf-8')
    office_phone = request.form['office_phone'].encode('utf-8')
    office_hours = request.form['office_hours'].encode('utf-8')

    office_id = request.form['office_id']

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("UPDATE offices SET office_name = %s, office_desc = %s, office_phone = %s, office_hours = %s WHERE office_id = %s", (office_name, office_desc, office_phone, office_hours, office_id,))
    db.connection.commit()
    cursor.close()
    flash('Cuenta editada con exito.')
    return redirect(url_for('admin'))

@app.route('/office_Delete', methods=["GET", "POST"])
@login_required
def office_Delete():
    office_id = request.form['office_id']
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("DELETE FROM offices WHERE office_id = %s", (office_id,))
    db.connection.commit()
    cursor.close()
    flash('Oficina eliminada con exito.')
    return redirect(url_for('admin'))


# ~~~~~~~~~~~~~~~~~~~~ ADMIN CRUD ~~~~~~~~~~~~~~~~~~~~

@app.route('/admin_View', methods=["GET", "POST"])
@login_required
def admin_View():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT * FROM admins A INNER JOIN offices O ON A.admin_office = O.office_id INNER JOIN campus C ON A.admin_campus = C.campus_name")
    ad = cursor.fetchall()
    cursor.close()

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM offices")
    of = cursor.fetchall()
    cursor.close()

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM campus")
    ca = cursor.fetchall()
    cursor.close()

    priv = True

    return render_template('admin_view.html', admin = ad, office = of, campus = ca, priv = priv)

@app.route('/admin_Add', methods=["GET", "POST"])
@login_required
def admin_Add():
    admin_cod = request.form['admin_cod']
    admin_password = request.form['admin_password']
    hashed_pass = generate_password_hash(admin_password)
    admin_campus = request.form['admin_campus'].encode('utf-8')
    admin_office = request.form['admin_office']
    admin_fullname = request.form['admin_fullname'].encode('utf-8')
    admin_email = request.form['admin_email'].encode('utf-8')
    admin_priv = request.form['admin_priv'].encode('utf-8')

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("INSERT INTO admins (admin_cod, admin_password, admin_campus, admin_office, admin_fullname, admin_email, admin_priv) VALUES (%s, %s, %s, %s, %s, %s, %s)", (admin_cod, hashed_pass, admin_campus, admin_office, admin_fullname, admin_email, admin_priv,))
    db.connection.commit()
    cursor.close()
    flash('Admin creado con exito.')
    return redirect(url_for('admin_View'))

@app.route('/admin_Edit', methods=["GET", "POST"])
@login_required
def admin_Edit():
    admin_cod = request.form['admin_cod']
    admin_campus = request.form['admin_campus'].encode('utf-8')
    admin_office = request.form['admin_office']
    admin_fullname = request.form['admin_fullname'].encode('utf-8')
    admin_email = request.form['admin_email'].encode('utf-8')
    admin_priv = request.form['admin_priv'].encode('utf-8')

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("UPDATE admins SET admin_campus = %s, admin_office = %s, admin_fullname = %s, admin_email = %s, admin_priv = %s WHERE admin_cod = %s", ( admin_campus, admin_office, admin_fullname, admin_email, admin_priv, admin_cod,))
    db.connection.commit()
    cursor.close()
    flash('Admin editado con exito.')
    return redirect(url_for('admin_View'))

@app.route('/admin_Delete', methods=["GET", "POST"])
@login_required
def admin_Delete():
    admin_cod = request.form['admin_cod']
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("DELETE FROM admins WHERE admin_cod = %s", (admin_cod,))
    db.connection.commit()
    cursor.close()
    flash('Admin eliminado con exito.')
    return redirect(url_for('admin_View'))

@app.route('/admin', methods=["GET", "POST"])
@login_required
def admin():
    
    admin = current_user

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM admins A INNER JOIN offices O ON A.admin_office = O.office_id INNER JOIN campus C ON A.admin_campus = C.campus_name WHERE admin_cod = %s", (admin.id,))
    ad = cursor.fetchone()
    cursor.close()
    priv = True
    if ad['admin_priv'] == 1:
        return render_template('admin_rec.html',admin = ad, priv = priv)
    else:
        return render_template('admin.html',admin = ad, priv = priv)

# ~~~~~~~~~~~~~~~~~~~~ CHATBOT ~~~~~~~~~~~~~~~~~~~~



# ~~~~~~~~~~~~~~~~~~~~ PROTECT VIEW ~~~~~~~~~~~~~~~~~~~~
@app.route('/protected')
@login_required
def protected():
    return "<h1>Esta es una vista protegida, solo para usuarios autorizados.</h1>"

# ~~~~~~~~~~~~~~~~~~~~ ERRORES ~~~~~~~~~~~~~~~~~~~~
def status_401(error):
    return redirect(url_for('login'))

def status_404(error):
    return "<h1>Pagina no encontrada</h1>", 404

if __name__ == '__main__':
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    app.run()