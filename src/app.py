# ~~~~~~~~~~~~~~~~~~~~ LIBS ~~~~~~~~~~~~~~~~~~~~
from flask import Flask, render_template, request, redirect, url_for, render_template_string, flash, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_mysqldb import MySQL, MySQLdb
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import config
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

import folium
import json
import PyPDF2

import openai
import os
import tiktoken
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import pickle

# ~~~~~~~~~~~~~~~~~~~~ MODELS ~~~~~~~~~~~~~~~~~~~~
from models.ModelUser import ModelUser
from models.ModelAdmin import ModelAdmin

# ~~~~~~~~~~~~~~~~~~~~ ENTITIES ~~~~~~~~~~~~~~~~~~~~
from models.entities.User import User
from models.entities.Admin import Admin


app = Flask(__name__, template_folder='template')
load_dotenv()

csrf = CSRFProtect()
db = MySQL(app)
login_manager_app = LoginManager(app)
openai.api_key = os.getenv('OPENAI_API_KEY')

# ~~~~~~~~~~~~~~~~~~~~ FUNCIONES PARA EL CHATBOT ~~~~~~~~~~~~~~~~~~~~

def extract_text_from_pdf(pdf_file: str) -> str:
    with open(pdf_file, 'rb') as pdf:
        reader = PyPDF2.PdfReader(pdf, strict=False)
        text = ''
        for page in reader.pages:
            content = page.extract_text()
            if content:
                text += content + '\n'
    return text

def split_text(text: str, max_tokens: int = 500) -> list:
    tokenizer = tiktoken.get_encoding("cl100k_base")
    sentences = text.split('. ')
    chunks = []
    chunk = ''
    tokens = 0

    for sentence in sentences:
        sentence_tokens = len(tokenizer.encode(sentence))
        if sentence_tokens > max_tokens:
            words = sentence.split(' ')
            sub_sentence = ''
            sub_tokens = 0
            for word in words:
                word_tokens = len(tokenizer.encode(word))
                if sub_tokens + word_tokens <= max_tokens:
                    sub_sentence += word + ' '
                    sub_tokens += word_tokens
                else:
                    chunks.append(sub_sentence.strip())
                    sub_sentence = word + ' '
                    sub_tokens = word_tokens
            if sub_sentence:
                chunks.append(sub_sentence.strip())
        else:
            if tokens + sentence_tokens <= max_tokens:
                chunk += sentence + '. '
                tokens += sentence_tokens
            else:
                chunks.append(chunk.strip())
                chunk = sentence + '. '
                tokens = sentence_tokens

    if chunk:
        chunks.append(chunk.strip())

    return chunks


def generate_embeddings(chunks: list, office_id: str) -> list:
    embeddings = []
    for idx, chunk in enumerate(chunks):
        try:
            print(f"Generando embedding para el fragmento {idx+1}/{len(chunks)}")
            response = openai.Embedding.create(
                input=chunk,
                model="text-embedding-ada-002"
            )
            embedding = response['data'][0]['embedding']
            embeddings.append({'embedding': embedding, 'text': chunk, 'office_id': office_id})
        except Exception as e:
            print(f"Error al generar embedding para el fragmento {idx+1}: {e}")
            continue
    print(f"Total de embeddings generados: {len(embeddings)}")
    return embeddings



def save_embeddings(embeddings: list, filename: str):
    with open(filename, 'wb') as f:
        pickle.dump(embeddings, f)

def load_embeddings(filename: str):
    try:
        with open(filename, 'rb') as f:
            embeddings = pickle.load(f)
        print(f"Embeddings cargados desde {filename}: {len(embeddings)} embeddings")
        return embeddings
    except Exception as e:
        print(f"Error al cargar embeddings desde {filename}: {e}")
        return []



def get_relevant_chunks(question: str, embeddings: list, top_k: int = 5) -> list:
    response = openai.Embedding.create(
        input=question,
        model="text-embedding-ada-002"
    )
    question_embedding = response['data'][0]['embedding']
    
    similarities = []
    for item in embeddings:
        similarity = cosine_similarity(
            [question_embedding],
            [item['embedding']]
        )[0][0]
        similarities.append((similarity, item))
    
    similarities.sort(key=lambda x: x[0], reverse=True)
    top_items = similarities[:top_k]
    return top_items


def get_answer(question: str, context: str, office_info: dict) -> str:
    def is_greeting(text):
        greetings = ['hola', 'buenos días', 'buenas tardes', 'buenas noches', 'qué tal', 'saludos', 'buen día', 'hi', 'hello', 'hey']
        text = text.lower().strip()
        return text in greetings

    if is_greeting(question):
        return "Hola, ¿en qué puedo ayudarte?"

    prompt = f"""Utiliza el siguiente contexto para responder la pregunta de manera clara y concisa.
                Al final de tu respuesta, indica cuál es la oficina correspondiente y cómo el estudiante puede contactarla.

                Contexto:
                {context}

                Pregunta:
                {question}

                Respuesta:"""

    try:
        response = openai.ChatCompletion.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.7
        )

        answer = response.choices[0].message['content']

        return answer
    except Exception as e:
        print(f"Error al obtener respuesta de ChatGPT: {e}")
        return "Lo siento, ha ocurrido un error al obtener la respuesta."



# ~~~~~~~~~~~~~~~~~~~~ CARGAR EMBEDDINGS ~~~~~~~~~~~~~~~~~~~~
all_embeddings = []

embeddings_folder = 'embeddings'

if not os.path.exists(embeddings_folder):
    os.makedirs(embeddings_folder)

for filename in os.listdir(embeddings_folder):
    if filename.endswith('.pkl'):
        embeddings = load_embeddings(os.path.join(embeddings_folder, filename))
        print(f"Cargando {len(embeddings)} embeddings desde {filename}")
        all_embeddings.extend(embeddings)

print(f"Total de embeddings cargados al iniciar la aplicación: {len(all_embeddings)}")



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

@app.route('/home')
@login_required
def home():
    user = current_user
    priv = False
    if isinstance(current_user, Admin):
        priv = True

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM campus C INNER JOIN offices O ON C.campus_name = O.office_campus WHERE campus_name = %s", (user.campus,))
    offices = cursor.fetchall()
    cursor.close()

    if offices:
        first_office = offices[0]
        # Convertir los datos de las oficinas a JSON
        offices_json = json.dumps(offices, default=str)

        # Obtener el GeoJSON del campus
        campus_geojson = first_office['campus_coords']
        # Asegurarnos de que sea un objeto JSON
        if isinstance(campus_geojson, str):
            campus_geojson = json.loads(campus_geojson)
        # Convertir a cadena JSON para pasarlo al template
        campus_geojson_json = json.dumps(campus_geojson)

        return render_template('home.html', campus=first_office, offices_json=offices_json, campus_geojson=campus_geojson_json, priv=priv)
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
def get_office_info(office_id):
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM offices WHERE office_id = %s", (office_id,))
    office = cursor.fetchone()
    cursor.close()
    if office:
        office_info = {
            'office_name': office['office_name'],
            'office_location': f"{office['office_lat']}, {office['office_lon']}",
            'office_hours': office['office_hours'],
            'office_contact': office['office_phone']
        }
        return office_info
    else:
        return {
            'office_name': 'Desconocida',
            'office_location': 'No disponible',
            'office_hours': 'No disponible',
            'office_contact': 'No disponible'
        }

@app.route('/office_View', methods=["GET", "POST"])
@login_required
def office_View():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM offices O LEFT JOIN admins A ON O.office_id = A.admin_office")
    of = cursor.fetchall()
    cursor.close()

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM campus")
    ca = cursor.fetchall()
    cursor.close()

    priv = True

    return render_template('office_view.html', office=of, priv=priv, campus = ca)

@app.route('/office_Add', methods=["GET", "POST"])
@login_required
def office_Add():
    office_campus = request.form['office_campus'].encode('utf-8')
    office_name = request.form['office_name'].encode('utf-8')
    office_lat = request.form['office_lat'].encode('utf-8')
    office_lon = request.form['office_lon'].encode('utf-8')
    office_career = request.form['office_career'].encode('utf-8')

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("INSERT INTO offices (office_campus, office_name, office_lat, office_lon, office_career) VALUES (%s, %s, %s, %s, %s)", (office_campus, office_name, office_lat, office_lon, office_career,))
    db.connection.commit()
    cursor.close()
    flash('Oficina creada con exito.')
    return redirect(url_for('office_View'))

@app.route('/office_Edit', methods=["GET", "POST"])
@login_required
def office_Edit():
    office_id = request.form['office_id']
    office_name = request.form['office_name'].encode('utf-8')
    office_desc = request.form['office_desc'].encode('utf-8')
    office_phone = request.form['office_phone'].encode('utf-8')
    office_hours = request.form['office_hours'].encode('utf-8')

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("UPDATE offices SET office_name = %s, office_desc = %s, office_phone = %s, office_hours = %s WHERE office_id = %s", (office_name, office_desc, office_phone, office_hours, office_id,))
    db.connection.commit()
    cursor.close()
    flash('Cuenta editada con exito.')
    return redirect(url_for('admin'))

@app.route('/office_Edit_Rec', methods=["GET", "POST"])
@login_required
def office_Edit_Rec():
    office_id = request.form['office_id']
    office_name = request.form['office_name'].encode('utf-8')
    office_lat = request.form['office_lat'].encode('utf-8')
    office_lon = request.form['office_lon'].encode('utf-8')
    office_career = request.form['office_career'].encode('utf-8')
    
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("UPDATE offices SET office_name = %s, office_lat = %s, office_lon = %s, office_career = %s WHERE office_id = %s", (office_name, office_lat, office_lon, office_career, office_id))
    
    db.connection.commit()
    cursor.close()
    
    flash('Oficina editada con éxito.')
    return redirect(url_for('office_View'))


@app.route('/office_Delete', methods=["GET", "POST"])
@login_required
def office_Delete():
    office_id = request.form['office_id']
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("DELETE FROM offices WHERE office_id = %s", (office_id,))
    db.connection.commit()
    cursor.close()
    flash('Oficina eliminada con exito.')
    return redirect(url_for('office_View'))


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
@app.route('/chatbot', methods=['POST'])
@login_required
def chatbot():
    print("Solicitud recibida en /chatbot")
    data = request.get_json()
    print(f"Pregunta del usuario: {data['message']}")
    user_question = data['message']
    
    if not all_embeddings:
        return jsonify({'reply': 'El chatbot aún no está listo. Por favor, procesa primero el PDF.'})
    
    top_items = get_relevant_chunks(user_question, all_embeddings, top_k=5)

    context = ""
    office_ids = []
    for _, item in top_items:
        context += item['text'] + "\n\n"
        office_ids.append(item['office_id'])

    # Obtener el office_id más común entre los fragmentos relevantes
    most_common_office_id = max(set(office_ids), key=office_ids.count)

    office_info = get_office_info(most_common_office_id)

    answer = get_answer(user_question, context, office_info)
    
    # Retornar la respuesta y el office_id
    print(most_common_office_id)
    return jsonify({'reply': answer, 'office_id': most_common_office_id})


@app.route('/upload_pdf', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    if request.method == 'POST':
        pdf_file = request.files['pdf_file']
        if pdf_file:
            if not os.path.exists('uploads'):
                os.makedirs('uploads')
            pdf_path = os.path.join('uploads', pdf_file.filename)
            pdf_file.save(pdf_path)
            text = extract_text_from_pdf(pdf_path)
            print(f"Texto extraído del PDF ({len(text)} caracteres)")
            if len(text.strip()) == 0:
                print("El texto extraído del PDF está vacío.")
                flash('El PDF no contiene texto o no se pudo extraer.')
                return redirect(url_for('upload_pdf'))
            chunks = split_text(text)
            print(f"Número de fragmentos generados: {len(chunks)}")
            office_id = str(current_user.career)
            embeddings = generate_embeddings(chunks, office_id)
            
            embeddings_folder = 'embeddings'
            if not os.path.exists(embeddings_folder):
                os.makedirs(embeddings_folder)
            embeddings_filename = f'embeddings_{office_id}.pkl'
            embeddings_path = os.path.join(embeddings_folder, embeddings_filename)
            save_embeddings(embeddings, embeddings_path)

            file_size = os.path.getsize(embeddings_path)
            print(f"Embeddings guardados en {embeddings_path} ({file_size} bytes)")

            all_embeddings.clear()
            for filename in os.listdir(embeddings_folder):
                if filename.endswith('.pkl'):
                    embeddings = load_embeddings(os.path.join(embeddings_folder, filename))
                    all_embeddings.extend(embeddings)

            flash('El PDF ha sido procesado y los embeddings se han generado correctamente.')
            return redirect(url_for('admin'))
        else:
            flash('Por favor, sube un archivo PDF.')
            return redirect(url_for('upload_pdf'))
    else:
        return render_template('upload_pdf.html')

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
    port = int(os.environ.get('PORT', 5000))
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    app.run()
