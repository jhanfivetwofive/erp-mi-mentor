from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from authlib.integrations.flask_client import OAuth
from google.cloud import bigquery
import os
import pandas as pd
import time
import json
from functools import wraps  # Asegúrate de importar wraps
from flask_session import Session
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
# opcional, si generarás hashes también
from werkzeug.security import generate_password_hash
from firebase_admin import credentials, auth
import firebase_admin
from google.cloud import secretmanager
from firebase_admin import auth as firebase_auth


def get_firebase_credentials():
    client = secretmanager.SecretManagerServiceClient()
    name = "projects/fivetwofive-20/secrets/firebase-key/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data


if not firebase_admin._apps:
    cred = credentials.Certificate(json.loads(get_firebase_credentials()))
    firebase_admin.initialize_app(cred)

import firebase_admin
from firebase_admin import auth as firebase_auth

# Inicializar Firebase con credenciales de servicio
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)

load_dotenv()

# Crear la app antes de usarla
app = Flask(__name__)  # ✅ Esto debe ir antes de usar app

# Configuración secreta y de entorno
app.secret_key = os.getenv("FLASK_SECRET_KEY")
project_id = os.getenv("GCP_PROJECT_ID")

# Ruta del directorio de sesiones
session_dir = '/tmp/flask_sessions'

# Verificar si el directorio existe, si no, crear el directorio
if not os.path.exists(session_dir):
    os.makedirs(session_dir)
    print(f"Directorio {session_dir} creado.")
else:
    print(f"El directorio {session_dir} ya existe.")

    # Configuración


# Configuración de la clave secreta para manejar las sesiones
# app.secret_key = os.urandom(24)  # Usa una clave secreta aleatoria

# Configuración explícita del almacenamiento de sesiones
# Esto almacenará las sesiones en el sistema de archivos
app.config['SESSION_TYPE'] = 'filesystem'
# Hace que las sesiones sean temporales por defecto
app.config['SESSION_PERMANENT'] = False
# Opcional: directorio donde se almacenarán las sesiones
app.config['SESSION_FILE_DIR'] = '/tmp/flask_sessions'

# Inicializa la extensión Flask-Session
Session(app)

app.debug = True

client = bigquery.Client()

# Vista de alumnos
BQ_VIEW = "fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL"


@app.route("/")
def home():
    return redirect(url_for("login_firebase_page"))

@app.route("/login_firebase", methods=["GET"])
def login_firebase_page():
    return render_template("login_firebase.html")

@app.route("/login_firebase", methods=["POST"])
def login_firebase():
    try:
        data = request.get_json()
        id_token = data.get("idToken")

        decoded_token = auth.verify_id_token(id_token)
        email = decoded_token["email"]

        # Buscar en BigQuery si el usuario existe
        query = """
            SELECT correo, nombre, rol
            FROM `fivetwofive-20.INSUMOS.DB_USUARIO`
            WHERE correo = @correo
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("correo", "STRING", email)]
        )
        result = client.query(query, job_config=job_config).result()

        user = None
        for row in result:
            user = {
                "correo": row["correo"],
                "nombre": row["nombre"],
                "rol": row["rol"]
            }

        if not user:
            return jsonify({"error": "Usuario no autorizado"}), 403

        session["user"] = user
        return jsonify({"message": "Login exitoso"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401
def crear_usuario_firebase(correo, password):
    user = firebase_auth.create_user(
        email=correo,
        password=password
    )
    print(f"Usuario creado: {user.uid}")

@app.route("/login_firebase", methods=["POST"])
def login_firebase():
    try:
        data = request.get_json()
        id_token = data.get("idToken")

        # Verifica el token con Firebase
        decoded_token = firebase_auth.verify_id_token(id_token)
        email = decoded_token["email"]

        # Busca al usuario en tu BigQuery
        query = """
            SELECT correo, nombre, rol
            FROM `fivetwofive-20.INSUMOS.DB_USUARIO`
            WHERE correo = @correo
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("correo", "STRING", email)]
        )
        result = client.query(query, job_config=job_config).result()

        user = None
        for row in result:
            user = {
                "correo": row["correo"],
                "nombre": row["nombre"],
                "rol": row["rol"]
            }

        if not user:
            return jsonify({"error": "Usuario no autorizado"}), 403

        session["user"] = user
        return jsonify({"message": "Login exitoso"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401



@app.route('/logout')
def logout():
    session.pop('user', None)  # Elimina al usuario de la sesión
    return redirect(url_for('login_firebase'))  # Redirige a la página de login


def login_required(roles=["admin"]):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                # Redirige al login si no hay sesión
                return redirect(url_for("login_firebase"))

            user = session["user"]
            if user["rol"] not in roles:  # Asegurando que el rol es correcto
                return "No tienes permiso para acceder a esta página", 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route("/admin")
# Solo los usuarios con rol 'admin' pueden acceder
@login_required(roles=["admin"])
def admin_page():
    return render_template("admin.html")


@app.route('/alumnos')
def alumnos_page():
    if 'user' not in session:
        # Redirige si no hay sesión activa
        return redirect(url_for('login_firebase'))
    return render_template("alumnos.html")

    # Endpoint para obtener datos de alumnos


@app.route("/api/alumnos")
def api_alumnos():
    # Lógica para obtener datos
    start = time.time()
    generacion = request.args.get("generacion", "").strip()
    correo = request.args.get("correo", "").strip()

    query = """
            SELECT
                ID_INSCRIPCION,
                FECHA_INSCRIPCION,
                ID_ALUMNO,
                FECHA_COMPRA,
                NOMBRE_ALUMNO,
                TELEFONO,
                CORREO,
                ID_PROGRAMA,
                PROGRAMA,
                SKU_PRODUCTO,
                ID_GENERACION_PROGRAMA,
                GENERACION_PROGRAMA,
                FUENTE,
                PRECIO_GENERACION
            FROM fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL
            WHERE 1=1
        """

    if generacion:
        query += f" AND GENERACION_PROGRAMA = @generacion"
    if correo:
        query += f" AND LOWER(CORREO) = @correo"

    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("generacion", "STRING", generacion),
            bigquery.ScalarQueryParameter("correo", "STRING", correo.lower())
        ]
    )
    df = client.query(query, job_config=job_config).to_dataframe()

    # Convertir fechas de manera segura
    for col in df.select_dtypes(include=["datetime64[ns]", "object"]).columns:
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            df[col] = df[col].apply(lambda x: x.strftime(
                '%Y-%m-%d') if pd.notnull(x) else "")

    # Rellenar valores vacíos en columnas tipo texto
    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].fillna("")

    alumnos = df.to_dict(orient="records")
    return jsonify(alumnos)


@app.route('/api/generaciones')
def obtener_generaciones():
    query = """
            SELECT DISTINCT GENERACION_PROGRAMA
            FROM fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL
            WHERE GENERACION_PROGRAMA IS NOT NULL
            ORDER BY GENERACION_PROGRAMA
        """
    generaciones = client.query(query).result()
    return jsonify([row.GENERACION_PROGRAMA for row in generaciones])


@app.route("/catalogo/<catalogo_id>")
def catalogo_page(catalogo_id):
    return render_template(f"catalogo_{catalogo_id}.html", catalogo_id=catalogo_id)

    # Ruta para visualizar todos los programas


@app.route("/catalogo/programas")
def catalogo_programas():
    if 'user' not in session:
        # Redirige si no hay sesión activa
        return redirect(url_for('login_firebase'))
    return render_template("cat_programas.html")

    # Ruta para visualizar todas las generaciones


@app.route("/catalogo/generaciones")
def catalogo_generaciones():
    if 'user' not in session:
        # Redirige si no hay sesión activa
        return redirect(url_for('login_firebase'))
    return render_template("cat_generacion_programas.html")

    # API para obtener los datos de los programas


@app.route('/api/catalogo/programas')
def api_programas():
    query = """
            SELECT 
                ID_PROGRAMA, 
                NOMBRE_PROGRAMA, 
                NOMENCLATURA, 
                DESCRIPCION, 
                SKU_PRODUCTO, 
                EMBUDO 
            FROM fivetwofive-20.INSUMOS.CAT_PROGRAMA
        """
    try:
        df = client.query(query).to_dataframe()

        # Verificar si la consulta tiene resultados
        if df.empty:
            return jsonify({"error": "No data found for programs"}), 404

        # Convertir valores vacíos en columnas tipo texto
        for col in df.select_dtypes(include=["object", "string"]).columns:
            df[col] = df[col].fillna("")

        programas = df.to_dict(orient="records")
        return jsonify(programas)
    except Exception as e:
        return jsonify({"error": f"Failed to load data: {str(e)}"}), 500

    # API para obtener los datos de las generaciones


@app.route('/api/catalogo/generaciones')
def api_generaciones():
    query = """
            SELECT 
                ID_GENERACION_PROGRAMA, 
                PROGRAMA, 
                GENERACION, 
                GENERACION_ETIQUETA, 
                FECHA_INICIO, 
                FECHA_FIN, 
                PRECIO_GENERACION, 
                DESCRIPCION 
            FROM fivetwofive-20.INSUMOS.CAT_GENERACION_PROGRAMA
        """
    try:
        df = client.query(query).to_dataframe()

        # Verificar si la consulta tiene resultados
        if df.empty:
            return jsonify({"error": "No data found for generations"}), 404

        # Convertir fechas de manera segura
        # Asegurarse de que los valores NaT sean manejados correctamente
        for col in ['FECHA_INICIO', 'FECHA_FIN']:
            # Convierte las fechas, 'coerce' reemplaza errores por NaT
            df[col] = pd.to_datetime(df[col], errors='coerce')
            # Rellena los NaT con un valor predeterminado (puede ser una cadena vacía o 'No Disponible')
            df[col] = df[col].fillna('No Disponible')

        # Convertir valores vacíos en columnas tipo texto
        for col in df.select_dtypes(include=["object", "string"]).columns:
            df[col] = df[col].fillna("")

        generaciones = df.to_dict(orient="records")
        return jsonify(generaciones)

    except Exception as e:
        return jsonify({"error": f"Failed to load data: {str(e)}"}), 500


@app.route("/alumnos/nuevo", methods=["GET", "POST"])
# Opcional, puedes quitar esto si deseas acceso libre
@login_required(roles=["admin"])
def nuevo_alumno():
    if request.method == "POST":
        nombre = request.form.get("nombre")
        correo = request.form.get("correo")
        telefono = request.form.get("telefono")
        programa = request.form.get("programa")
        generacion = request.form.get("generacion")

        # Aquí iría la lógica para guardar en BigQuery
        print("Alumno recibido:", nombre, correo,
              telefono, programa, generacion)

        return redirect(url_for("alumnos_page"))

    return render_template("nuevo_alumno.html")


@app.route('/alumno/<correo>', methods=['GET'])
def get_alumno_info(correo):
    try:
        # Consulta para la información del alumno
        query_alumno = """
            SELECT
            ID_ALUMNO,
            CORREO,
            STRING_AGG(DISTINCT PROGRAMA, ', ') AS PROGRAMA,
            STRING_AGG(DISTINCT GENERACION_PROGRAMA, ', ') AS GENERACION_PROGRAMA,
            MAX(NOMBRE_ALUMNO) AS NOMBRE_ALUMNO,
            MAX(TELEFONO) AS TELEFONO,
            MIN(FECHA_INSCRIPCION) AS FECHA_INSCRIPCION
            FROM `fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL` 
            WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
            GROUP BY ID_ALUMNO, CORREO
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter(
                "correo", "STRING", correo)]
        )
        result_alumno = client.query(
            query_alumno, job_config=job_config).result()

        alumno_info = None
        for row in result_alumno:
            alumno_info = {
                'ID_ALUMNO': row['ID_ALUMNO'],
                'NOMBRE_ALUMNO': row['NOMBRE_ALUMNO'],
                'CORREO': row['CORREO'],
                'TELEFONO': row['TELEFONO'],
                'FECHA_INSCRIPCION': row['FECHA_INSCRIPCION'],
                'PROGRAMA': row['PROGRAMA'],
                'GENERACION_PROGRAMA': row['GENERACION_PROGRAMA']
            }

        # Consulta para cursos
        query_cursos = """
            SELECT COURSE_NAME, PERCENTAGE_COMPLETED,
                   STARTED_AT, UPDATED_AT, COMPLETED_AT
            FROM `fivetwofive-20.INSUMOS.DB_PROGRESO_AVANCE_EDUCATIVO_THINKIFIC`
            WHERE LOWER(TRIM(user_email)) = LOWER(TRIM(@correo))
        """
        result_cursos = client.query(
            query_cursos, job_config=job_config).result()

        cursos_info = []
        for row in result_cursos:
            cursos_info.append({
                'COURSE_NAME': row['COURSE_NAME'],
                'PERCENTAGE_COMPLETED': row['PERCENTAGE_COMPLETED'],
                'STARTED_AT': row['STARTED_AT'],
                'UPDATED_AT': row['UPDATED_AT'],
                'COMPLETED_AT': row['COMPLETED_AT']
            })

        print("Renderizando plantilla panel_alumnos.html...")
        return render_template('panel_alumnos.html',
                               alumno_info=alumno_info,
                               cursos_info=cursos_info)

    except Exception as e:
        import traceback
        traceback.print_exc()  # muestra el error en la consola de Cloud Run o local
        return jsonify({"error": str(e)}), 500
