from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from authlib.integrations.flask_client import OAuth
from google.cloud import bigquery
import os
import pandas as pd
import time
from functools import wraps  # Asegúrate de importar wraps
from flask_session import Session

# Ruta del directorio de sesiones
session_dir = '/tmp/flask_sessions'

# Verificar si el directorio existe, si no, crear el directorio
if not os.path.exists(session_dir):
    os.makedirs(session_dir)
    print(f"Directorio {session_dir} creado.")
else:
    print(f"El directorio {session_dir} ya existe.")


# Configuración
app = Flask(__name__)

# Configuración de la clave secreta para manejar las sesiones
app.secret_key = os.urandom(24)  # Usa una clave secreta aleatoria

# Configuración explícita del almacenamiento de sesiones
app.config['SESSION_TYPE'] = 'filesystem'  # Esto almacenará las sesiones en el sistema de archivos
app.config['SESSION_PERMANENT'] = False  # Hace que las sesiones sean temporales por defecto
app.config['SESSION_FILE_DIR'] = '/tmp/flask_sessions'  # Opcional: directorio donde se almacenarán las sesiones

# Inicializa la extensión Flask-Session
Session(app)

app.debug = True

client = bigquery.Client()

# Vista de alumnos
BQ_VIEW = "fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL"

@app.route("/")
def home():
    return "Mini ERP de Alumnos - Mi Mentor de Inversión"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']

        # Consulta segura en BigQuery usando parámetros
        query = """
        SELECT correo, nombre, rol
        FROM `fivetwofive-20.INSUMOS.DB_USUARIO`
        WHERE correo = @correo
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("correo", "STRING", correo)]
        )
        result = client.query(query, job_config=job_config).result()

        user = None
        for row in result:
            user = {'correo': row['correo'], 'nombre': row['nombre'], 'rol': row['rol']}

        if user:
            # Guardar la información del usuario en la sesión
            session['user'] = {'correo': user['correo'], 'nombre': user['nombre'], 'rol': user['rol']}
            return redirect(url_for('alumnos_page'))
        else:
            return "Usuario no encontrado", 401

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)  # Elimina al usuario de la sesión
    return redirect(url_for('login'))  # Redirige a la página de login

def login_required(roles=["admin"]): 
    def decorator(f):  
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))  # Redirige al login si no hay sesión

            user = session["user"]
            if user["rol"] not in roles:  # Asegurando que el rol es correcto
                return "No tienes permiso para acceder a esta página", 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/admin")
@login_required(roles=["admin"])  # Solo los usuarios con rol 'admin' pueden acceder
def admin_page():
    return render_template("admin.html")

@app.route('/alumnos')
def alumnos_page():
    if 'user' not in session:
        return redirect(url_for('login'))  # Redirige si no hay sesión activa
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
            df[col] = df[col].apply(lambda x: x.strftime('%Y-%m-%d') if pd.notnull(x) else "")
    
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
#@login_required(roles=["admin", "usuario"])  # Solo los usuarios con rol 'admin' o 'usuario' pueden acceder
def catalogo_page(catalogo_id):
    return render_template(f"catalogo_{catalogo_id}.html", catalogo_id=catalogo_id)

# Ruta para visualizar todos los programas
@app.route("/catalogo/programas")
#@login_required(roles=["admin", "usuario"])
def catalogo_programas():
    return render_template("cat_programas.html")

# Ruta para visualizar todas las generaciones
@app.route("/catalogo/generaciones")
#@login_required(roles=["admin", "usuario"])
def catalogo_generaciones():
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
            df[col] = pd.to_datetime(df[col], errors='coerce')  # Convierte las fechas, 'coerce' reemplaza errores por NaT
            df[col] = df[col].fillna('No Disponible')  # Rellena los NaT con un valor predeterminado (puede ser una cadena vacía o 'No Disponible')

        # Convertir valores vacíos en columnas tipo texto
        for col in df.select_dtypes(include=["object", "string"]).columns:
            df[col] = df[col].fillna("")

        generaciones = df.to_dict(orient="records")
        return jsonify(generaciones)

    except Exception as e:
        return jsonify({"error": f"Failed to load data: {str(e)}"}), 500    

    

