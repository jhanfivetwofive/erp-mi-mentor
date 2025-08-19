from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from authlib.integrations.flask_client import OAuth
from google.cloud import bigquery
import os
import pandas as pd
from pandas.api.types import is_numeric_dtype
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
from datetime import datetime, timezone
import uuid

def current_user_role():
    user = session.get("user") or {}
    return user.get("rol")

def get_firebase_credentials():
    client = secretmanager.SecretManagerServiceClient()
    name = "projects/fivetwofive-20/secrets/firebase-key/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data

def get_user_from_session():
    return session.get("user") or {}

def fetch_rol_from_bq(correo):
    q = """
      SELECT ANY_VALUE(rol) rol
      FROM `fivetwofive-20.INSUMOS.DB_USUARIO`
      WHERE LOWER(correo)=LOWER(@c)
    """
    job = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("c","STRING", correo)]
    )
    for row in client.query(q, job_config=job).result():
        return (row["rol"] or "").strip().lower()
    return ""

ESTADOS_PERMITIDOS = {"contactado", "en_proceso", "cerrado"}

def _now_iso_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')

# --- Inicialización de Firebase en arranque (asegúrate que la SA tenga secretAccessor) ---
if not firebase_admin._apps:
    cred = credentials.Certificate(json.loads(get_firebase_credentials()))
    firebase_admin.initialize_app(cred)

load_dotenv()

# Crear la app antes de usarla
app = Flask(__name__)  # ✅ Esto debe ir antes de usar app

# Configuración secreta y de entorno
app.secret_key = os.getenv("FLASK_SECRET_KEY")
project_id = os.getenv("GCP_PROJECT_ID")

# Ruta del directorio de sesiones
session_dir = '/tmp/flask_sessions'
if not os.path.exists(session_dir):
    os.makedirs(session_dir)
    print(f"Directorio {session_dir} creado.")
else:
    print(f"El directorio {session_dir} ya existe.")

# Configuración explícita del almacenamiento de sesiones
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_FILE_DIR'] = '/tmp/flask_sessions'

# Inicializa la extensión Flask-Session
Session(app)

app.debug = True

client = bigquery.Client()

# Vista de alumnos
BQ_VIEW = "fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL"
# Vista de comunidad consolidada de alumnos
COMMUNITY_VIEW = "fivetwofive-20.COMUNIDAD.VW_COMUNIDAD_CONSOLIDADO_X_ALUMNO"

# Filtro para formatear moneda MXN en Jinja
def mxn(value):
    try:
        if value is None or value == "":
            return ""
        return f"${float(value):,.2f}"
    except Exception:
        return str(value)

app.jinja_env.filters["mxn"] = mxn

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

        # 1. Verifica el token con Firebase
        decoded_token = firebase_auth.verify_id_token(id_token)
        email = decoded_token["email"]
        name = decoded_token.get("name", email.split("@")[0])

        # 2. Busca en BigQuery si ya existe
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

        # 3. Si no existe, crearlo como "invitado"
        if not user:
            table_id = "fivetwofive-20.INSUMOS.DB_USUARIO"
            rows_to_insert = [{
                "correo": email,
                "nombre": name,
                "rol": "invitado",  # 👈 Rol por defecto
                "firebase_uid": decoded_token["uid"]
            }]
            errors = client.insert_rows_json(table_id, rows_to_insert)
            if errors:
                print(f"Error insertando nuevo usuario: {errors}")
            user = {
                "correo": email,
                "nombre": name,
                "rol": "invitado"
            }

        # 4. Guardar en sesión
        session["user"] = user
        return jsonify({"message": "Login exitoso"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route('/logout')
def logout():
    session.pop('user', None)  # Elimina al usuario de la sesión
    return redirect(url_for('login_firebase_page'))

def login_required(roles=None):
    if roles is None:
        roles = ["admin"]  # por defecto

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login_firebase"))

            user = session["user"]
            if user["rol"] not in roles:
                return render_template("no_autorizado.html"), 403  # vista amigable

            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/admin")
@login_required(roles=["admin"])
def admin_page():
    return render_template("alumnos.html")  # <-- faltaba return

@app.route("/adquisicion")
@login_required(roles=["admin", "adquisicion"])
def adquisicion_page():
    return render_template("alumnos.html")  # <-- faltaba return

@app.route("/panel_basico")
@login_required(roles=["admin", "invitado", "postventa", "comunidad", "people", "adquisicion"])
def panel_basico():
    return render_template("alumnos.html")  # <-- faltaba return

@app.route('/alumnos')
def alumnos_page():
    if 'user' not in session:
        # Redirige si no hay sesión activa
        return redirect(url_for('login_firebase'))
    return render_template("alumnos.html")

# --------- API alumnos (ya estaba OK) ----------
@app.route("/api/alumnos")
def api_alumnos():
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
    df = df.convert_dtypes()

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
def catalogo_page(catalogo_id):
    return render_template(f"catalogo_{catalogo_id}.html", catalogo_id=catalogo_id)

@app.route("/catalogo/programas")
def catalogo_programas():
    if 'user' not in session:
        return redirect(url_for('login_firebase'))
    return render_template("cat_programas.html")

@app.route("/catalogo/generaciones")
def catalogo_generaciones():
    if 'user' not in session:
        return redirect(url_for('login_firebase'))
    return render_template("cat_generacion_programas.html")

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
        if df.empty:
            return jsonify({"error": "No data found for programs"}), 404

        for col in df.select_dtypes(include=["object", "string"]).columns:
            df[col] = df[col].fillna("")
        programas = df.to_dict(orient="records")
        return jsonify(programas)
    except Exception as e:
        return jsonify({"error": f"Failed to load data: {str(e)}"}), 500

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
        if df.empty:
            return jsonify({"error": "No data found for generations"}), 404

        for col in ['FECHA_INICIO', 'FECHA_FIN']:
            df[col] = pd.to_datetime(df[col], errors='coerce')
            df[col] = df[col].fillna('No Disponible')

        for col in df.select_dtypes(include=["object", "string"]).columns:
            df[col] = df[col].fillna("")
        generaciones = df.to_dict(orient="records")
        return jsonify(generaciones)
    except Exception as e:
        return jsonify({"error": f"Failed to load data: {str(e)}"}), 500

@app.route("/alumnos/nuevo", methods=["GET", "POST"])
@login_required(roles=["admin"])
def nuevo_alumno():
    if request.method == "POST":
        nombre = request.form.get("nombre")
        correo = request.form.get("correo")
        telefono = request.form.get("telefono")
        programa = request.form.get("programa")
        generacion = request.form.get("generacion")
        print("Alumno recibido:", nombre, correo, telefono, programa, generacion)
        return redirect(url_for("alumnos_page"))
    return render_template("nuevo_alumno.html")

@app.route('/alumno/<correo>', methods=['GET'])
def get_alumno_info(correo):
    try:
        # ---- Parametrización compartida ----
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("correo", "STRING", correo)]
        )

        # ---- 1) Info del alumno ----
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
        result_alumno = client.query(query_alumno, job_config=job_config).result()

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
            break  # solo el primero (debería ser único)

        if not alumno_info:
            return render_template('panel_alumnos.html',
                                   alumno_info=None,
                                   cursos_info=[],
                                   seguimientos=[],
                                   rol_usuario=current_user_role() if 'current_user_role' in globals() else None), 404

        # ---- 2) Cursos Thinkific ----
        query_cursos = """
            WITH base AS (
                    SELECT
                        COURSE_NAME,
                        -- Limpia posibles '%' y espacios, y castea a número
                        SAFE_CAST(REGEXP_REPLACE(CAST(PERCENTAGE_COMPLETED AS STRING), r'[%\s]', '') AS FLOAT64) AS pct,
                        STARTED_AT,
                        UPDATED_AT,
                        COMPLETED_AT
                    FROM `fivetwofive-20.INSUMOS.DB_PROGRESO_AVANCE_EDUCATIVO_THINKIFIC`
                    WHERE LOWER(TRIM(user_email)) = LOWER(TRIM(@correo))
                    )
                    SELECT
                    COURSE_NAME,
                    -- Normaliza: si está entre 0 y 1 => *100; si ya está 0–100 => se queda
                    CASE
                        WHEN pct IS NULL THEN NULL
                        WHEN pct <= 1.0 THEN ROUND(pct * 100, 2)
                        ELSE ROUND(pct, 2)
                    END AS PERCENTAGE_COMPLETED,
                    STARTED_AT,
                    UPDATED_AT,
                    COMPLETED_AT
                    FROM base
                    ORDER BY UPDATED_AT DESC;
        """
        result_cursos = client.query(query_cursos, job_config=job_config).result()

        cursos_info = []
        for row in result_cursos:
            cursos_info.append({
                'COURSE_NAME': row['COURSE_NAME'],
                'PERCENTAGE_COMPLETED': row['PERCENTAGE_COMPLETED'],
                'STARTED_AT': row['STARTED_AT'],
                'UPDATED_AT': row['UPDATED_AT'],
                'COMPLETED_AT': row['COMPLETED_AT']
            })
        
        # 2.1) Datos para gráfico de barras (Top 12 por % completado)
        chart_labels, chart_values = [], []
        try:
            cursos_sorted = sorted(
                cursos_info,
                key=lambda r: (
                    float(r.get('PERCENTAGE_COMPLETED') or 0),
                    str(r.get('UPDATED_AT') or '')
                ),
                reverse=True
            )
            top = cursos_sorted[:12]
            for r in top:
                nombre = (r.get('COURSE_NAME') or '').strip()
                if len(nombre) > 38:
                    nombre = nombre[:35] + '…'
                chart_labels.append(nombre or 'Curso')
                chart_values.append(float(r.get('PERCENTAGE_COMPLETED') or 0))
        except Exception as e:
            print("WARN chart data:", e, flush=True)

        # ---- 3) Seguimientos ----
        query_seg = """
            SELECT
              ID,
              FECHA,
              AUTOR,
              ROL_AUTOR,
              TIPO,
              NOTA,
              ESTADO
            FROM `fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO`
            WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
            ORDER BY FECHA DESC
        """
        result_seg = client.query(query_seg, job_config=job_config).result()

        seguimientos = []
        for row in result_seg:
            seguimientos.append({
                "ID": row["ID"],
                "FECHA": row["FECHA"],
                "AUTOR": row["AUTOR"],
                "ROL_AUTOR": row["ROL_AUTOR"],
                "TIPO": row.get("TIPO", ""),
                "NOTA": row.get("NOTA", ""),
                "ESTADO": row.get("ESTADO", "")
            })

        # ---- 4) KPIs de Comunidad (vista consolidada) ----
        q_comm = """
            SELECT
            MONTO_INVERTIDO_CURSOS,
            MONTO_INVERTIDO_GALA,
            MONTO_INVERTIDO_TOTAL,
            NPS_FINAL,
            CALIF_CALC_0_10,
            CALIF_EXPECTATIVAS,     -- <-- agregado
            CALIF_TEMAS,            -- <-- agregado
            CALIF_CONTENIDO,        -- <-- agregado
            CALIF_CLASE,            -- <-- agregado
            TOTAL_CURSOS,
            PROMEDIO_AVANCE,
            PROGRAMAS_CURSOS,
            GENERACION_PROGRAMAS,
            COMENTARIOS,
            TOTAL_ASISTENCIA_WEBINAR
            FROM `fivetwofive-20.COMUNIDAD.VW_COMUNIDAD_CONSOLIDADO_X_ALUMNO`
            WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
            LIMIT 1
            """
        comunidad = None
        for r in client.query(q_comm, job_config=job_config).result():
            comunidad = dict(r)
            break

        # ---- Render final (¡un solo return!) ----
        return render_template(
            'panel_alumnos.html',
            alumno_info=alumno_info,
            cursos_info=cursos_info,
            seguimientos=seguimientos,
            comunidad=comunidad,
            chart_labels=chart_labels,      # <-- nuevo
            chart_values=chart_values,      # <-- nuevo
            rol_usuario=current_user_role() if 'current_user_role' in globals() else None
        )


    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/seguimiento", methods=["POST"])
def api_crear_seguimiento():
    try:
        # 1) intenta sacar rol de sesión
        user = get_user_from_session()
        rol = (user.get("rol") or "").strip().lower()

        # 2) si no hay rol, rehidrata desde BQ por el usuario en sesión
        if not rol:
            correo_sesion = (user.get("correo") or "").strip().lower()
            if correo_sesion:
                rol = fetch_rol_from_bq(correo_sesion)
                if rol:
                    user["rol"] = rol
                    session["user"] = user

        # 3) autoriza
        if rol not in ["postventa", "admin"]:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}
        correo = (data.get("correo") or "").strip().lower()
        nota   = (data.get("nota")   or "").strip()
        tipo   = (data.get("tipo")   or "").strip().lower() or "otro"
        estado = (data.get("estado") or "contactado").strip().lower()

        ESTADOS_PERMITIDOS = {"contactado","en_proceso","cerrado"}
        if not correo or not nota:
            return jsonify({"error": "Faltan datos (correo y nota)"}), 400
        if estado not in ESTADOS_PERMITIDOS:
            return jsonify({"error": f"Estado inválido. Usa: {', '.join(sorted(ESTADOS_PERMITIDOS))}"}), 400

        # Resolver ID_ALUMNO
        query_id = """
          SELECT ANY_VALUE(ID_ALUMNO) AS ID_ALUMNO
          FROM `fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL`
          WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
        """
        res = client.query(
            query_id,
            job_config=bigquery.QueryJobConfig(
                query_parameters=[bigquery.ScalarQueryParameter("correo","STRING", correo)]
            )
        ).result()
        id_alumno = None
        for r in res:
            id_alumno = r["ID_ALUMNO"]

        table_id = "fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO"  # unificado
        row = {
            "ID": str(uuid.uuid4()),
            "ID_ALUMNO": id_alumno,   # ahora es STRING en BQ
            "CORREO": correo,
            "FECHA": _now_iso_utc(),
            "AUTOR": ((session.get("user") or {}).get("correo") or "").lower(),
            "ROL_AUTOR": rol,
            "TIPO": tipo,
            "NOTA": nota,
            "ESTADO": estado,
        }

        print("Insertando en:", table_id, "row=", row, flush=True)

        errors = client.insert_rows_json(table_id, [row])
        if errors:
            return jsonify({"error": errors}), 500

        return jsonify({"message": "Seguimiento agregado"}), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/seguimiento/<seg_id>", methods=["PATCH"])
def api_mover_seguimiento(seg_id):
    try:
        rol = (current_user_role() or "").strip().lower()
        if rol not in ["postventa","admin"]:
            return jsonify({"error":"No autorizado"}), 403

        data = request.get_json() or {}
        nuevo_estado = (data.get("estado") or "").strip().lower()
        if nuevo_estado not in {"contactado","en_proceso","cerrado"}:
            return jsonify({"error":"Estado inválido"}), 400

        # 1) Traer contexto de la tarjeta (correo, id_alumno) por su ID
        q_ctx = """
          SELECT CORREO, ID_ALUMNO
          FROM `fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO`
          WHERE ID = @id
          ORDER BY FECHA DESC
          LIMIT 1
        """
        job_ctx = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("id","STRING", seg_id)]
        )
        correo = None
        id_alumno = None
        for r in client.query(q_ctx, job_config=job_ctx).result():
            correo = (r["CORREO"] or "").strip().lower()
            id_alumno = r["ID_ALUMNO"]
        if not correo:
            return jsonify({"error":"No se encontró el seguimiento a mover"}), 404

        # 2) Insertar un nuevo evento con MISMO ID y nuevo estado
        table_id = "fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO"
        row = {
            "ID": seg_id,
            "ID_ALUMNO": id_alumno,
            "CORREO": correo,
            "FECHA": _now_iso_utc(),
            "AUTOR": ((session.get("user") or {}).get("correo") or "").lower(),
            "ROL_AUTOR": rol,
            "TIPO": "movimiento",
            "NOTA": f"Cambio de estado a {nuevo_estado}",
            "ESTADO": nuevo_estado,
        }
        errors = client.insert_rows_json(table_id, [row])
        if errors:
            return jsonify({"error": errors}), 500

        return jsonify({"message":"Estado actualizado"}), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/seguimientos")
def api_listar_seguimientos():
    if "user" not in session:
        return jsonify({"error": "No autorizado"}), 401

    correo = (request.args.get("correo") or "").strip().lower()
    if not correo:
        return jsonify({"error": "Falta correo"}), 400

    q = """
      SELECT
        ID, FECHA, AUTOR, ROL_AUTOR, TIPO, NOTA, ESTADO
      FROM `fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO`
      WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
      QUALIFY ROW_NUMBER() OVER (PARTITION BY ID ORDER BY FECHA DESC) = 1
      ORDER BY FECHA DESC
    """
    job = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("correo","STRING", correo)]
    )
    rows = client.query(q, job_config=job).result()

    out = []
    for r in rows:
        out.append({
            "ID": r["ID"],
            "FECHA": r["FECHA"].isoformat() if r["FECHA"] else None,
            "AUTOR": r["AUTOR"],
            "ROL_AUTOR": r["ROL_AUTOR"],
            "TIPO": r["TIPO"],
            "NOTA": r["NOTA"],
            "ESTADO": r["ESTADO"],
        })
    return jsonify(out)

# -------------------- Comunidad: Lista y Panel --------------------
@app.route("/comunidad")
@login_required(roles=["admin", "postventa", "comunidad"])
def comunidad_list():
    return render_template("comunidad.html")

@app.route("/api/comunidad")
@login_required(roles=["admin", "postventa", "comunidad"])
def api_comunidad():
    try:
        correo = (request.args.get("correo") or "").strip().lower()
        q = f"""
          SELECT *
          FROM `{COMMUNITY_VIEW}`
          WHERE 1=1
            {"AND LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))" if correo else ""}
          ORDER BY NOMBRE_ALUMNO
        """
        params = []
        if correo:
            params.append(bigquery.ScalarQueryParameter("correo", "STRING", correo))
        job = bigquery.QueryJobConfig(query_parameters=params)

        df = client.query(q, job_config=job).to_dataframe()

        # ✅ Formateo seguro para DataTables:
        # 1) Asegura dtypes "modernos"
        df = df.convert_dtypes()

        # 2) Redondea numéricos (Float64) donde aplique
        float_cols = [
            "MONTO_INVERTIDO_CURSOS","MONTO_INVERTIDO_GALA","MONTO_INVERTIDO_TOTAL",
            "CALIF_EXPECTATIVAS","CALIF_TEMAS","CALIF_CONTENIDO","CALIF_CLASE",
            "CALIF_CALC_0_10","NPS_FINAL","PROMEDIO_AVANCE"
        ]
        for c in float_cols:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce").astype("Float64").round(2)

        # 3) Enteros (permiten pd.NA)
        int_cols = ["TOTAL_CURSOS","TOTAL_ASISTENCIA_WEBINAR"]
        for c in int_cols:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")

        # 4) Solo columnas de texto se llenan con ''
        text_cols = [
            "NOMBRE_ALUMNO","CORREO","TELEFONO","FUENTE",
            "PROGRAMAS_CURSOS","GENERACION_PROGRAMAS","PROGRAMAS_THINKIFIC",
            "WEBINAR","WEBINARS","COMENTARIOS","GENERACION_GALA","PRODUCTO_GALA",
            "PONENTE_GALA","PONENCIA_GALA","BANDERA_GALA"
        ]
        for c in text_cols:
            if c in df.columns:
                df[c] = df[c].astype("string").fillna("")

        # 5) pd.NA/NaN -> None para JSON
        df = df.replace({pd.NA: None})
        df = df.where(pd.notnull(df), None)

        return jsonify(df.to_dict(orient="records")), 200
    except Exception as e:
        # Para evitar "Invalid JSON response" en DataTables
        app.logger.exception("Error en /api/comunidad: %s", e)
        return jsonify([]), 200

@app.route("/comunidad/<correo>")
@login_required(roles=["admin", "postventa", "comunidad", "invitado"])
def comunidad_panel(correo):
    correo = (correo or "").strip().lower()

    # 1) Trae 1 fila consolidada
    q = f"""
      SELECT *
      FROM `{COMMUNITY_VIEW}`
      WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
      LIMIT 1
    """
    job = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("correo","STRING",correo)]
    )
    row = None
    for r in client.query(q, job_config=job).result():
        row = dict(r)
        break

    if not row:
        return render_template("comunidad_panel.html", data=None, cursos=[], webinars=[], seguimientos=[]), 404

    # 2) (Opcional) Detalle de cursos Thinkific del alumno
    q_courses = """
      SELECT
        COURSE_NAME, PERCENTAGE_COMPLETED, STARTED_AT, UPDATED_AT, COMPLETED_AT
      FROM `fivetwofive-20.INSUMOS.DB_PROGRESO_AVANCE_EDUCATIVO_THINKIFIC`
      WHERE LOWER(TRIM(user_email)) = LOWER(TRIM(@correo))
      ORDER BY UPDATED_AT DESC
      LIMIT 50
    """
    courses = []
    for r in client.query(q_courses, job_config=job).result():
        courses.append({
            "COURSE_NAME": r["COURSE_NAME"],
            "PERCENTAGE_COMPLETED": r["PERCENTAGE_COMPLETED"],
            "STARTED_AT": r["STARTED_AT"],
            "UPDATED_AT": r["UPDATED_AT"],
            "COMPLETED_AT": r["COMPLETED_AT"],
        })

    # 3) (Opcional) Últimos webinars asistidos (detalle simple)
    q_webs = """
      SELECT webinar_id, webinar_topic, join_time, leave_time, duration, status
      FROM `fivetwofive-20.INSUMOS.DB_ZOOM_WEBINARS_ASISTENCIA`
      WHERE LOWER(TRIM(participant_email)) = LOWER(TRIM(@correo))
      ORDER BY join_time DESC
      LIMIT 50
    """
    webinars = []
    for r in client.query(q_webs, job_config=job).result():
        webinars.append({
            "webinar_id": r["webinar_id"],
            "webinar_topic": r["webinar_topic"],
            "join_time": r["join_time"],
            "leave_time": r["leave_time"],
            "duration": r["duration"],
            "status": r["status"],
        })

    # 4) Seguimientos (última versión por ID)
    q_seg = """
      SELECT ID, FECHA, AUTOR, ROL_AUTOR, TIPO, NOTA, ESTADO
      FROM `fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO`
      WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
      QUALIFY ROW_NUMBER() OVER (PARTITION BY ID ORDER BY FECHA DESC) = 1
      ORDER BY FECHA DESC
    """
    seguimientos = []
    for r in client.query(q_seg, job_config=job).result():
        seguimientos.append({
            "ID": r["ID"],
            "FECHA": r["FECHA"],
            "AUTOR": r["AUTOR"],
            "ROL_AUTOR": r["ROL_AUTOR"],
            "TIPO": r["TIPO"],
            "NOTA": r["NOTA"],
            "ESTADO": r["ESTADO"],
        })

    return render_template(
        "comunidad_panel.html",
        data=row,
        cursos=courses,
        webinars=webinars,
        seguimientos=seguimientos,
        rol_usuario=current_user_role()
    )
