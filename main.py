from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from authlib.integrations.flask_client import OAuth
from google.cloud import bigquery
import os
import pandas as pd
from pandas.api.types import is_numeric_dtype
import time
import json
from functools import wraps
from jinja2 import TemplateNotFound
# from flask_session import Session
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash
from firebase_admin import credentials, auth
import firebase_admin
from google.cloud import secretmanager
from firebase_admin import auth as firebase_auth
from datetime import datetime, timezone, timedelta
import uuid
import re
import urllib.parse
import traceback
from flask import Response

# =========================================================
# 1) Crear app y configurar sesión/secret_key (ANTES de usar app)
# =========================================================
app = Flask(__name__)


@app.errorhandler(Exception)
def _handle_any_exc(e):
    app.logger.exception("Unhandled exception on %s", request.path)
    if isinstance(e, HTTPException):
        # Respeta el código HTTP original para errores conocidos
        return e
    if request.args.get("debug") == "1":
        import traceback
        tb = traceback.format_exc()
        return Response(f"<h3>Excepción:</h3><pre>{tb}</pre>", status=500, mimetype="text/html")
    try:
        return render_template("error_500.html", msg=str(e)), 500
    except Exception:
        return Response("Error interno del servidor", status=500, mimetype="text/plain")


def load_secret(project_id: str, name: str, version: str = "latest") -> str:
    sm_client = secretmanager.SecretManagerServiceClient()
    resource = f"projects/{project_id}/secrets/{name}/versions/{version}"
    resp = sm_client.access_secret_version(request={"name": resource})
    return resp.payload.data.decode("utf-8")


project_id = os.getenv("GCP_PROJECT_ID", "fivetwofive-20")

# Secret key: primero ENV, si no, Secret Manager
app.secret_key = os.getenv("FLASK_SECRET_KEY") or load_secret(
    project_id, "FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY no está configurado")

# Sesión nativa de Flask (cookies firmadas)
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_NAME'] = 'mmi_sess'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# En Cloud Run producción (HTTPS) → True. En local http → False.
# cambia a True en producción HTTPS
app.config['SESSION_COOKIE_SECURE'] = False

app.debug = True
load_dotenv()

# =========================================================
# 2) Helpers, Firebase, BigQuery (manteniendo tus nombres)
# =========================================================

# --- Helpers de rol/sesión ---
ROLES_VALIDOS = {"admin", "postventa", "comunidad",
                 "adquisicion", "people", "invitado"}


def normalize_email(s: str) -> str:
    return (s or "").strip().lower()


def get_user_from_session():
    return session.get("user") or {}


def current_user_role():
    u = get_user_from_session()
    return (u.get("rol") or "").strip().lower()


def fetch_role_from_bq(email_norm: str) -> str | None:
    q = """
      SELECT ANY_VALUE(rol) rol
      FROM `fivetwofive-20.INSUMOS.DB_USUARIO`
      WHERE LOWER(TRIM(correo)) = @c
      LIMIT 1
    """
    cfg = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter(
            "c", "STRING", email_norm)]
    )
    rows = list(client.query(q, job_config=cfg).result())
    if not rows:
        return None
    rol = (rows[0]["rol"] or "").strip().lower()
    return rol if rol in ROLES_VALIDOS else "invitado"


def login_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_firebase_page"))  # GET del login
        return f(*args, **kwargs)
    return _wrap


def role_required(*roles):
    roles_norm = {r.strip().lower() for r in roles}

    def deco(f):
        @wraps(f)
        def _wrap(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login_firebase_page"))
            r = (session.get("user", {}).get("rol") or "").strip().lower()
            # admin siempre puede
            if r == "admin" or r in roles_norm:
                return f(*args, **kwargs)
            return render_template("no_autorizado.html"), 403
        return _wrap
    return deco


def get_firebase_credentials():
    sm_client = secretmanager.SecretManagerServiceClient()
    name = "projects/fivetwofive-20/secrets/firebase-key/versions/latest"
    response = sm_client.access_secret_version(request={"name": name})
    return response.payload.data


ESTADOS_PERMITIDOS = {"contactado", "en_proceso", "cerrado"}


def _now_iso_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


# --- Inicialización de Firebase (como ya la tenías) ---
if not firebase_admin._apps:
    cred = credentials.Certificate(json.loads(get_firebase_credentials()))
    firebase_admin.initialize_app(cred)

# BigQuery client (manteniendo tu nombre)
client = bigquery.Client()

# =========================================================
# 3) Constantes de vistas / filtros
# =========================================================
# ---- Vista de alumnos
BQ_VIEW = "fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL"
# ---- Vista de comunidad consolidada de alumnos
COMMUNITY_VIEW = "fivetwofive-20.COMUNIDAD.VW_COMUNIDAD_CONSOLIDADO_X_ALUMNO"
# ---- Vista de usuarios
DB_USUARIO = "fivetwofive-20.INSUMOS.DB_USUARIO"
# ---- Postventa: constantes de tablas ----
POSTVENTA_TABLA_BASE = "fivetwofive-20.POSTVENTA.DB_DIAGNOSTICO_POSTVENTA"

# ---- Cuestionario Diagnóstico (opciones visibles) ----
PREGUNTAS_DEF = {
    "R1":  {"texto": "¿Tienes actualmente alguna fuente de ingreso activa?",
            "opciones": [("3", "Sí, ingresos estables mensuales."),
                         ("2", "Sí, pero son variables o inestables."),
                         ("1", "No tengo ingresos actualmente.")]},
    "R2":  {"texto": "¿De cuanto son tus ingresos mensuales aproximadamente?",
            "opciones": [("3", "Más de $30,000 MXN."),
                         ("2", "Entre $10,000 y $30,000 MXN."),
                         ("1", "Menos de $10,000 MXN.")]},
    "R3":  {"texto": "¿Tienes personas que dependan de ti?",
            "opciones": [("3", "Sí, y compartimos ingresos/responsabilidades."),
                         ("2", "Mi familia cercana depende de mí."),
                         ("1", "Aparte de mi familia cercana más personas dependen de mí.")]},
    "R4":  {"texto": "¿Tu numero de libertad financiera es más, menos o igual de tus ingresos actuales ?",
            "opciones": [("3", "Mucho menos de lo que ingreso mensualmente"),
                         ("2", "Igual a lo que ingreso mensualmente"),
                         ("1", "Mucho más de lo que ingreso mensualmente")]},
    "R5":  {"texto": "¿Cuánto puedes invertir mensualmente sin afectar tus gastos básicos?",
            "opciones": [("3", "Más de $5,000 MXN."),
                         ("2", "Entre $1,000 y $5,000 MXN."),
                         ("1", "Menos de $1,000 MXN o nada.")]},
    "R6":  {"texto": "¿Tienes algún ahorro o capital disponible para invertir? ¿y cual sería el monto aproximado?",
            "opciones": [("3", "Más de $50,000 MXN."),
                         ("2", "Entre $10,000 y $50,000 MXN."),
                         ("1", "Menos de $10,000 MXN.")]},
    "R7":  {"texto": "¿Tienes acceso a financiamiento?",
            "opciones": [("3", "Sí, y lo ha usado estratégicamente."),
                         ("2", "Sí, pero aún no lo usa."),
                         ("1", "No tiene acceso a crédito o lo usa mal.")]},
    "R8":  {"texto": "¿Tienes alguna deuda activa actualmente?",
            "opciones": [("3", "No tengo deudas"),
                         ("2", "Algunas deudas pero manejables."),
                         ("1", "Muchas deudas o sin control.")]},
    "R9":  {"texto": "¿Qué tan dispuesto estás a seguir un plan de acción con la guía de mentores?",
            "opciones": [("3", "Totalmente comprometido y abierto a cambios."),
                         ("2", "Interesado pero con algunas dudas."),
                         ("1", "No está seguro o le cuesta seguir procesos.")]},
    "R10": {"texto": "Si hoy tuvieras una estrategia clara para invertir, ¿te comprometerías a ejecutarla?",
            "opciones": [("3", "Sí, inmediatamente."),
                         ("2", "Sí, pero necesita más seguridad."),
                         ("1", "No está seguro o le falta claridad.")]},
    "R11": {"texto": "En una escala del 1 al 10, ¿qué tan importante es para ti lograr la libertad financiera?",
            "opciones": [("3", "9-10: Es su máxima prioridad."),
                         ("2", "7-8: Le interesa, pero aún tiene otras prioridades."),
                         ("1", "6 o menos: No está realmente comprometido.")]}
}

VENTA_MAP = {0: "Sin venta", 1: "Venta"}  # ajusta a tu semántica real


def venta_text(v):
    try:
        return VENTA_MAP.get(int(v), str(v))
    except Exception:
        return str(v)


def viabilidad_label(calif):
    try:
        c = int(calif)
        if c < 20:
            return ("NO VIABLE", "danger")
        elif 20 <= c <= 25:
            return ("REQUIERE AJUSTE", "warning")
        else:
            return ("VIABLE", "success")
    except Exception:
        return ("", "secondary")


def score_to_label(key, val):
    opts = (PREGUNTAS_DEF.get(key) or {}).get("opciones", [])
    for code, label in opts:
        if str(code) == str(val):
            return label
    return ""


app.jinja_env.globals.update(
    score_to_label=score_to_label,
    viabilidad_label=viabilidad_label,
    venta_text=venta_text
)


# --- SECCION DE HELPERS

# Filtro para formatear moneda MXN en Jinja (SIN CAMBIOS)
def mxn(value):
    try:
        if value is None or value == "":
            return ""
        return f"${float(value):,.2f}"
    except Exception:
        return str(value)

# Helper para normalizar el telefono "MX = 52"


def to_whatsapp_e164(phone_raw: str, default_cc: str = "52") -> str:
    """Convierte un teléfono a formato para wa.me.
    - Deja solo dígitos
    - Si son 10 dígitos => antepone CC (por defecto MX 52)
    - Si ya empieza con 52 y tiene 12–13 dígitos => lo deja
    - Si venía con '00' => lo quita
    - Si nada cuadra, regresa los dígitos limpios (mejor eso que nada)
    """
    if not phone_raw:
        return ""
    digits = re.sub(r"\D", "", str(phone_raw))
    if not digits:
        return ""
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith(default_cc) and 11 <= len(digits) <= 13:
        return digits
    if len(digits) == 10:
        return default_cc + digits
    return digits

# ---- Normalizadores sencillos ----


def _normalize_phone(raw: str) -> str:
    if not raw:
        return ""
    digits = re.sub(r"\D", "", str(raw))
    return digits[-10:] if len(digits) >= 10 else digits


def _normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def _format_generacion(raw: str) -> str:
    if not raw:
        return ""
    m = re.search(r"(\d+)", str(raw))
    if not m:
        return ""
    n = int(m.group(1))
    if n < 1:
        return ""
    return f"G-{n:02d}"

# ---- ID incremental estilo E00001 (simple; suficiente para baja concurrencia) ----


def _postventa_next_id() -> str:
    q = f"""
      SELECT IFNULL(MAX(num), 0) AS max_id
      FROM (
        SELECT SAFE_CAST(REGEXP_EXTRACT(ID, r'\\d+$') AS INT64) AS num
        FROM `{POSTVENTA_TABLA_BASE}`
      )
    """
    rows = list(client.query(q))
    nxt = (rows[0]["max_id"] if rows else 0) + 1
    return f"E{nxt:05d}"



app.jinja_env.filters["mxn"] = mxn
app.jinja_env.globals.update(to_whatsapp_e164=to_whatsapp_e164)
app.jinja_env.globals.update(PREGUNTAS_DEF=PREGUNTAS_DEF)

# --- KPIs Postventa ---
def _postventa_kpis():
    q = """
      SELECT
        COUNT(1) AS total,
        COUNTIF(ESTATUS_VENTA = 1) AS ventas,
        COUNTIF(ESTATUS_VIABLE = 'VIABLE') AS viables,
        COUNTIF(ESTATUS_VIABLE = 'REQUIERE AJUSTE') AS requiere_ajuste,
        COUNTIF(ESTATUS_VIABLE = 'NO VIABLE') AS no_viable
      FROM `fivetwofive-20.POSTVENTA.DM_ENCUESTA_DIAGNOSTICO_POSTVENTA`
    """
    try:
        row = next(iter(client.query(q).result()))
        return {k: int(row[k] or 0) for k in
                ("total","ventas","viables","requiere_ajuste","no_viable")}
    except Exception:
        return {"total": 0, "ventas": 0, "viables": 0,
                "requiere_ajuste": 0, "no_viable": 0}


def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

def _postventa_insights_data(date_from=None, date_to=None, generacion=None):
    """
    Devuelve todas las piezas necesarias para el dashboard de insights.
    Filtros: date_from/date_to (YYYY-MM-DD) y generacion (ej. 'G-01').
    """
    table = "fivetwofive-20.POSTVENTA.DM_ENCUESTA_DIAGNOSTICO_POSTVENTA"

    # WHERE dinámico
    wh = ["1=1"]
    params = []
    if date_from:
        wh.append("DATE(FECHA_ENCUESTA) >= @from")
        params.append(bigquery.ScalarQueryParameter("from", "DATE", date_from))
    if date_to:
        wh.append("DATE(FECHA_ENCUESTA) <= @to")
        params.append(bigquery.ScalarQueryParameter("to", "DATE", date_to))
    if generacion:
        wh.append("GENERACION = @gen")
        params.append(bigquery.ScalarQueryParameter("gen", "STRING", generacion))
    where_sql = "WHERE " + " AND ".join(wh)

    # 1) KPIs
    q_kpis = f"""
    SELECT
      COUNT(*)                         AS total,
      COUNTIF(ESTATUS_VENTA = 1)       AS ventas,
      COUNTIF(ESTATUS_VIABLE = 'VIABLE') AS viables,
      COUNTIF(ESTATUS_VIABLE = 'REQUIERE AJUSTE') AS requiere_ajuste,
      COUNTIF(ESTATUS_VIABLE = 'NO VIABLE') AS no_viable,
      ROUND(AVG(CALIFICACION),2)       AS avg_score,
      APPROX_QUANTILES(CALIFICACION, 2)[OFFSET(1)] AS mediana
    FROM `{table}`
    {where_sql}
    """
    row = next(iter(client.query(q_kpis, job_config=bigquery.QueryJobConfig(query_parameters=params)).result()), None)
    kpis = {
        "total": int(row["total"]) if row and row["total"] is not None else 0,
        "ventas": int(row["ventas"]) if row and row["ventas"] is not None else 0,
        "viables": int(row["viables"]) if row and row["viables"] is not None else 0,
        "requiere_ajuste": int(row["requiere_ajuste"]) if row and row["requiere_ajuste"] is not None else 0,
        "no_viable": int(row["no_viable"]) if row and row["no_viable"] is not None else 0,
        "avg_score": float(row["avg_score"]) if row and row["avg_score"] is not None else None,
        "mediana": float(row["mediana"]) if row and row["mediana"] is not None else None,
    }
    kpis["tasa_conversion"] = round((kpis["ventas"] / kpis["total"])*100, 1) if kpis["total"] else 0.0
    kpis["pct_viable"] = round((kpis["viables"] / kpis["total"])*100, 1) if kpis["total"] else 0.0

    # 2) Serie temporal (por día)
    q_series = f"""
    SELECT DATE(FECHA_ENCUESTA) AS d, COUNT(*) AS n
    FROM `{table}`
    {where_sql}
    GROUP BY d
    ORDER BY d
    """
    by_date_labels, by_date_counts = [], []
    for r in client.query(q_series, job_config=bigquery.QueryJobConfig(query_parameters=params)).result():
        by_date_labels.append(r["d"].isoformat())
        by_date_counts.append(int(r["n"]))

    # 3) Mezcla por viabilidad
    q_viab = f"""
    SELECT ESTATUS_VIABLE AS v, COUNT(*) AS n
    FROM `{table}`
    {where_sql}
    GROUP BY v
    """
    viability_labels, viability_counts = [], []
    for r in client.query(q_viab, job_config=bigquery.QueryJobConfig(query_parameters=params)).result():
        viability_labels.append(r["v"] or "—")
        viability_counts.append(int(r["n"]))

    # 4) Promedio por pregunta R1..R11
    # Unpivot sencillo con UNION ALL
    q_qs = f"""
    WITH base AS (
      SELECT R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11
      FROM `{table}`
      {where_sql}
    )
    SELECT k, ROUND(AVG(v),2) AS avg_v
    FROM (
      SELECT 'R1'  AS k, R1  AS v FROM base UNION ALL
      SELECT 'R2', R2 FROM base UNION ALL
      SELECT 'R3', R3 FROM base UNION ALL
      SELECT 'R4', R4 FROM base UNION ALL
      SELECT 'R5', R5 FROM base UNION ALL
      SELECT 'R6', R6 FROM base UNION ALL
      SELECT 'R7', R7 FROM base UNION ALL
      SELECT 'R8', R8 FROM base UNION ALL
      SELECT 'R9', R9 FROM base UNION ALL
      SELECT 'R10', R10 FROM base UNION ALL
      SELECT 'R11', R11 FROM base
    )
    GROUP BY k
    ORDER BY CAST(SUBSTR(k,2) AS INT64)
    """
    questions_labels, questions_avg = [], []
    for r in client.query(q_qs, job_config=bigquery.QueryJobConfig(query_parameters=params)).result():
        questions_labels.append(r["k"])
        questions_avg.append(float(r["avg_v"] or 0))

    # 5) Conversión por viabilidad
    q_conv = f"""
    SELECT ESTATUS_VIABLE AS v,
           SAFE_DIVIDE(COUNTIF(ESTATUS_VENTA=1), COUNT(*)) AS conv
    FROM `{table}`
    {where_sql}
    GROUP BY v
    ORDER BY v
    """
    conv_labels, conv_rates = [], []
    for r in client.query(q_conv, job_config=bigquery.QueryJobConfig(query_parameters=params)).result():
        conv_labels.append(r["v"] or "—")
        conv_rates.append(round(float(r["conv"] or 0)*100, 1))

    # 6) Top generaciones
    q_gens = f"""
    SELECT GENERACION AS g,
           COUNT(*) AS n,
           SAFE_DIVIDE(COUNTIF(ESTATUS_VENTA=1), COUNT(*)) AS conv
    FROM `{table}`
    {where_sql}
    GROUP BY g
    ORDER BY n DESC
    LIMIT 10
    """
    gen_rows = []
    for r in client.query(q_gens, job_config=bigquery.QueryJobConfig(query_parameters=params)).result():
        gen_rows.append({
            "g": r["g"],
            "n": int(r["n"]),
            "conv": round(float(r["conv"] or 0)*100, 1)
        })

    return {
        "kpis": kpis,
        "by_date_labels": by_date_labels, "by_date_counts": by_date_counts,
        "viability_labels": viability_labels, "viability_counts": viability_counts,
        "questions_labels": questions_labels, "questions_avg": questions_avg,
        "conv_labels": conv_labels, "conv_rates": conv_rates,
        "gen_rows": gen_rows,
    }

# === BACK URL ROBUSTO (ATRÁS) ===
def _is_safe_internal_url(target: str) -> bool:
    """Permite solo URLs internas del mismo host (previene saltos externos)."""
    if not target:
        return False
    try:
        host_url = urllib.parse.urlparse(request.host_url)
        redirect_url = urllib.parse.urlparse(urllib.parse.urljoin(request.host_url, target))
        return (redirect_url.scheme in ("http", "https") and host_url.netloc == redirect_url.netloc)
    except Exception:
        return False

def _route_por_rol() -> str:
    """Home por rol. Ajusta endpoints si cambian."""
    rol = (current_user_role() or "").lower()
    mapa = {
        "admin": "alumnos_page",                 # tu dashboard redirige a alumnos_page
        "postventa": "postventa_diagnostico_list",
        "comunidad": "comunidad_list",
        "adquisicion": "alumnos_page",           # si tienes otro home de Adquisición, cámbialo aquí
        "people": "alumnos_page",
        "invitado": "alumnos_page",
        "": "alumnos_page",
    }
    endpoint = mapa.get(rol, "alumnos_page")
    try:
        return url_for(endpoint)
    except Exception:
        return url_for("alumnos_page")

def back_url(default: str | None = None) -> str:
    """
    Resuelve una URL de regreso robusta:
      1) ?next= (o form 'next')
      2) request.referrer (interno)
      3) ruta por rol
      4) alumnos_page
    """
    # 1) next
    next_param = request.args.get("next") or request.form.get("next")
    if next_param and _is_safe_internal_url(next_param):
        return next_param

    # 2) referrer
    ref = request.referrer
    if ref and _is_safe_internal_url(ref):
        return ref

    # 3) default (si lo pasan) o por rol
    if default and _is_safe_internal_url(default):
        return default

    # 4) fallback final
    try:
        return _route_por_rol()
    except Exception:
        return url_for("alumnos_page")


# =========================================================
# 4) Rutas
# =========================================================

# Exponer a Jinja como función global
@app.context_processor
def _inject_back_url():
    return {"back_url": back_url}


@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("alumnos_page"))
    return redirect(url_for("login_firebase_page"))


@app.route("/__health")
def __health():
    return "ok", 200


@app.route("/dashboard")
@login_required
def dashboard():
    return redirect(url_for("alumnos_page"))

# --- Comunidad (ya trabajando)


@app.route("/comunidad/insights")
@role_required("comunidad")
def comunidad_insights():
    return render_template("comunidad/insights.html")

# --- Login Firebase: GET (pantalla)

@app.route("/login_firebase", methods=["GET"])
def login_firebase_page():
    try:
        return render_template("login_firebase.html")
    except TemplateNotFound:
        # Fallback minimal para confirmar que la ruta funciona
        return """
        <html><body style="font-family: system-ui">
          <h3>Login Firebase</h3>
          <p>No se encontró <code>templates/login_firebase.html</code> en la imagen.</p>
          <p>Verifica el COPY en Dockerfile: <code>COPY templates/ templates/</code></p>
        </body></html>
        """, 200


# --- Login Firebase: POST (verifica token, guarda sesión)


@app.route("/login_firebase", methods=["POST"])
def login_firebase():
    try:
        data = request.get_json(force=True)
        id_token = data.get("idToken")
        decoded = firebase_auth.verify_id_token(id_token)

        email = normalize_email(decoded["email"])
        name = decoded.get("name", email.split("@")[0])
        uid = decoded.get("uid", "")

        # 1) Rol desde BQ (normalizado)
        role = fetch_role_from_bq(email)

        # 2) Si no existe en BQ, lo creamos como invitado
        if role is None:
            table_id = "fivetwofive-20.INSUMOS.DB_USUARIO"
            rows_to_insert = [{
                "correo": email,
                "nombre": name,
                "rol": "invitado",
                "firebase_uid": uid
            }]
            errors = client.insert_rows_json(table_id, rows_to_insert)
            if errors:
                print(f"[WARN] Error insertando usuario nuevo: {errors}")
            role = "invitado"

        # 3) Guardar en sesión
        session.clear()
        session["user"] = {"correo": email,
                           "nombre": name, "rol": role, "uid": uid}
        session.permanent = False  # cookie de sesión: expira al cerrar navegador

        return jsonify({"message": "Login exitoso", "role": role}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route('/logout')
def logout():
    session.pop('user', None)  # Elimina al usuario de la sesión
    return redirect(url_for('login_firebase_page'))

# -------------------- Alumnos y catálogos --------------------


@app.route('/alumnos')
def alumnos_page():
    if 'user' not in session:
        # Redirige si no hay sesión activa
        return redirect(url_for('login_firebase_page'))
    return render_template("alumnos.html")


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
            PRECIO_GENERACION,
            GASTO,
            INGRESO
        FROM `fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL`
        WHERE 1=1
    """
    params = []
    if generacion:
        query += " AND GENERACION_PROGRAMA = @generacion"
        params.append(bigquery.ScalarQueryParameter(
            "generacion", "STRING", generacion))
    if correo:
        query += " AND LOWER(CORREO) = @correo"
        params.append(bigquery.ScalarQueryParameter(
            "correo", "STRING", correo.lower()))

    job_config = bigquery.QueryJobConfig(query_parameters=params)
    df = client.query(query, job_config=job_config).to_dataframe()
    df = df.convert_dtypes()

    # Asegurar numérico para MXN
    for c in ["PRECIO_GENERACION", "GASTO", "INGRESO"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").astype("Float64")

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
        FROM `fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL`
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
        return redirect(url_for('login_firebase_page'))
    return render_template("cat_programas.html")


@app.route("/catalogo/generaciones")
def catalogo_generaciones():
    if 'user' not in session:
        return redirect(url_for('login_firebase_page'))
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
        FROM `fivetwofive-20.INSUMOS.CAT_PROGRAMA`
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
        FROM `fivetwofive-20.INSUMOS.CAT_GENERACION_PROGRAMA`
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

# -------------------- Crear nuevo alumno (solo admin) --------------------


@app.route("/alumnos/nuevo", methods=["GET", "POST"])
@role_required("admin")
def nuevo_alumno():
    if request.method == "POST":
        nombre = request.form.get("nombre")
        correo = request.form.get("correo")
        telefono = request.form.get("telefono")
        programa = request.form.get("programa")
        generacion = request.form.get("generacion")
        print("Alumno recibido:", nombre, correo,
              telefono, programa, generacion)
        return redirect(url_for("alumnos_page"))
    return render_template("nuevo_alumno.html")


# -------------------- Panel de alumno --------------------
@app.route('/alumno/<correo>', methods=['GET'])
def get_alumno_info(correo):
    try:
        rol = current_user_role()  # ← rol del usuario en sesión

        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter(
                "correo", "STRING", correo)]
        )

        # ---- 1) Info del alumno (se muestra a todos) ----
        query_alumno = """
            SELECT
              ID_ALUMNO,
              CORREO,
              STRING_AGG(DISTINCT PROGRAMA, ', ') AS PROGRAMA,
              STRING_AGG(DISTINCT GENERACION_PROGRAMA, ', ') AS GENERACION_PROGRAMA,
              MAX(NOMBRE_ALUMNO) AS NOMBRE_ALUMNO,
              MAX(TELEFONO) AS TELEFONO,
              MIN(FECHA_INSCRIPCION) AS FECHA_INSCRIPCION,
              MAX(GASTO) AS GASTO,
              MAX(INGRESO) AS INGRESO
            FROM `fivetwofive-20.INSUMOS.DV_VISTA_ALUMNOS_GENERAL`
            WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
            GROUP BY ID_ALUMNO, CORREO
        """
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
                'GENERACION_PROGRAMA': row['GENERACION_PROGRAMA'],
                'GASTO': row['GASTO'],
                'INGRESO': row['INGRESO']
            }
            break

        if not alumno_info:
            return render_template('panel_alumnos.html',
                                   alumno_info=None,
                                   cursos_info=[],
                                   seguimientos=[],
                                   comunidad=None,
                                   webinars=[],
                                   webinar_topics=[],
                                   chart_labels=[],
                                   chart_values=[],
                                   rol_usuario=rol), 404

        # -------------------------------------------------
        # 2) CURSOS & GRÁFICA  → SOLO admin/comunidad
        # -------------------------------------------------
        cursos_info, chart_labels, chart_values = [], [], []
        if rol in ("admin", "comunidad"):
            query_cursos = """
                WITH base AS (
                    SELECT
                        COURSE_NAME,
                        SAFE_CAST(REGEXP_REPLACE(CAST(PERCENTAGE_COMPLETED AS STRING), r'[%\\s]', '') AS FLOAT64) AS pct,
                        STARTED_AT,
                        UPDATED_AT,
                        COMPLETED_AT
                    FROM `fivetwofive-20.INSUMOS.DB_PROGRESO_AVANCE_EDUCATIVO_THINKIFIC`
                    WHERE LOWER(TRIM(user_email)) = LOWER(TRIM(@correo))
                )
                SELECT
                    COURSE_NAME,
                    CASE
                        WHEN pct IS NULL THEN NULL
                        WHEN pct <= 1.0 THEN ROUND(pct * 100, 2)
                        ELSE ROUND(pct, 2)
                    END AS PERCENTAGE_COMPLETED,
                    STARTED_AT,
                    UPDATED_AT,
                    COMPLETED_AT
                FROM base
                ORDER BY UPDATED_AT DESC
            """
            result_cursos = client.query(
                query_cursos, job_config=job_config).result()

            for row in result_cursos:
                cursos_info.append({
                    'COURSE_NAME': row['COURSE_NAME'],
                    'PERCENTAGE_COMPLETED': row['PERCENTAGE_COMPLETED'],
                    'STARTED_AT': row['STARTED_AT'],
                    'UPDATED_AT': row['UPDATED_AT'],
                    'COMPLETED_AT': row['COMPLETED_AT']
                })

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
                    chart_values.append(
                        float(r.get('PERCENTAGE_COMPLETED') or 0))
            except Exception as e:
                print("WARN chart data:", e, flush=True)

        # -------------------------------------------------
        # 2.7) Webinars (fallback simple) → SOLO admin/comunidad
        # -------------------------------------------------
        webinars = []
        if rol in ("admin", "comunidad"):
            q_webs = """
                SELECT DISTINCT webinar_topic
                FROM `fivetwofive-20.INSUMOS.DB_ZOOM_WEBINARS_ASISTENCIA`
                WHERE LOWER(TRIM(participant_email)) = LOWER(TRIM(@correo))
                ORDER BY webinar_topic
                LIMIT 100
            """
            for r in client.query(q_webs, job_config=job_config).result():
                webinars.append({"webinar_topic": r["webinar_topic"]})

        # -------------------------------------------------------
        # ---- 2.9) KPIs de Postventa (solo admin/postventa) ----
        # -------------------------------------------------------
        postventa = None
        if rol in ("admin", "postventa"):
            try:
                q_post = """
                SELECT
                    ID_ALUMNO,
                    CORREO,
                    NOMBRE,
                    TELEFONO,
                    CORREO_OFICIAL,
                    FORMA_DE_PAGO_ULT,
                    FECHA_COMPRA_ULTIMA,
                    VENTA_TOTAL_SUM,
                    TOTAL_PAGADO_SUM,
                    POR_COBRAR_SUM,
                    NUM_COMPRAS,
                    GENERACION_INVINF_ULT,
                    GENERACION_MP_ULT,
                    OBS_ULT,
                    ESTATUS_GLOBAL
                FROM `fivetwofive-20.POSTVENTA.VW_POSTVENTA_X_ALUMNO`
                WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
                LIMIT 1
                """
                for r in client.query(q_post, job_config=job_config).result():
                    postventa = dict(r)
                    break

            except Exception as e:
                # Si la vista no existe o está en otra región, no rompemos el panel
                print("[WARN] Postventa no disponible:", e)
                postventa = None

        # -------------------------------------------------
        # 3) Seguimientos → SOLO admin/postventa
        # -------------------------------------------------
        seguimientos = []
        if rol in ("admin", "postventa"):
            query_seg = """
                SELECT
                  ID, FECHA, AUTOR, ROL_AUTOR, TIPO, NOTA, ESTADO
                FROM `fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO`
                WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
                ORDER BY FECHA DESC
            """
            result_seg = client.query(
                query_seg, job_config=job_config).result()
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

        # -----------------------------------------------------------------
        # --- URL de WhatsApp para el botón (solo para postventa/admin) ---
        # -----------------------------------------------------------------

        whatsapp_url = None
        phone_raw = None

        # Preferimos un teléfono “oficial” si existe en postventa; si no, el del alumno
        if isinstance(postventa, dict):
            phone_raw = postventa.get(
                "TELEFONO_OFICIAL") or postventa.get("TELEFONO")

        if not phone_raw and isinstance(alumno_info, dict):
            phone_raw = alumno_info.get("TELEFONO")

        e164 = to_whatsapp_e164(phone_raw or "")
        if e164:
            alumno_nombre = (alumno_info.get("NOMBRE_ALUMNO")
                             if isinstance(alumno_info, dict) else "") or ""
            msg = f"Hola {alumno_nombre}, te saluda el equipo de Mi Mentor de Inversión. ¿Tienes 2 minutos?"
            whatsapp_url = f"https://wa.me/{e164}?text=" + \
                urllib.parse.quote(msg)

        # -------------------------------------------------
        # 4) Comunidad → SOLO admin/comunidad
        # -------------------------------------------------
        comunidad = None
        webinar_topics = []
        if rol in ("admin", "comunidad"):
            q_comm = """
                SELECT
                  MONTO_INVERTIDO_CURSOS,
                  MONTO_INVERTIDO_GALA,
                  MONTO_INVERTIDO_TOTAL,
                  NPS_FINAL,
                  CALIF_CALC_0_10,
                  CALIF_EXPECTATIVAS,
                  CALIF_TEMAS,
                  CALIF_CONTENIDO,
                  CALIF_CLASE,
                  TOTAL_CURSOS,
                  PROMEDIO_AVANCE,
                  PROGRAMAS_CURSOS,
                  GENERACION_PROGRAMAS,
                  COMENTARIOS,
                  TOTAL_ASISTENCIA_WEBINAR,
                  WEBINARS_ASISTIDOS
                FROM `fivetwofive-20.COMUNIDAD.VW_COMUNIDAD_CONSOLIDADO_X_ALUMNO`
                WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
                LIMIT 1
            """
            for r in client.query(q_comm, job_config=job_config).result():
                comunidad = dict(r)
                break

            if comunidad:
                raw = None
                for key in ("WEBINARS_ASISTIDOS", "WEBINAR", "WEBINARS", "WEBINAR_TOPIC"):
                    if key in comunidad and comunidad[key]:
                        raw = str(comunidad[key])
                        break
                if raw:
                    parts = re.split(r"\s*\|\s*|\s*,\s*", raw)
                    webinar_topics = [p.strip()
                                      for p in parts if p and p.strip()]

            # Fallback de topics solo si rol permite comunidad
            if not webinar_topics and webinars:
                webinar_topics = sorted({
                    (w.get("webinar_topic") or "").strip()
                    for w in webinars
                    if (w.get("webinar_topic") or "").strip()
                })

        return render_template(
            'panel_alumnos.html',
            alumno_info=alumno_info,
            cursos_info=cursos_info,          # vacío para postventa
            seguimientos=seguimientos,        # vacío para comunidad
            comunidad=comunidad,              # None para postventa
            webinars=webinars,                # vacío para postventa
            webinar_topics=webinar_topics,    # vacío para postventa
            chart_labels=chart_labels,        # vacío para postventa
            chart_values=chart_values,        # vacío para postventa
            postventa=postventa,              # vacío para comunidad
            whatsapp_url=whatsapp_url,       # vacío para postventa
            rol_usuario=rol
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# -------------------- Seguimientos (crear / mover / listar) --------------------


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
                rol = fetch_role_from_bq(correo_sesion)
                if rol:
                    user["rol"] = rol
                    session["user"] = user

        # 3) autoriza
        if rol not in ["postventa", "admin"]:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}
        correo = (data.get("correo") or "").strip().lower()
        nota = (data.get("nota") or "").strip()
        tipo = (data.get("tipo") or "").strip().lower() or "otro"
        estado = (data.get("estado") or "contactado").strip().lower()

        ESTADOS_PERMITIDOS = {"contactado", "en_proceso", "cerrado"}
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
                query_parameters=[bigquery.ScalarQueryParameter(
                    "correo", "STRING", correo)]
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
        if rol not in ["postventa", "admin"]:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}
        nuevo_estado = (data.get("estado") or "").strip().lower()
        if nuevo_estado not in {"contactado", "en_proceso", "cerrado"}:
            return jsonify({"error": "Estado inválido"}), 400

        # 1) Traer contexto de la tarjeta (correo, id_alumno) por su ID
        q_ctx = """
          SELECT CORREO, ID_ALUMNO
          FROM `fivetwofive-20.POSTVENTA.DB_SEGUIMIENTO_ALUMNO`
          WHERE ID = @id
          ORDER BY FECHA DESC
          LIMIT 1
        """
        job_ctx = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("id", "STRING", seg_id)]
        )
        correo = None
        id_alumno = None
        for r in client.query(q_ctx, job_config=job_ctx).result():
            correo = (r["CORREO"] or "").strip().lower()
            id_alumno = r["ID_ALUMNO"]
        if not correo:
            return jsonify({"error": "No se encontró el seguimiento a mover"}), 404

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

        return jsonify({"message": "Estado actualizado"}), 200

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
        query_parameters=[bigquery.ScalarQueryParameter(
            "correo", "STRING", correo)]
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

# -------------------- Postventa: Diagnóstico (form + list) --------------------

@app.route("/postventa/diagnostico", methods=["GET", "POST"])
@role_required("postventa", "admin")
def postventa_diagnostico():
    KEYS = list(PREGUNTAS_DEF.keys())

    if request.method == "POST":
        # Lee crudo (para mensajes) y normaliza (para guardar)
        nombre = (request.form.get("nombre") or "").strip()
        telefono_raw = request.form.get("telefono") or ""
        telefono = _normalize_phone(telefono_raw)
        correo_raw = (request.form.get("correo") or "").strip()
        correo_norm = _normalize_email(correo_raw.replace(",", "."))  # corrige ,com → .com
        generacion = _format_generacion(request.form.get("generacion"))
        estatus_venta_raw = request.form.get("estatus_venta") or "0"

        # Validaciones con mensajes útiles
        errors = []
        if not nombre:
            errors.append("Ingresa el nombre.")
        if not telefono or not re.fullmatch(r"\d{10}", telefono):
            errors.append("El teléfono debe tener exactamente 10 dígitos.")
        if not correo_raw:
            errors.append("Ingresa el correo.")
        else:
            if "," in correo_raw:
                errors.append("El correo contiene coma ',' — cámbiala por punto '.'.")
            # Regex sencilla de e-mail
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", correo_norm):
                errors.append("El correo no parece válido (ejemplo: usuario@dominio.com).")
        if not generacion:
            errors.append("Indica la generación en formato G-01, G-02, ...")

        # Preguntas R1..R11
        vals = {}
        faltantes = []
        invalidas = []
        for k in KEYS:
            v = (request.form.get(k) or "").strip()
            if not v:
                faltantes.append(k)
            elif v not in {"1", "2", "3"}:
                invalidas.append(k)
            else:
                vals[k] = int(v)

        if faltantes:
            errors.append(f"Faltan respuestas en: {', '.join(faltantes)} (elige 1, 2 o 3).")
        if invalidas:
            errors.append(f"Valores inválidos en: {', '.join(invalidas)} (debe ser 1, 2 o 3).")

        # Si hay errores, re-render con feedback y valores previos
        if errors:
            return render_template(
                "postventa_diagnostico_form.html",
                preguntas=PREGUNTAS_DEF,  # ← siempre el mismo shape que espera el template
                errors=errors,
                form=request.form
            ), 400

        # Parseo seguro de estatus_venta
        try:
            estatus_venta = int(estatus_venta_raw)
        except ValueError:
            estatus_venta = 0

        nuevo_id = _postventa_next_id()
        calificacion = sum(vals.values())
        now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        row = {
            "ID": nuevo_id,
            "NOMBRE": nombre,
            "TELEFONO": telefono,
            "CORREO": correo_norm,
            "GENERACION": generacion,
            "FECHA": now_iso,
            **{k: vals[k] for k in KEYS},  # R1..R11
            "CALIFICACION": calificacion,
            "ESTATUS_VENTA": estatus_venta,
        }

        errors_bq = client.insert_rows_json(POSTVENTA_TABLA_BASE, [row])
        if errors_bq:
            return render_template(
                "postventa_diagnostico_form.html",
                preguntas=PREGUNTAS_DEF,
                errors=[f"Error al guardar en BigQuery: {errors_bq}"],
                form=request.form
            ), 500

        return redirect(url_for("postventa_diagnostico_list"))

    # GET
    return render_template("postventa_diagnostico_form.html",
                           preguntas=PREGUNTAS_DEF,
                           errors=[],
                           form=None)


@app.route("/postventa/diagnostico/list")
@role_required("postventa", "admin")
def postventa_diagnostico_list():
    q = """
      SELECT
        ID_ENCUESTA AS ID, FECHA_ENCUESTA AS FECHA, NOMBRE, GENERACION, CALIFICACION, ESTATUS_VENTA, TELEFONO, CORREO,
        R1, R1_DESC, R2, R2_DESC, R3, R3_DESC, R4, R4_DESC, R5, R5_DESC,
        R6, R6_DESC, R7, R7_DESC, R8, R8_DESC, R9, R9_DESC, R10, R10_DESC, R11, R11_DESC,
        ESTATUS_VIABLE
      FROM `fivetwofive-20.POSTVENTA.DM_ENCUESTA_DIAGNOSTICO_POSTVENTA`
      ORDER BY FECHA_ENCUESTA DESC
      LIMIT 500
    """
    rows = list(client.query(q))
    data = [dict(r) for r in rows]

     # Opcional: dejar FECHA amigable
    for d in data:
        f = d.get("FECHA")
        if isinstance(f, datetime):
            d["FECHA"] = f.strftime("%Y-%m-%d %H:%M")

    return render_template("postventa_diagnostico_list.html",
                           data=data, preguntas=PREGUNTAS_DEF)

@app.route("/postventa/insights")
@role_required("postventa", "admin")
def postventa_insights():
    f = request.args.get("from")
    t = request.args.get("to")
    g = (request.args.get("gen") or "").strip() or None

    date_from = _parse_date(f)
    date_to   = _parse_date(t)

    try:
        data = _postventa_insights_data(date_from=date_from, date_to=date_to, generacion=g)
    except Exception:
        app.logger.exception("Error en _postventa_insights_data")
        data = {
            "kpis": {"total":0,"ventas":0,"viables":0,"requiere_ajuste":0,"no_viable":0,
                     "tasa_conversion":0.0,"pct_viable":0.0,"avg_score":None,"mediana":None},
            "by_date_labels": [], "by_date_counts": [],
            "viability_labels": [], "viability_counts": [],
            "questions_labels": [], "questions_avg": [],
            "conv_labels": [], "conv_rates": [],
            "gen_rows": [],
        }

    try:
        return render_template(
            "postventa_insights.html",   # ← ANTES decía "postventa/insights.html"
            kpis=data["kpis"],
            by_date_labels=data["by_date_labels"], by_date_counts=data["by_date_counts"],
            viability_labels=data["viability_labels"], viability_counts=data["viability_counts"],
            questions_labels=data["questions_labels"], questions_avg=data["questions_avg"],
            conv_labels=data["conv_labels"], conv_rates=data["conv_rates"],
            gen_rows=data["gen_rows"],
            f_from=f or "", f_to=t or "", f_gen=g or ""
        )
    except TemplateNotFound:
        return Response(
            "Falta la plantilla templates/postventa_insights.html en la imagen (o nombre distinto).",
            status=500, mimetype="text/plain"
        )

# -------------------- Comunidad: Lista y Panel --------------------

@app.route("/comunidad")
@role_required("admin", "comunidad")
def comunidad_list():
    return render_template("comunidad.html")


@app.route("/api/comunidad")
@role_required("admin", "comunidad")
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
            params.append(bigquery.ScalarQueryParameter(
                "correo", "STRING", correo))
        job = bigquery.QueryJobConfig(query_parameters=params)

        df = client.query(q, job_config=job).to_dataframe()

        # Formateo seguro para DataTables
        df = df.convert_dtypes()

        float_cols = [
            "MONTO_INVERTIDO_CURSOS", "MONTO_INVERTIDO_GALA", "MONTO_INVERTIDO_TOTAL",
            "CALIF_EXPECTATIVAS", "CALIF_TEMAS", "CALIF_CONTENIDO", "CALIF_CLASE",
            "CALIF_CALC_0_10", "NPS_FINAL", "PROMEDIO_AVANCE"
        ]
        for c in float_cols:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce").astype(
                    "Float64").round(2)

        int_cols = ["TOTAL_CURSOS", "TOTAL_ASISTENCIA_WEBINAR"]
        for c in int_cols:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")

        text_cols = [
            "NOMBRE_ALUMNO", "CORREO", "TELEFONO", "FUENTE",
            "PROGRAMAS_CURSOS", "GENERACION_PROGRAMAS", "PROGRAMAS_THINKIFIC",
            "WEBINAR", "WEBINARS", "COMENTARIOS", "GENERACION_GALA", "PRODUCTO_GALA",
            "PONENTE_GALA", "PONENCIA_GALA", "BANDERA_GALA"
        ]
        for c in text_cols:
            if c in df.columns:
                df[c] = df[c].astype("string").fillna("")

        df = df.replace({pd.NA: None})
        df = df.where(pd.notnull(df), None)

        return jsonify(df.to_dict(orient="records")), 200
    except Exception as e:
        app.logger.exception("Error en /api/comunidad: %s", e)
        return jsonify([]), 200


@app.route("/comunidad/<correo>")
@role_required("admin", "comunidad")
def comunidad_panel(correo):
    correo = (correo or "").strip().lower()

    q = """
      SELECT *
      FROM `fivetwofive-20.COMUNIDAD.VW_COMUNIDAD_CONSOLIDADO_X_ALUMNO`
      WHERE LOWER(TRIM(CORREO)) = LOWER(TRIM(@correo))
      LIMIT 1
    """
    job = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter(
            "correo", "STRING", correo)]
    )
    row = None
    for r in client.query(q, job_config=job).result():
        row = dict(r)
        break

    if not row:
        return render_template("comunidad_panel.html", data=None, cursos=[], webinars=[], seguimientos=[]), 404

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
