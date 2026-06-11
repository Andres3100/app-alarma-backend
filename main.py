from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from typing import Optional
import firebase_admin
from firebase_admin import credentials, messaging
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import jwt

# ──────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────

app = FastAPI(title="App Alarma API - Multi-Barrio")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET", "cambia-esto-en-produccion-por-algo-largo-y-seguro")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 365 * 5  # 5 años

# ──────────────────────────────────────────
# FIREBASE
# ──────────────────────────────────────────

google_credentials = os.environ.get("GOOGLE_CREDENTIALS")
if google_credentials:
    cred_dict = json.loads(google_credentials)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccount.json")
firebase_admin.initialize_app(cred)

# ──────────────────────────────────────────
# BASE DE DATOS
# ──────────────────────────────────────────

def get_db():
    DATABASE_URL = os.environ.get("DATABASE_URL")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Tabla de barrios / proyectos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS barrios (
            id SERIAL PRIMARY KEY,
            nombre VARCHAR(200) NOT NULL,
            direccion VARCHAR(300),
            ciudad VARCHAR(100),
            codigo_unico VARCHAR(20) UNIQUE NOT NULL,
            activo BOOLEAN DEFAULT TRUE,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

    # Agregar columnas nuevas si no existen
    cur.execute("""
        ALTER TABLE barrios 
        ADD COLUMN IF NOT EXISTS telefono_vigilante VARCHAR(20),
        ADD COLUMN IF NOT EXISTS telefono_presidente VARCHAR(20)
    """)

    # Tabla de usuarios (3 roles)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            barrio_id INTEGER REFERENCES barrios(id),
            nombre VARCHAR(200) NOT NULL,
            email VARCHAR(200) UNIQUE NOT NULL,
            telefono VARCHAR(20),
            casa VARCHAR(100),
            password_hash TEXT NOT NULL,
            rol VARCHAR(20) NOT NULL CHECK (rol IN ('superadmin', 'admin_barrio', 'vecino')),
            activo BOOLEAN DEFAULT TRUE,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

    # Tabla de alertas (asociadas a un barrio)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id SERIAL PRIMARY KEY,
            barrio_id INTEGER REFERENCES barrios(id) NOT NULL,
            usuario_id INTEGER REFERENCES usuarios(id),
            casa VARCHAR(200),
            vecino VARCHAR(200),
            tipo VARCHAR(50),
            descripcion TEXT,
            hora VARCHAR(20),
            activa BOOLEAN DEFAULT TRUE,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

    # Tabla de tokens (FCM + refresh tokens)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
            barrio_id INTEGER REFERENCES barrios(id),
            tipo VARCHAR(20) NOT NULL CHECK (tipo IN ('fcm', 'refresh')),
            token TEXT NOT NULL,
            expira_en TIMESTAMP,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

    # Crear superadmin por defecto si no existe
    cur.execute("SELECT id FROM usuarios WHERE rol = 'superadmin' LIMIT 1")
    if not cur.fetchone():
        password_hash = bcrypt.hashpw(
            os.environ.get("SUPERADMIN_PASSWORD", "superadmin123").encode(),
            bcrypt.gensalt()
        ).decode()
        cur.execute("""
            INSERT INTO usuarios (nombre, email, password_hash, rol)
            VALUES ('Super Administrador', %s, %s, 'superadmin')
        """, (
            os.environ.get("SUPERADMIN_EMAIL", "admin@appalarma.com"),
            password_hash
        ))

    conn.commit()
    cur.close()
    conn.close()


init_db()

# ──────────────────────────────────────────
# MODELOS
# ──────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class CrearBarrioRequest(BaseModel):
    nombre: str
    direccion: Optional[str] = None
    ciudad: Optional[str] = None
    email_admin: str
    nombre_admin: str
    password_admin: str
    telefono_admin: Optional[str] = None

class CrearVecinoRequest(BaseModel):
    nombre: str
    email: str
    password: str
    telefono: Optional[str] = None
    casa: str

class AlertaRequest(BaseModel):
    tipo: str
    descripcion: Optional[str] = None

class TokenFCMRequest(BaseModel):
    token: str

class RevocarSesionRequest(BaseModel):
    usuario_id: int

# ──────────────────────────────────────────
# JWT HELPERS
# ──────────────────────────────────────────

def crear_access_token(usuario_id: int, barrio_id: Optional[int], rol: str) -> str:
    expira = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(usuario_id),
        "barrio_id": barrio_id,
        "rol": rol,
        "tipo": "access",
        "exp": expira
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def crear_refresh_token(usuario_id: int, barrio_id: Optional[int], rol: str) -> tuple[str, datetime]:
    expira = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(usuario_id),
        "barrio_id": barrio_id,
        "rol": rol,
        "tipo": "refresh",
        "exp": expira
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expira


def verificar_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def get_usuario_actual(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = verificar_token(credentials.credentials)
    if payload.get("tipo") != "access":
        raise HTTPException(status_code=401, detail="Se requiere access token")
    return payload


def require_rol(*roles):
    def checker(usuario: dict = Depends(get_usuario_actual)):
        if usuario["rol"] not in roles:
            raise HTTPException(status_code=403, detail="No tienes permiso para esta acción")
        return usuario
    return checker

# ──────────────────────────────────────────
# ENDPOINTS PÚBLICOS
# ──────────────────────────────────────────

@app.get("/")
def inicio():
    return {"mensaje": "Servidor App Alarma funcionando", "version": "2.0"}


@app.post("/auth/login")
def login(data: LoginRequest):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM usuarios WHERE email = %s AND activo = TRUE", (data.email,))
    usuario = cur.fetchone()

    if not usuario or not bcrypt.checkpw(data.password.encode(), usuario["password_hash"].encode()):
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    # Crear tokens
    access_token = crear_access_token(usuario["id"], usuario["barrio_id"], usuario["rol"])
    refresh_token, expira = crear_refresh_token(usuario["id"], usuario["barrio_id"], usuario["rol"])

    # Guardar refresh token en base de datos
    cur.execute("""
        INSERT INTO tokens (usuario_id, barrio_id, tipo, token, expira_en)
        VALUES (%s, %s, 'refresh', %s, %s)
    """, (usuario["id"], usuario["barrio_id"], refresh_token, expira))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "rol": usuario["rol"],
        "nombre": usuario["nombre"],
        "barrio_id": usuario["barrio_id"],
        "casa": usuario["casa"]
    }


@app.post("/auth/refresh")
def refresh(data: RefreshRequest):
    payload = verificar_token(data.refresh_token)
    if payload.get("tipo") != "refresh":
        raise HTTPException(status_code=401, detail="Se requiere refresh token")

    conn = get_db()
    cur = conn.cursor()

    # Verificar que el refresh token existe en la base de datos (no fue revocado)
    cur.execute("""
        SELECT id FROM tokens
        WHERE token = %s AND tipo = 'refresh' AND expira_en > NOW()
    """, (data.refresh_token,))
    token_db = cur.fetchone()

    if not token_db:
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Sesión revocada o expirada. Inicia sesión de nuevo.")

    # Emitir nuevo access token
    nuevo_access = crear_access_token(
        int(payload["sub"]),
        payload["barrio_id"],
        payload["rol"]
    )

    cur.close()
    conn.close()
    return {"access_token": nuevo_access}


# ──────────────────────────────────────────
# ENDPOINTS SUPERADMIN
# ──────────────────────────────────────────

@app.post("/admin/barrios")
def crear_barrio(data: CrearBarrioRequest, usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()

    # Generar código único para el barrio
    import random, string
    codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # Crear el barrio
    cur.execute("""
        INSERT INTO barrios (nombre, direccion, ciudad, codigo_unico)
        VALUES (%s, %s, %s, %s) RETURNING id
    """, (data.nombre, data.direccion, data.ciudad, codigo))
    barrio_id = cur.fetchone()["id"]

    # Crear el admin_barrio
    password_hash = bcrypt.hashpw(data.password_admin.encode(), bcrypt.gensalt()).decode()
    cur.execute("""
        INSERT INTO usuarios (barrio_id, nombre, email, telefono, password_hash, rol)
        VALUES (%s, %s, %s, %s, %s, 'admin_barrio') RETURNING id
    """, (barrio_id, data.nombre_admin, data.email_admin, data.telefono_admin, password_hash))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "mensaje": "Barrio creado exitosamente",
        "barrio_id": barrio_id,
        "codigo_unico": codigo,
        "admin_email": data.email_admin,
        "admin_password": data.password_admin
    }


@app.get("/admin/barrios")
def listar_barrios(usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT b.*, COUNT(u.id) as total_vecinos
        FROM barrios b
        LEFT JOIN usuarios u ON u.barrio_id = b.id AND u.rol = 'vecino'
        GROUP BY b.id
        ORDER BY b.creado_en DESC
    """)
    barrios = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(b) for b in barrios]


@app.post("/admin/revocar-sesion")
def revocar_sesion(data: RevocarSesionRequest, usuario: dict = Depends(require_rol("superadmin", "admin_barrio"))):
    conn = get_db()
    cur = conn.cursor()

    # Si es admin_barrio, verificar que el usuario pertenece a su barrio
    if usuario["rol"] == "admin_barrio":
        cur.execute("SELECT barrio_id FROM usuarios WHERE id = %s", (data.usuario_id,))
        target = cur.fetchone()
        if not target or target["barrio_id"] != usuario["barrio_id"]:
            cur.close()
            conn.close()
            raise HTTPException(status_code=403, detail="No puedes revocar sesiones fuera de tu barrio")

    cur.execute("DELETE FROM tokens WHERE usuario_id = %s AND tipo = 'refresh'", (data.usuario_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Sesión revocada. El usuario deberá iniciar sesión de nuevo."}


# ──────────────────────────────────────────
# ENDPOINTS ADMIN_BARRIO
# ──────────────────────────────────────────

@app.get("/barrio/vecinos")
def listar_vecinos(usuario: dict = Depends(require_rol("admin_barrio", "superadmin", "vecino"))):
    conn = get_db()
    cur = conn.cursor()
    barrio_id = usuario["barrio_id"]
    cur.execute("""
        SELECT id, nombre, email, telefono, casa, activo, creado_en
        FROM usuarios
        WHERE barrio_id = %s AND rol = 'vecino'
        ORDER BY casa
    """, (barrio_id,))
    vecinos = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(v) for v in vecinos]

@app.get("/barrio/vecinos")
def listar_vecinos(usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    barrio_id = usuario["barrio_id"]
    cur.execute("""
        SELECT id, nombre, email, telefono, casa, activo, creado_en
        FROM usuarios
        WHERE barrio_id = %s AND rol = 'vecino'
        ORDER BY casa
    """, (barrio_id,))
    vecinos = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(v) for v in vecinos]


@app.delete("/barrio/vecinos/{vecino_id}")
def desactivar_vecino(vecino_id: int, usuario: dict = Depends(require_rol("admin_barrio"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE usuarios SET activo = FALSE
        WHERE id = %s AND barrio_id = %s AND rol = 'vecino'
    """, (vecino_id, usuario["barrio_id"]))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Vecino desactivado"}


# ──────────────────────────────────────────
# ENDPOINTS VECINOS (y admin)
# ──────────────────────────────────────────

@app.post("/tokens/fcm")
def registrar_token_fcm(data: TokenFCMRequest, usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()

    # Evitar duplicados: borrar token anterior del mismo usuario si existía
    cur.execute("""
        DELETE FROM tokens WHERE usuario_id = %s AND tipo = 'fcm'
    """, (int(usuario["sub"]),))

    cur.execute("""
        INSERT INTO tokens (usuario_id, barrio_id, tipo, token)
        VALUES (%s, %s, 'fcm', %s)
    """, (int(usuario["sub"]), usuario["barrio_id"], data.token))

    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Token FCM registrado"}


@app.post("/alertas")
def crear_alerta(data: AlertaRequest, usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()

    barrio_id = usuario["barrio_id"]
    hora = datetime.now().strftime("%H:%M:%S")

    # Obtener datos del usuario
    cur.execute("SELECT nombre, casa FROM usuarios WHERE id = %s", (int(usuario["sub"]),))
    user_data = cur.fetchone()

    cur.execute("""
        INSERT INTO alertas (barrio_id, usuario_id, casa, vecino, tipo, descripcion, hora)
        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *
    """, (
        barrio_id,
        int(usuario["sub"]),
        user_data["casa"],
        user_data["nombre"],
        data.tipo,
        data.descripcion,
        hora
    ))
    nueva_alerta = dict(cur.fetchone())

    # Obtener todos los tokens FCM del mismo barrio
    cur.execute("""
        SELECT t.token FROM tokens t
        JOIN usuarios u ON u.id = t.usuario_id
        WHERE t.tipo = 'fcm' AND t.barrio_id = %s AND u.activo = TRUE
    """, (barrio_id,))
    tokens_fcm = cur.fetchall()

    conn.commit()
    cur.close()
    conn.close()

    # Enviar notificación push a todos los vecinos del barrio
    tipo_labels = {
        "robo": "🚨 ALERTA DE ROBO",
        "sospechoso": "👁️ PERSONA SOSPECHOSA",
        "incendio": "🔥 ALERTA DE INCENDIO",
        "emergencia": "🆘 EMERGENCIA",
    }
    titulo = tipo_labels.get(data.tipo, "⚠️ ALERTA COMUNAL")

    for row in tokens_fcm:
        try:
            message = messaging.Message(
                notification=messaging.Notification(
                    title=titulo,
                    body=f"{user_data['nombre']} - {user_data['casa']}",
                ),
                data={
                    "tipo": data.tipo,
                    "casa": user_data["casa"] or "",
                    "vecino": user_data["nombre"],
                    "alerta_id": str(nueva_alerta["id"]),
                },
                token=row["token"],
            )
            messaging.send(message)
        except Exception as e:
            print(f"Error enviando notificación: {e}")

    return {"mensaje": "Alerta creada y vecinos notificados", "alerta": nueva_alerta}


@app.get("/alertas")
def obtener_alertas(usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()

    if usuario["rol"] == "superadmin":
        # Superadmin ve todo
        cur.execute("SELECT * FROM alertas ORDER BY creado_en DESC LIMIT 100")
    else:
        # Vecinos y admins ven solo su barrio
        cur.execute("""
            SELECT * FROM alertas WHERE barrio_id = %s
            ORDER BY creado_en DESC LIMIT 100
        """, (usuario["barrio_id"],))

    alertas = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(a) for a in alertas]


@app.put("/alertas/{alerta_id}/desactivar")
def desactivar_alerta(alerta_id: int, usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE alertas SET activa = FALSE
        WHERE id = %s AND barrio_id = %s
    """, (alerta_id, usuario["barrio_id"]))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Alerta desactivada"}


@app.get("/auth/me")
def mi_perfil(usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.nombre, u.email, u.telefono, u.casa, u.rol, u.creado_en,
               b.nombre as barrio_nombre, b.ciudad, b.codigo_unico
        FROM usuarios u
        LEFT JOIN barrios b ON b.id = u.barrio_id
        WHERE u.id = %s
    """, (int(usuario["sub"]),))
    perfil = cur.fetchone()
    cur.close()
    conn.close()
    return dict(perfil)


@app.get("/barrio/info")
def info_barrio(usuario: dict = Depends(require_rol("admin_barrio", "superadmin", "vecino"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT nombre, direccion, ciudad, codigo_unico, 
               telefono_vigilante, telefono_presidente 
        FROM barrios WHERE id = %s
    """, (usuario["barrio_id"],))
    barrio = cur.fetchone()
    cur.close()
    conn.close()
    return dict(barrio)

@app.put("/barrio/contactos")
def actualizar_contactos(
    datos: dict,
    usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))
):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE barrios SET 
            telefono_vigilante = %s,
            telefono_presidente = %s
        WHERE id = %s
    """, (datos.get("telefono_vigilante"), datos.get("telefono_presidente"), usuario["barrio_id"]))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Contactos actualizados"}