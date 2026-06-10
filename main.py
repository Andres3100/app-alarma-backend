from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, messaging
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="App Alarma API")

# Inicializar Firebase
google_credentials = os.environ.get("GOOGLE_CREDENTIALS")
if google_credentials:
    cred_dict = json.loads(google_credentials)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccount.json")
firebase_admin.initialize_app(cred)

# Conexión a base de datos
def get_db():
    DATABASE_URL = os.environ.get("DATABASE_URL")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

# Crear tablas si no existen
def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id SERIAL PRIMARY KEY,
            casa VARCHAR(200),
            vecino VARCHAR(200),
            tipo VARCHAR(50),
            barrio VARCHAR(200),
            hora VARCHAR(20),
            activa BOOLEAN DEFAULT TRUE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id SERIAL PRIMARY KEY,
            token TEXT UNIQUE
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

class Alerta(BaseModel):
    casa: str
    vecino: str
    tipo: str
    barrio: str

class Token(BaseModel):
    token: str

@app.get("/")
def inicio():
    return {"mensaje": "Servidor App Alarma funcionando"}

@app.post("/registrar-token")
def registrar_token(data: Token):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO tokens (token) VALUES (%s) ON CONFLICT (token) DO NOTHING",
        (data.token,)
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Token registrado"}

@app.post("/alertas")
def crear_alerta(alerta: Alerta):
    conn = get_db()
    cur = conn.cursor()
    hora = datetime.now().strftime("%H:%M:%S")
    cur.execute(
        "INSERT INTO alertas (casa, vecino, tipo, barrio, hora) VALUES (%s, %s, %s, %s, %s) RETURNING *",
        (alerta.casa, alerta.vecino, alerta.tipo, alerta.barrio, hora)
    )
    nueva = cur.fetchone()
    conn.commit()

    # Obtener todos los tokens
    cur.execute("SELECT token FROM tokens")
    tokens = cur.fetchall()
    cur.close()
    conn.close()

    # Enviar notificación a todos los vecinos
    for row in tokens:
        try:
            message = messaging.Message(
                notification=messaging.Notification(
                    title="🚨 ALERTA DE ROBO",
                    body=f"{alerta.vecino} - {alerta.casa}",
                ),
                data={
                    "casa": alerta.casa,
                    "vecino": alerta.vecino,
                    "tipo": alerta.tipo,
                },
                token=row["token"],
            )
            messaging.send(message)
        except Exception as e:
            print(f"Error enviando notificación: {e}")

    return {"mensaje": "Alerta creada y vecinos notificados", "alerta": dict(nueva)}

@app.get("/alertas")
def obtener_alertas():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alertas ORDER BY id DESC")
    alertas = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(a) for a in alertas]

@app.put("/alertas/{id}/desactivar")
def desactivar_alerta(id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE alertas SET activa = FALSE WHERE id = %s", (id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Alerta desactivada"}