
import os
import secrets
import json
import logging
import urllib.parse
import urllib.request
import urllib.error

from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row
from flask import Flask, request, redirect, session, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

logging.basicConfig(level=logging.INFO)

CLIENT_ID = os.environ.get("MERCADOLIVRE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("MERCADOLIVRE_CLIENT_SECRET", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

REDIRECT_URI = (
    "https://bruno-central-oauth-2026.onrender.com/oauth/callback"
)
AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
TOKEN_URL = "https://api.mercadolibre.com/oauth/token"


def database_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL nao configurada")
    return psycopg.connect(DATABASE_URL, connect_timeout=10)


def create_tokens_table():
    """Cria a tabela se ainda nao existir."""
    with database_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mercadolivre_tokens (
                    user_id BIGINT PRIMARY KEY,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)


def save_tokens(token_data):
    """Insere ou atualiza os tokens da conta autorizada."""
    user_id = token_data.get("user_id")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")

    if not user_id or not access_token or not expires_in:
        raise ValueError("Resposta OAuth incompleta")

    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=int(expires_in)
    )

    create_tokens_table()

    with database_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO mercadolivre_tokens (
                    user_id,
                    access_token,
                    refresh_token,
                    expires_at,
                    created_at,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (user_id)
                DO UPDATE SET
                    access_token = EXCLUDED.access_token,
                    refresh_token = EXCLUDED.refresh_token,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW()
            """, (
                int(user_id),
                access_token,
                refresh_token,
                expires_at,
            ))


@app.get("/")
def home():
    if not app.secret_key:
        return "FLASK_SECRET_KEY nao configurada no Render.", 500

    if not CLIENT_ID or not CLIENT_SECRET:
        return "Confira as credenciais do Mercado Livre no Render.", 500

    return """
    <!doctype html>
    <html lang="pt-br">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Central de Afiliados</title>
    </head>
    <body style="font-family:Arial,sans-serif;
                 max-width:720px;margin:60px auto;padding:20px">
        <h1>Central de Afiliados</h1>
        <p>Conecte sua conta do Mercado Livre.</p>
        <a href="/oauth/login"
           style="display:inline-block;background:#3483fa;color:white;
                  padding:12px 20px;text-decoration:none;border-radius:6px">
            Conectar ao Mercado Livre
        </a>
    </body>
    </html>
    """


@app.get("/oauth/login")
def oauth_login():
    if not app.secret_key or not CLIENT_ID or not CLIENT_SECRET:
        return jsonify({
            "status": "erro",
            "mensagem": "Confira as variaveis de ambiente do Render.",
        }), 500

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    url = AUTH_URL + "?" + urllib.parse.urlencode(params)
    response = redirect(url)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/oauth/callback")
def oauth_callback():
    error = request.args.get("error")

    if error:
        return jsonify({
            "status": "erro_de_autorizacao",
            "mensagem": "O Mercado Livre nao autorizou a conexao.",
            "detalhe": error,
        }), 400

    code = request.args.get("code")
    received_state = request.args.get("state")

    if not code:
        return jsonify({
            "status": "erro",
            "mensagem": (
                "Codigo nao recebido. Inicie a conexao pela pagina inicial."
            ),
        }), 400

    expected_state = session.pop("oauth_state", None)

    if not expected_state or not received_state:
        return jsonify({
            "status": "erro_validacao_state",
            "mensagem": (
                "Sessao OAuth nao encontrada. Inicie uma nova conexao."
            ),
        }), 400

    if not secrets.compare_digest(expected_state, received_state):
        return jsonify({
            "status": "erro_validacao_state",
            "mensagem": (
                "Validacao de seguranca falhou. Inicie uma nova conexao."
            ),
        }), 400

    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    req = urllib.request.Request(
        TOKEN_URL,
        data=urllib.parse.urlencode(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as result:
            token_data = json.loads(result.read().decode("utf-8"))

    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = {}

        return jsonify({
            "status": "erro_na_troca_do_token",
            "http_status": exc.code,
            "erro": body.get("error", "erro_http"),
            "mensagem": body.get(
                "error_description",
                "O Mercado Livre recusou a troca do codigo pelo token.",
            ),
        }), 400

    except (urllib.error.URLError, TimeoutError):
        return jsonify({
            "status": "erro_de_conexao",
            "mensagem": "Falha de conexao com o Mercado Livre.",
        }), 502

    except (ValueError, UnicodeDecodeError):
        return jsonify({
            "status": "erro",
            "mensagem": "Resposta invalida da API do Mercado Livre.",
        }), 502

    try:
        save_tokens(token_data)
    except Exception:
        app.logger.exception("Falha ao salvar tokens no PostgreSQL")
        return jsonify({
            "status": "erro_ao_salvar_tokens",
            "mensagem": (
                "A autorizacao foi recebida, mas nao foi possivel "
                "salvar os tokens. Consulte os logs do Render."
            ),
        }), 500

    response = jsonify({
        "status": "conectado",
        "mensagem": (
            "Autorizacao concluida e tokens armazenados no PostgreSQL."
        ),
        "usuario_id": token_data.get("user_id"),
        "expira_em_segundos": token_data.get("expires_in"),
        "tokens_exibidos": False,
        "proxima_etapa": "Validar armazenamento e preparar renovacao.",
    })
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000")),
    )
