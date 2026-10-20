
import os
import secrets
import json
import urllib.parse
import urllib.request
import urllib.error

import psycopg

from flask import Flask, request, redirect, session, jsonify

app = Flask(__name__)

# Configuracao da sessao
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Credenciais do Mercado Livre
CLIENT_ID = os.environ.get("MERCADOLIVRE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("MERCADOLIVRE_CLIENT_SECRET", "").strip()

REDIRECT_URI = (
    "https://bruno-central-oauth-2026.onrender.com/oauth/callback"
)

AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
TOKEN_URL = "https://api.mercadolibre.com/oauth/token"


@app.get("/")
def home():
    if not app.secret_key:
        return (
            "Erro: FLASK_SECRET_KEY nao configurada no Render.",
            500,
        )

    if not CLIENT_ID or not CLIENT_SECRET:
        return (
            "Erro: confira as variaveis de ambiente do Mercado Livre.",
            500,
        )

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
            "mensagem": "Confira as variaveis de ambiente no Render.",
        }), 500

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    authorization_url = (
        AUTH_URL + "?" + urllib.parse.urlencode(params)
    )

    response = redirect(authorization_url)
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
                "Codigo de autorizacao nao recebido. "
                "Inicie a conexao pela pagina inicial."
            ),
        }), 400

    expected_state = session.pop("oauth_state", None)

    if not expected_state or not received_state:
        return jsonify({
            "status": "erro_validacao_state",
            "mensagem": (
                "Sessao OAuth nao encontrada. "
                "Volte a pagina inicial e tente novamente."
            ),
            "diagnostico": "state_ausente_ou_sessao_perdida",
        }), 400

    if not secrets.compare_digest(expected_state, received_state):
        return jsonify({
            "status": "erro_validacao_state",
            "mensagem": (
                "A validacao de seguranca falhou. "
                "Inicie uma nova conexao."
            ),
            "diagnostico": "state_diferente_do_esperado",
        }), 400

    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    data = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        TOKEN_URL,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as result:
            token_response = json.loads(
                result.read().decode("utf-8")
            )

    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = {}

        response = jsonify({
            "status": "erro_na_troca_do_token",
            "http_status": exc.code,
            "erro": body.get("error", "erro_http"),
            "mensagem": body.get(
                "error_description",
                "O Mercado Livre recusou a troca do codigo pelo token.",
            ),
            "orientacao": (
                "Confira as credenciais, o Redirect URI e se o codigo "
                "de autorizacao e novo."
            ),
        })
        response.status_code = 400
        response.headers["Cache-Control"] = "no-store"
        return response

    except (urllib.error.URLError, TimeoutError):
        return jsonify({
            "status": "erro_de_conexao",
            "mensagem": "Falha de conexao com a API do Mercado Livre.",
        }), 502

    except (ValueError, UnicodeDecodeError):
        return jsonify({
            "status": "erro",
            "mensagem": "Resposta da API nao pode ser interpretada.",
        }), 502

    if not token_response.get("access_token"):
        return jsonify({
            "status": "erro",
            "mensagem": "A API nao retornou um access token.",
        }), 502

    response = jsonify({
        "status": "conectado",
        "mensagem": (
            "Autorizacao concluida. Os tokens ainda nao foram salvos."
        ),
        "usuario_id": token_response.get("user_id"),
        "expira_em_segundos": token_response.get("expires_in"),
        "proxima_etapa": (
            "Configurar armazenamento seguro e renovacao dos tokens."
        ),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


# ROTA TEMPORARIA: teste da conexao com PostgreSQL
@app.get("/diagnostico-db")
def diagnostico_db():
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        return jsonify({
            "status": "erro",
            "mensagem": "DATABASE_URL nao configurada no Render.",
        }), 500

    try:
        with psycopg.connect(
            database_url,
            connect_timeout=5,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                resultado = cur.fetchone()[0]

        if resultado == 1:
            return jsonify({
                "status": "sucesso",
                "mensagem": "Conexao com PostgreSQL funcionando.",
            }), 200

        return jsonify({
            "status": "erro",
            "mensagem": "O banco respondeu com um resultado inesperado.",
        }), 500

    except Exception:
        app.logger.exception(
            "Falha no teste de conexao com PostgreSQL"
        )
        return jsonify({
            "status": "erro",
            "mensagem": (
                "Nao foi possivel conectar ao banco. "
                "Consulte os logs do Render."
            ),
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000")),
    )
