
import os
import secrets
import json
import time
import urllib.parse
import urllib.request
import urllib.error

from flask import Flask, request, redirect, session, jsonify

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")

CLIENT_ID = os.environ.get("MERCADOLIVRE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("MERCADOLIVRE_CLIENT_SECRET", "")
REDIRECT_URI = "https://bruno-central-oauth-2026.onrender.com/oauth/callback"

AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
TOKEN_URL = "https://api.mercadolibre.com/oauth/token"


@app.get("/")
def home():
    if not app.secret_key:
        return "Configuração incompleta: falta FLASK_SECRET_KEY no Render.", 500

    if not CLIENT_ID or not CLIENT_SECRET:
        return "Configuração incompleta: confira as variáveis do Mercado Livre no Render.", 500

    return """
    <!doctype html>
    <html lang="pt-br">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Central de Afiliados</title>
    </head>
    <body style="font-family:Arial;max-width:720px;margin:60px auto;padding:20px">
      <h1>Central de Afiliados</h1>
      <p>Conecte sua conta do Mercado Livre para iniciar a integração.</p>
      <a href="/oauth/login"
         style="display:inline-block;padding:14px 22px;background:#3483fa;
         color:white;text-decoration:none;border-radius:8px">
         Conectar ao Mercado Livre
      </a>
    </body>
    </html>
    """


@app.get("/oauth/login")
def oauth_login():
    if not app.secret_key or not CLIENT_ID or not CLIENT_SECRET:
        return "Configure as variáveis de ambiente no Render.", 500

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    url = AUTH_URL + "?" + urllib.parse.urlencode(params)
    return redirect(url)


@app.get("/oauth/callback")
def oauth_callback():
    error = request.args.get("error")
    if error:
        session.pop("oauth_state", None)
        return jsonify({
            "status": "erro_de_autorizacao",
            "mensagem": "O Mercado Livre não autorizou a conexão.",
            "erro": error
        }), 400

    code = request.args.get("code")
    received_state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)

    if not code:
        return jsonify({
            "status": "erro",
            "mensagem": "Código de autorização não recebido. Inicie pelo botão Conectar."
        }), 400

    if not expected_state or not received_state or not secrets.compare_digest(
        expected_state, received_state
    ):
        return jsonify({
            "status": "erro",
            "mensagem": "Validação de segurança falhou. Volte à página inicial e tente novamente."
        }), 400

    payload = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }).encode("utf-8")

    req = urllib.request.Request(
        TOKEN_URL,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            token_data = json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as exc:
        # Não registrar o corpo da resposta, pois pode conter dados sensíveis.
        app.logger.error("Mercado Livre recusou a troca do código. HTTP %s", exc.code)
        return jsonify({
            "status": "erro_na_troca_do_token",
            "mensagem": "O Mercado Livre recusou a autorização. Confira a configuração e tente novamente.",
            "http_status": exc.code
        }), 502

    except Exception:
        app.logger.exception("Falha de comunicação com o Mercado Livre.")
        return jsonify({
            "status": "erro_de_comunicacao",
            "mensagem": "Não foi possível concluir a comunicação com o Mercado Livre."
        }), 502

    # Esta versão valida a conexão, mas ainda não persiste os tokens.
    # Não exiba nem grave access_token ou refresh_token nos logs.
    if not token_data.get("access_token") or not token_data.get("refresh_token"):
        return jsonify({
            "status": "resposta_incompleta",
            "mensagem": "A API respondeu, mas não retornou todos os dados esperados."
        }), 502

    return jsonify({
        "status": "conectado",
        "mensagem": "Autorização concluída com sucesso. Os tokens ainda não foram salvos.",
        "usuario_id": token_data.get("user_id"),
        "expira_em_segundos": token_data.get("expires_in"),
        "proxima_etapa": "Configurar armazenamento seguro dos tokens."
    }), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000"))
    )
