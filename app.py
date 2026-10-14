
import os
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.get("/")
def home():
    return """
    <!doctype html>
    <html lang="pt-br">
    <meta charset="utf-8">
    <title>Central Afiliados OAuth</title>
    <body style="font-family:Arial,sans-serif;max-width:720px;margin:60px auto;padding:20px">
    <h1>Central de Afiliados</h1>
    <p>Endpoint de retorno OAuth do Mercado Livre em execução.</p>
    <p>Rota de trabalho: <code>/oauth/callback</code></p>
    </body>
    </html>
    """


@app.get("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        return jsonify({
            "status": "erro_de_autorizacao",
            "erro": error
        }), 400

    if not code:
        return jsonify({
            "status": "callback_reached",
            "mensagem": "Rota acessível; nenhum código OAuth recebido.",
            "estado_recebido": bool(state)
        }), 200

    # Não registra nem armazena o código OAuth.
    return jsonify({
        "status": "codigo_de_autorizacao_recebido",
        "mensagem": "Código recebido, mas não armazenado.",
        "estado_recebido": bool(state)
    }), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000"))
    )
