import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.get("/")
def home():
    return """<!doctype html><html lang="pt-br"><meta charset="utf-8">
    <title>Central Afiliados OAuth</title>
    <body style="font-family:Arial,sans-serif;max-width:720px;margin:60px auto;padding:0 20px">
    <h1>Central de Afiliados</h1>
    <p>Endpoint de retorno OAuth do Mercado Livre em execução.</p>
    <p>Rota de retorno: <code>/oauth/callback</code></p></body></html>"""

@app.get("/oauth/callback")
def oauth_callback():
    # Não registrar códigos, tokens ou segredos em logs.
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    if error:
        return jsonify({"status": "authorization_error", "error": error}), 400
    if not code:
        return jsonify({"status": "callback_reached",
                        "message": "Rota acessível; nenhum código OAuth recebido.",
                        "state_received": bool(state)}), 200
    # A troca do código por token será implementada separadamente no app Windows.
    return jsonify({"status": "authorization_code_received",
                    "message": "Código recebido, não exibido nem armazenado.",
                    "state_received": bool(state)}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
