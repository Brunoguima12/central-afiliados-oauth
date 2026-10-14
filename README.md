# Central de Afiliados — retorno OAuth

Endpoint Flask mínimo para receber o retorno OAuth do Mercado Livre.

## Publicação
1. Envie estes arquivos para um repositório GitHub.
2. No Render, crie um Web Service conectado ao repositório.
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `gunicorn app:app`
5. Após o deploy, copie a URL HTTPS gerada pelo Render.
6. A URI de redirecionamento será `https://SEU-SERVICO.onrender.com/oauth/callback`, trocando pelo domínio real gerado.

## Importante
Este endpoint inicial não troca o código OAuth por token e não armazena códigos ou segredos. Antes de uso real, a integração precisa validar `state` contra CSRF e implementar a troca OAuth com credenciais protegidas. A URL só deve ser cadastrada se o DevCenter do Mercado Livre aceitá-la.
