# Palco Vivo na nuvem

Servidor do Palco Vivo para outras pessoas usarem com a conta delas, sem criar conta na Groq.

- `public/index.html`: o Palco Vivo (gerado pelo build, modo "conta").
- `public/admin.html`: painel de administração (só e-mails em `ADMIN_EMAILS`).
- `src/index.js`: servidor (Cloudflare Worker). Entrada com Google, IA e Whisper da Groq com a chave do servidor, minutos por pessoa, assinatura pelo Mercado Pago, e-books e atas em `/e/<id>/`.
- Banco D1 criado sozinho; as tabelas são criadas no primeiro acesso.

Segredos (painel da Cloudflare, tipo "Secret"): `GROQ_KEY`, `SESSION_SECRET`, `MP_TOKEN`.
Aviso do Mercado Pago (webhook): `https://<endereço>/api/mp/aviso`, evento "Planos e assinaturas".
Publicação: Cloudflare Workers ligado a este repositório, pasta raiz `app`.
