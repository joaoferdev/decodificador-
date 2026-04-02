# Atlas Certificate Toolkit

Ferramenta web para:

- decodificar CSR
- converter certificados entre `PEM`, `CRT`, `DER`, `KEY`, `PFX` e `P12`
- extrair arquivos de `PFX/P12`
- alertar quando os arquivos enviados nao formam um par valido
- avisar quando um certificado parece ser intermediario ou raiz da cadeia

## Estrutura

- `src`
  Backend em Node.js + Express.
- `atlas-certificate-toolkit-ui`
  Frontend em React + Vite.
- `tests`
  Validacoes automatizadas do backend.

## O que a ferramenta faz

### CSR Decoder

Permite colar ou enviar um CSR e visualizar:

- subject
- algoritmo da chave
- assinatura
- extensoes
- fingerprints
- avisos importantes

### Conversao de certificados

Permite enviar arquivos como:

- `.pem`
- `.crt`
- `.cer`
- `.key`
- `.pfx`
- `.p12`
- `.csr`
- `.txt`

E gerar saidas como:

- `PEM`
- `CRT`
- `DER`
- `KEY`
- `PFX`
- `P12`
- bundle PEM

## Comportamentos importantes

- `PFX/P12` so sao gerados quando certificado e chave privada correspondem.
- Quando ha mais de um certificado ou mais de uma chave privada, a aplicacao evita escolher arquivos de forma ambigua.
- Certificados intermediarios e raiz da cadeia sao sinalizados para o usuario.
- Algumas conversoes continuam disponiveis quando apenas o certificado e valido, como `PEM`, `CRT` e `DER`.

## Requisitos

- Node.js 20+
- npm

## Desenvolvimento

### Backend

```bash
npm install
npm run dev
```

Backend padrao:

- `http://localhost:3000`

### Frontend

```bash
cd atlas-certificate-toolkit-ui
npm install
npm run dev
```

Frontend padrao:

- `http://localhost:5173`

## Variaveis de ambiente

### Backend

O arquivo `.env.example` existe para servir como modelo de configuracao.

Ele nao e usado automaticamente em producao. A ideia e:

1. copiar `.env.example` para `.env`
2. preencher os valores reais do ambiente
3. manter o `.env.example` versionado como referencia para o projeto

Exemplo:

```bash
cp .env.example .env
```

Variaveis do backend:

- `NODE_ENV`
- `PORT`
- `LOG_LEVEL`
- `TRUST_PROXY`
- `CORS_ORIGINS`
- `REQUIRE_AUTH_TOKEN`
- `RATE_LIMIT_WINDOW_MS`
- `RATE_LIMIT_MAX`
- `CSR_RATE_LIMIT_MAX`
- `JOB_CREATE_RATE_LIMIT_MAX`
- `JOB_ACTION_RATE_LIMIT_MAX`
- `JOB_STORAGE_ROOT`
- `JOB_TTL_MS`
- `REQUEST_TIMEOUT_MS`
- `JSON_BODY_LIMIT`
- `TEXT_BODY_LIMIT`
- `MAX_UPLOAD_FILE_SIZE_BYTES`
- `MAX_UPLOAD_FILES`

### Frontend

O frontend usa `VITE_API_BASE`.

Exemplo:

```bash
cd atlas-certificate-toolkit-ui
cp .env.example .env
```

## Build

### Backend

```bash
npm run build
```

### Frontend

```bash
cd atlas-certificate-toolkit-ui
npm run build
```

## Testes

### Backend

```bash
npm test
```

### Frontend

```bash
cd atlas-certificate-toolkit-ui
./node_modules/.bin/tsc -b
```

## Publicacao

### Checklist minimo

- configurar HTTPS
- publicar backend e frontend em dominios reais
- preencher `CORS_ORIGINS` com o dominio do frontend
- configurar `VITE_API_BASE` com a URL publica da API
- revisar limites de upload
- revisar `rate limit`
- monitorar `/health`
- confirmar que logs nao contem material sensivel

### Recomendacoes de deploy

- colocar o backend atras de proxy reverso ou plataforma com HTTPS
- usar `NODE_ENV=production`
- manter limpeza de arquivos temporarios
- validar fluxo real com:
  - certificado + chave correta
  - certificado + chave errada
  - PFX com senha correta
  - PFX com senha incorreta
  - certificado intermediario

## Observacoes de seguranca

- Arquivos enviados sao tratados como material sensivel.
- A aplicacao nao deve ser publicada sem HTTPS.
- `REQUIRE_AUTH_TOKEN` pode ficar vazio se a ferramenta for publica.
- Mesmo publica, a aplicacao deve continuar com `rate limit`, timeout e limites de upload.
- Por padrao, os arquivos temporarios ficam em `.tmp/atlas-certificate-toolkit` dentro do projeto e expiram automaticamente conforme `JOB_TTL_MS`.
- Na inicializacao, a aplicacao remove diretorios temporarios expirados que tenham sobrado de reinicios anteriores.
- Erros internos agora retornam mensagens genericas ao cliente; detalhes tecnicos ficam apenas nos logs.

## Operacao e observabilidade

- `/health` agora informa `jobTtlMs` e contadores simples de operacao, como jobs criados, jobs expirados, receitas executadas e downloads.
- Se quiser mover o armazenamento temporario para outro volume ou area isolada, configure `JOB_STORAGE_ROOT`.
- Em ambientes compartilhados, prefira um diretorio temporario exclusivo da aplicacao com permissao restrita.

## Resumo sobre `.env.example`

O `.env.example` existe para documentar quais variaveis a aplicacao precisa.

Ele serve para:

- facilitar setup local
- facilitar deploy
- evitar esquecer configuracoes obrigatorias
- mostrar quais valores sao esperados sem expor segredos reais

Ele nao deve conter senhas reais, tokens reais nem URLs sensiveis de producao.
