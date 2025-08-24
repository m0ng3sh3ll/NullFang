# Interface Web do NullFang

Interface web para classificação e análise de documentos encontrados pelo NullFang.

## Características

- Visualização de documentos encontrados
- Classificação manual de documentos
- Análise de sensibilidade
- Relatórios e estatísticas
- Interface responsiva e moderna
- Mapa de infraestrutura (BloodHound-like)
- Correlação de usuários e acessos
- Análise de segurança

## Requisitos

- Go 1.16 ou superior
- SQLite3
- Navegador web moderno

## Instalação

1. Clone o repositório
2. Navegue até o diretório `web`
3. Execute `go mod tidy` para instalar as dependências

## Uso

Para iniciar o servidor web:

```bash
go run cmd/main.go -db /caminho/para/nfdb -port 8080
```

Parâmetros:
- `-db`: Caminho para o banco de dados SQLite do NullFang (padrão: "nfdb")
- `-port`: Porta para o servidor web (padrão: "8080")

## Acesso

Após iniciar o servidor, acesse:
```
http://localhost:8080
```

## Estrutura do Projeto

```
web/
├── cmd/
│   └── main.go           # Ponto de entrada do servidor
├── frontend/
│   └── src/
│       ├── router.js     # Roteamento do frontend
│       └── index.html    # Página principal
└── backend.go            # API e lógica do servidor
```

## Estrutura do Banco de Dados

### Tabelas Existentes
- `files`: Documentos encontrados
- `classifications`: Classificações de documentos
- `classification_rules`: Regras de classificação automática
- `document_classifications`: Relação entre documentos e classificações

### Novas Tabelas para Infraestrutura
- `hosts`: Informações sobre hosts descobertos
  - id, name, ip, os, domain, last_seen
  - is_domain_controller, is_server, is_workstation

- `users`: Usuários encontrados
  - id, username, domain, is_admin, last_seen
  - description, groups, password_last_set

- `groups`: Grupos de usuários
  - id, name, domain, description
  - is_admin_group, is_domain_admin

- `shares`: Compartilhamentos de rede
  - id, name, host_id, path
  - permissions, is_accessible

- `access_paths`: Caminhos de acesso
  - id, source_id, target_id, path_type
  - access_type, is_critical

- `user_access`: Acessos de usuários
  - id, user_id, target_id, target_type
  - access_type, first_seen, last_seen

### Índices e Relacionamentos
- Índices para busca rápida por nome, domínio e tipo
- Chaves estrangeiras para integridade referencial
- Índices compostos para consultas de caminhos

## Módulos

### 1. Documentos
- Visualização e classificação de documentos
- Análise de sensibilidade
- Relatórios e estatísticas

### 2. Infraestrutura (BloodHound-like)
- Mapa interativo de hosts e relações
- Visualização de nós (hosts, usuários, grupos, shares)
- Conexões mostrando relações de acesso
- Filtros por tipo de relação
- Exportação para relatórios

### 3. Correlação de Usuários
- Mapeamento de usuários admin/não-admin
- Histórico de acessos por host
- Análise de privilégios
- Identificação de cadeias de acesso
- Caminhos críticos de acesso

### 4. Análise de Segurança
- Identificação de configurações inseguras
- Detecção de permissões excessivas
- Sugestões de hardening
- Priorização de riscos

## Rotas da API

### Documentos (Existentes)
- `GET /api/documents`: Lista documentos
- `GET /api/documents/:id`: Obtém documento específico
- `POST /api/documents/classify`: Classifica documento
- `POST /api/documents/bulk-classify`: Classifica múltiplos documentos
- `POST /api/documents/auto-classify`: Classificação automática
- `DELETE /api/documents/classify/:id`: Remove classificação

### Infraestrutura (Novas)
- `GET /api/infrastructure/hosts`: Lista hosts
- `GET /api/infrastructure/hosts/:id`: Detalhes do host
- `GET /api/infrastructure/users`: Lista usuários
- `GET /api/infrastructure/users/:id`: Detalhes do usuário
- `GET /api/infrastructure/groups`: Lista grupos
- `GET /api/infrastructure/groups/:id`: Detalhes do grupo
- `GET /api/infrastructure/shares`: Lista compartilhamentos
- `GET /api/infrastructure/shares/:id`: Detalhes do compartilhamento

### Análise de Acesso
- `GET /api/analysis/access-paths`: Lista caminhos de acesso
- `GET /api/analysis/access-paths/:id`: Detalhes do caminho
- `GET /api/analysis/user-access`: Lista acessos de usuários
- `GET /api/analysis/user-access/:id`: Detalhes do acesso
- `GET /api/analysis/critical-paths`: Lista caminhos críticos
- `GET /api/analysis/privilege-escalation`: Análise de escalação

### Visualização
- `GET /api/visualization/graph`: Dados para o grafo
- `GET /api/visualization/graph/filtered`: Grafo com filtros
- `GET /api/visualization/graph/export`: Exporta grafo
- `GET /api/visualization/stats`: Estatísticas gerais

## Desenvolvimento

Para desenvolvimento local:

1. Inicie o servidor backend:
```bash
go run cmd/main.go
```

2. A interface web será servida automaticamente pelo backend

## Segurança

- A interface web é projetada para uso local
- Não requer conexão com internet
- Todos os dados são armazenados localmente
- Suporte a autenticação básica (opcional)

## Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request 