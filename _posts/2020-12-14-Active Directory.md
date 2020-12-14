---
title: "Active Directory - Introdução"
tags: [Windows, Active Directory]
categories: Active Directory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-intro/active.png)

# Considerações Iniciais

Estou há um bom tempo sem realizar posts aqui, agora vou iniciar uma seção a respeito de Active Directory, principais formas de ataque e suas possíveis mitigações.

Antes de iniciar a série de posts, vamos clarificar alguns explicações mais básicas

## O que é Active Directory?

É o que o Windows utiliza para controlar redes do próprio Windows, tudo no AD são objetos. Centraliza tudo com o intuito de gerenciar com mais "segurança" a rede. De certo modo é um outro mundo dentro da Microsoft.

O Active Directory (AD) é uma ferramenta da Microsoft utilizada para o gerenciamento de usuários de rede, denominada serviço de diretório. Um diretório nada mais é do que um banco de dados contendo informações dos usuários de uma organização, tais como nome, login, senha, cargo, perfil e etc.

Como podemos ver na imagem abaixo ele `centraliza` tudo dentro da rede.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-intro/active1.png)

Uma paraíso para os gerentes de rede não? Até certo ponto sim, contudo pelo menos pra mim ele é um tanto quanto complexo de se implementar e realmente entender o funcionamento a fundo dele pode demorar anos.

São alguns dos principais recursos do AD:

```
    Autenticação centralizada
    Nível de segurança controlado
    Facilita a Delegação de tarefas administrativas
    Torna eficiente o gerenciamento de acesso
    Proporciona um índice dos recursos na rede
    Subdivisão de domínios em unidades lógicas
    Fornece recursos de replicação de dados
    Facilita a atribuição e manutenção de múltiplos domínios
    Unificação do sistema de nomes baseado em DNS
    Facilita a implementação de políticas de utilização (Políticas de Grupos)
```

## Como Funciona o Active Directory?

Certo, como ele funciona?

### Funcionamento do AD na perspectiva do usuário

Na perspectiva dos usuários, o AD funciona para que eles possam acessar os recursos disponíveis na rede. Para isso basta que estes efetuem o logon uma única vez no ambiente local de rede (normalmente, ao iniciar o sistema Operacional).

Quando o usuário digita seu login e senha, o AD verifica se as informações fornecidas pelos usuários são válidas, e em caso positivo, realizar a autenticação. O AD é organizado de uma forma hierárquica, com o uso de domínios.

### Funcionamento do AD na perspectiva técnica

As informações relevantes que normalmente são armazenadas no AD incluem basicamente:

```
    dados de contato do usuário,
    informações da fila da impressora,
    e dados específicos de configuração do desktop ou da rede.
```

O "Active Directory data Store" (Banco de Dados de Active Directory) contém todas as informações do diretório, como informações sobre usuários, computadores, grupos, outros objetos e os objetos aos quais os usuários podem acessar, assim como componentes de rede. Ele permite um gerenciamento de acesso total e controlado.

Os diretórios são utilizados para gerenciar pacotes de software, arquivos e contas de usuários finais dentro das organizações. O administrador utiliza os conceitos de árvore e floresta do AD, não sendo necessário visitar os desktops individualmente.  

## Infraestrutura do Active Directory

E como ele é estruturado?

### Estrutura Lógica do Active Directory (AD)

A estrutura lógica é dividida de forma a facilitar a gestão dos objetos / registros de conta para os recursos de rede, dentro da organização. 

#### Objetos

São os recursos de rede gerenciados pelo AD. 

Objetos são parte da estrutura lógica do AD. O principal objetivo desta ferramenta é auxiliar o administrador de redes com o gerenciamento de recursos de redes. Para isso, o AD permite que o administrador cadastre os recursos em forma de objetos de diretório. Cada tipo/classe de objeto corresponde a um tipo de recurso administrado. 

Tipos de Objetos no Active Directory :

```
    Usuários
    Pasta Compartilhadas
    Grupos de Usuários
    Unidades Organizacionais
    Computadores
    Impressoras
    Contatos
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-intro/active2.png)

#### Unidades Organizacionais

É um tipo de objeto de diretório contido nos domínios para qual podem ser atribuídas configurações de Política de Grupos de Usuários ou delegar autoridade administrativa.

Unidades Organizacionais são parte da estrutura lógica do AD. Na Administração do  Active Directory, uma Unidade Organizacional (U.O.) é um tipo de objeto de diretório contido nos domínios para qual podem ser atribuídas configurações de Política de Grupos de Usuários ou delegar autoridade administrativa (a U.O. é o menor escopo ou a menor unidade à qual você pode atribuir estas configurações).

Este recurso facilita o trabalho do Administrador de Redes que gerencia a configuração e o uso de contas e recursos com base no modelo organizacional da empresa em que trabalha. 

#### Domínios, Árvores e Florestas

*Domínio:* é uma atribuição de nome para uma família de recursos. O domínio é a principal unidade funcional da estrutura lógica do Active Directory.

*Árvore:* trata-se de uma organização hierárquica de um ou mais Domínios. Todos os domínios compartilham na arvore, informações e recursos, onde as funções são únicas.

*Floresta:* é um conjunto de árvores. O uso de florestas é bastante comum em grupos de empresas, onde cada uma das empresas do grupo mantém uma autonomia de identidade em relação as outras.

### Estrutura Física do Active Directory

É formada basicamente por:

```
    Controladores de domínio
    Sites
```

Os componentes responsáveis por otimizar o tráfego de rede, manter segurança em locais físicos e fornecer recursos que são utilizados na perspectiva lógica.

#### Controladores de domínio (Domain Controllers - DC)

É um um servidor que executa o AD DS: Active Directory Domain Services (Servidor de Domínio do Active Directory). Um DC tem executa o Active Directory e armazena a base do AD, bem como replica esta base com outros DC’s.

O AD DS mantém um banco de dados com informações sobre recursos da rede e dados específicos de aplicativos habilitados por diretório. Em outras palavras, é o AD DS que armazena os dados da estrutura lógica do AD.

O gerenciamento de acesso é possível graças aos recursos fornecidos pelo AD DS por meio de autenticação de logon e controle de acesso a recursos no diretório:

```
    os administradores podem gerenciar dados de diretório e organização por toda a sua rede;
    os usuários de rede podem usar um único logon para acessar recursos em qualquer lugar na rede, conforme configurações previamente estabelecidas pelos administradores. 
```

#### Sites

Um site é localização física de sua infraestrutura de redes, como por exemplo uma rede local (LAN). No AD DS, um objeto de site representa os aspectos do site físico que podem ser gerenciados, especificamente, a replicação dos dados do diretório entre os controladores de domínio.

Os objetos de sites normalmente são utilizados pelo administrador de redes para:

```
    Criar novos sites
    Delegar o controle sobre sites usando a Política de Grupo e as permissões
```

Em cada site há um objeto de Configurações de Site NTDS que identifica o criador de topologia entre sites (ISTG). O ISTG é o controlador de domínio no site que gera os objetos de conexão dos controladores de domínio em sites diferentes e desempenha funções avançadas de gestão da replicação.

# Conclusão

Bom, deu pra ter um overview bem bacana do que se trata Active Directory e ter a certeza que é uma ferramenta excelente quando bem implementada e utilizada pelo pessoal de TI de qualquer organização que seja, mas como sabemos, nem tudo são maravilhas, agora vamos começar a verificar como podemos explorar ele para ganharmos acesso dentro do ambiente!