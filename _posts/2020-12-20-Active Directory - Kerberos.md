---
title: "Active Directory - Kerberos"
tags: [Windows, Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained.png)

# Considerações Iniciais

Agora vamos um pouco mais fundo na nossa exploração dentro do Active Directory, vamos brincar com o `Kerberos` que o servidor de autenticação do AD.

Logicamente minhas explicações vão ser bem simples e não esgotam todo o assunto, mas lhe dará uma base para estudos futuros

Aqui serão realizados os ataques de `Kerberoast`, `Constrained Delegation` e `Unconstrained Delegation`

## Como funciona o Kerberos?

Sempre que um usuário requisita o acesso a um serviço disponibilizado dentro do ambiente do Active Directory ele percorre esse caminho da figura abaixo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/kerberos.gif)

Que está "explicado" aqui:

Passo 1 -> O cliente solicita um TGT para o servidor do kerberos, o servidor checa o time stamp

Passo 2 -> o kdc mando um TGT, Ticket Grant Ticket, um ticket que garante acesso para um ticket que vai ser o TGS, ele é encriptado, assinado pelo hash do krbtgt (por isso quando pegamos o hash do krbtgt conseguimos controle sobre o AD)

Passo 3 -> O cliente manda o TGT de volta para o DC, para provar que o cliente tem um domain user logged in vaĺido. Me da um TGS já que sou eu mesmo, sou válido para todo o AD.

Passo 4 -> O kdc encripta o TGT, a unica validação que ele faz é se ele pode desincriptar o TGT com o hash do kerberos, então aqui é vulnerável, uma vez que conseguimos forjar um ticket qualquer com o hash do krbtgt podemos nos passar por qualquer um, pq ele vai validar o TGS

Passo 5 -> o usuário se conecta ao serviço que ele requisitou, enviando o TGS

Passo 6 -> Ele fornece a autenticação

O que me espanta mais é descobrir que `TODOS` os passos são vulneráveis e passíveis de algum tipo de exploração.

### Como assim todas vulneráveis?

Simmmmm, isso mesmo, todos os passos são passíveis de algum tipo de ataque, aqui vamos tentar explicar e explorar eles, logicamente não vai clarificar 100% dos conceitos, mas novamente, segue como base para estudos futuros, e por favor, caso tenha sugestões ou ache algum erro nas minhas explicações, me avise!

### Kerberoast

Esse "ataque" explora os passos `3` e `4`

No passo 3 o TGT, que foi apresentado pelo KDC/DC, podemos requisitar a autorização para qualquer serviço, uma vez que a única autenticação que ele faz é se ele pode desincriptar com o krbtgt hash

Requisitamos o ticket de um serviço que está sendo executado com *privilégios avançados*, vulgo SPN, `Service Principal Name`

### Unconstrained Delegation

### Constrained Delegation

