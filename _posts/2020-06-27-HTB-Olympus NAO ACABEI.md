---
title: "Hack The Box - Olympus"
tags: [Linux,Medium]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/135>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 2222 - Servidor SSH

> Porta 80 - Servidore Web

> Porta 53 - Servidor DNS

## Enumeração da porta 53

Bom, seguindo aquela ideia que Porta 53 aberta sempre é coisa boa pro atacante pq geralmente sinaliza uma má configuração do servidor DNS, vamos começar nossa enumeração por aqui

Não conseguimos nada por aqui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_dns.png)

Nem vamos tentar muito pq não vai ter sucesso

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_burp.png)

Não irei rodar o Gobuster também por que realmente não teve nada de útil

Bom, estamos no 0, o que fazer?

Joga a requisição do site pro BurpSuite e vamos ver se tem algo de diferente interagindo com a aplicação

### BurpSuite

Então atualizamos a página e mandamos a requisição para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_burp.png)

Agora mandamos pro Repeater e enviamos a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_burp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_burp2.png)

Aqui de cara algo já nos chamou atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_burp3.png)

Xdebug 2.5.5

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_google.png)

Hummm... uma ferramenta de debugação PHP, isso quer dizer que conseguimos debugar remotamente, possivelmente vamos conseguir explorar por aqui

# Exploração Xdebug 2.5.5

Bom, sabendo disso e que é no mínimo estranho ter isso habilitado, vamos pesquisar mais, pra ver como podemos explorar isso pra ganhar RCE na máquina, dando uma pesquisada em outros write ups, encontrei bastante material pra poder embasar a exploração, vou fazer de duas maneiras. Uma mais demorada, manual mesmo, explicando passo a passo através de puglins do Chrome, a outra mais específica e direta através de um script

## Exploração Manual (Chrome)

Os créditos desse método são todos do Ippsec, fica a dica pra vocês procurarem no YouTube pelo seus vídeos

Primeiro passo é abrir o "Chromium" na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m.png)

Segundo passo é pesquisar pro Apps que realizem debugação do Xdebug 2.5.5

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m2.png)

https://chrome.google.com/webstore/detail/xdebug/nhodjblplijafdpjjfhhanfmchplpfgl

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m3.png)

Então, instalamos ela e iniciamos a aplicação clicando em LISTEN

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m5.png)

Agora verificamos que a aplicação abriu uma conexão na nossa porta local 9000

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m6.png)

Terceiro passo agora é "startar" a aplicação, para isso enviamos uma requisição para a máquina do HTB

```
Com o comando 
GET /?XDEBUG_SESSION_START=qlqr coisa
Iniciamos o debug
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m7.png)

A requisição vai automaticamente para o Debuger que está aberto no Chrome

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-olympus/O_m8.png)

Essa merda também não deu, depois daqui uns tempo voltar aqui e tentar de novo