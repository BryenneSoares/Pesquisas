
<p align="center">
  <img src="./imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
</p>

# CTI Purple Team - Execução Acionada por Evento: Alterar Associação de Arquivo Padrão 

Quando um arquivo é criado em um sistema operacional como o Windows, ele é automaticamente associado a um programa específico que será usado para abrir esse tipo de arquivo quando clicado duas vezes.

A execução acionada por evento permite que os usuários personalizem a maneira como os arquivos são abertos, definindo regras específicas para acionar a execução de aplicativos diferentes com base em diferentes eventos.

As seleções de associação de arquivos são armazenados no Registro do Windows e podem ser editados por usuários, administradores ou programas que tenham acesso ao Registro ou por administradores usando o utilitário associado.

Neste contexto, exploraremos os conceitos por trás da execução acionada por evento representando o sequestro da extenção ***.txt***, sendo possível executar um aplicativo malicioso antes que o arquivo real seja aberto.

## Contexto

Quando um arquivo ***.txt*** é clicado duas vezes, ele é aberto com um ***notepad.exe***. O windows por padrão sabe que para abrir esse tipo de extensão precisa usar o *notepad.exe*.

As associaçõs de arquivos do sistemas estão listadas em **HKEY_CLASSES_ROOT.[extention]**, no caso dessa pesquisa será listado em **HKEY_CLASSES_ROOT.txt**.

No entanto, é possível sequestrar chaves de registro que controlam o programa padrão para extensões específicas durante uma avaliação de Red Team, a fim de obter persistência.


## Análise e Execução do código malicioso

Há dois locais de registro que definem os manipuladores de extensão, que são mostrados a seguir, e são classificados como: *Global* e *Local*.

<p align="center">
  <img src="imagens/2.smbexec_header.png">
</p>

Quando um usuário tenta abrir um arquivo, o sistema operacional verifica os registros locais em (HKEY_USERS) para determinar qual programa está designado para lidar com aquela extensão de arquivo. Caso nao houver nenhuma entrada de registro associada, a verificação é feita na árvore de registro global (HKEY_CLASSES_ROOT).

Dependendo dos privilégios do usuário (Administrador ou Usuário Padrão), esses locais de registro podem ser explorados para executar código malicioso, utilizabdo o manipulador de extensão como um gatilho.
