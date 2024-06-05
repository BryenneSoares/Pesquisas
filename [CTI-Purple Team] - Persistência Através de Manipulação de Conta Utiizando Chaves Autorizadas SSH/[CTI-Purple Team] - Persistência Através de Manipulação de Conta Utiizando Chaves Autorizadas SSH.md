
<p align="center">
<<<<<<< HEAD
  <img src="./imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
=======
  <img src="./Imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
</p>

# CTI Purple Team - Persistência Utilizando Chaves Autorizadas SSH

Nesta pesquisa, iremos abordar a tática [TA0003](https://attack.mitre.org/tactics/TA0003/) (Persistência), dando ênfase a sub-técnica [T1098.004](https://attack.mitre.org/techniques/T1098/004/) (Account Manipulation: SSH Authorized Keys).

A tática de persisência é uma das maneiras pelas quais os invasores podem explorar eventos específicos do sistema para executar código malicioso de forma persistente. Neste ataque em questão, os adversários podem mudar o `autorized_keys`, arquivo SSH no Linux para manter a persistência no host da vítima. 

Uma vez dentro do sistema, mesmo que a máquina seja reiniciada ou as chaves de acesso SSH sejam modificadas, isso pode incluir adição de entradas ao cronjob, instalação de backdoors, ou, especificamente para o nosso caso, adição de chaves SSH autorizadas.

<<<<<<< HEAD
**A priori, para executar o sequestro de extensão, é importante salientar que o atacante já possua o primeiro acesso inicial à máquina alvo, com privilégios administrativos. Portando, já ter realizado a Execução e Escalação de Privilégios na vítima**.
=======
**A priori, para executar a manipulação de conta, é importante salientar que o atacante já possua o primeiro acesso inicial à máquina alvo, com privilégios administrativos. Portando, já ter realizado a Execução e Escalação de Privilégios na vítima**.
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

## Contexto

SSH ou Shell Seguro, é um protocolo de internet criptografado de código aberto usado para administrar e comunicar-se com servidores e executar comandos remotamente. Um servidor SSH pode autenticar clientes usando vários métodos diferentes. A mais básica delas é a autenticação por senha, que é fácil de usar, mas não é a mais segura.

A manipulação de contas refere-se à criação, modificação ou exclusão de contas de usuários ou outras credenciais na infraestrutura de TI de uma organização. Embora existem algumas maneiras diferentes de fazer login em um servidor SSH, neste guia nos concentraremos na configuração de chaves SSH.

O `autorized_keys` arquivo em SSH especifica as chaves SSH que podem ser usadas para fazer login na conta de usuário para a qual o arquivo está configurado.

O diretório `.ssh` dentro do diretório inicial do usuário contém esse arquivo,`<user-home>/.ssh/autorized_keys`. Por exemplo, para um usuário chamado smith, você pode encontrar o `autorized_keys` arquivo localizado em `/home/smith/.ssh/autorized_keys`. Este arquivo define as chaves públicas que este usuário usa para fazer login em algumas de suas contas. Cada linha do arquivo representa uma única chave pública.

Os usuários podem editar o arquivo de configuração SSH do sistema para modificar as diretivas `PubKeyAuthentication` e `RSAAuthentication` para o valor `"yes"` para garantir que a  chave pública e a autenticada RSA estejam habilitadas em `/etc/ssh/sshd-config`.

## Emulação de Ameaça - Etapa I: Criação da Chave SSH

Para começar a usar o SSH sem senha é preciso gerar um par de chaves SSH em seu computador local. Neste guia vamos focar na versão 2 do SSH, que é a mais recente e mais segura.

Primeiro, verificamos se a chave SSH para a máquina atacante já existe. Isto irá prevenir que a configuração atual seja sobrescrita, caso haja uma. Utilizaremos o comando abaixo:

```zsh
ls -al ~/.ssh/id_*.pub
``` 

Se houver uma chave existente, você tem as opções de pular os passos de geração de uma chave SSH, sobrescrever as configurações atuais ou criar um backup da chave existente. Se a chave não existir, você vai ver o seguinte resultado:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/chave não existente.png">
  <br>
  Figura : Par de Chaves SSH Não Existente
=======
  <img src="Imagens/chave não existente.png">
  <br>
  Figura 1 : Par de Chaves SSH Não Existente
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
</p>

Se a chave ja existir, terá um output como abaixo:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/chaves existente.png">
  <br>
  Figura : Par de Chaves SSH Existentes
=======
  <img src="Imagens/chaves existente.png">
  <br>
  Figura 2 : Par de Chaves SSH Existentes
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
</p>

Em seguida, vamos prosseguir com a geração da chave SSH. Para gerar uma chave pública no Ubuntu, utiliza-se o utilitário especial chamado `ssh-keygen -t rsa` ou também pode utilizar a versão mais simples do comando `ssh-keygen`. 

***Info***: A opção *`-t`* significa *type* e *`RSA`* é o protocolo padrão utilizado na geração da chave.

```zsh
ssh-keygen -t rsa
```
```zsh
ssh-keygen
```

<<<<<<< HEAD
Você será solicitado para escolher um local para as chaves que serão geradas. Por padrão, as chaves serão armazenadas no diretório `~/.ssh` do diretório inicial do usuário. A chave privada será chamada `id_rsa` e a chave pública associada será chamada `id_rsa.pub`. 

Caso queira escolher outro local, basta digitá-lo agora, caso contrário, apenas pressione `ENTER` para aceitar o padrão.

<p align="center">
  <img src="imagens/local para chave.png">
  <br>
  Figura : Atribuindo Local para o Par de Chaves SSH
</p>

=======
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
***Info:*** A chave padrão é de 2048 bits. Mas se você quer mais segurança basta trocar o valor para 4096 bits. Neste caso o comando será:

```zsh
ssh-keygen -t rsa -b 4096
```

<<<<<<< HEAD
Em seguida, será solicitado atribuir uma senha para a chave. Este é um processo opcional, tendo em consideração que essa senha pode ser usada para criptografar o arquivo de chave privada do disco.

<p align="center">
  <img src="imagens/senha para chave.png">
  <br>
  Figura : Atribuir senha para a Chave Criada
=======
Você será solicitado para escolher um local para as chaves que serão geradas. Por padrão, as chaves serão armazenadas no diretório `~/.ssh` do diretório inicial do usuário. A chave privada será chamada `id_rsa` e a chave pública associada será chamada `id_rsa.pub`. 

Caso queira escolher outro local, basta digitá-lo agora, caso contrário, apenas pressione `ENTER` para aceitar o padrão.

<p align="center">
  <img src="Imagens/local para chave.png">
  <br>
  Figura 3 : Atribuindo Local para o Par de Chaves SSH
</p>

Em seguida, será solicitado atribuir uma senha para a chave. Este é um processo opcional, tendo em consideração que essa senha pode ser usada para criptografar o arquivo de chave privada do disco.

<p align="center">
  <img src="Imagens/senha para chave.png">
  <br>
  Figura 4 : Atribuir senha para a Chave Criada
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
</p>

Abaixo podemos vizualizar o par de chaves criadas com sucesso:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/par de chaves criada.png">
  <br>
  Figura : Atribuir senha para a Chave Criada
=======
  <img src="Imagens/par de chaves criada.png">
  <br>
  Figura 5 : Chaves Criadas com Sucesso
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
</p>

A próxima etapa é colocar a chave pública em seu servidor para que você possa usar a autenticação de chave SSH para fazer login.

## Emulação de Ameaça - Etapa II: Copiando uma Chave Pública SSH Para o seu Servidor

Existem várias maneiras de encaminhar sua chave pública para o servidor SSH remoto. A escolha do método a ser utilizado varia conforme as ferramentas à disposição e as especificidades da sua configuração atual. Sâo eles:

  - Utilizar o comando ssh-copy-id.
  - Copiar utilizando o SSH.
  - Copiar manualmente.

Embora os métodos abaixo alcancem o mesmo resultado final, o mais direto e automatizado é apresentado em primeiro lugar. As alternativas subsequentes demandam passos manuais adicionais, devendo ser adotadas somente se os métodos anteriores não forem viáveis.

### 1° Método: Copiar a Chave Pública usando o Comando `ssh-copy-id`

Uma forma direta de transferir sua chave pública para um servidor já existente é através do `ssh-copy-id`, um utilitário conhecido pela sua simplicidade. Se estiver disponível, é recomendado utilizá-lo.

<<<<<<< HEAD
O ssh-copy-id faz parte dos pacotes OpenSSH em muitas distribuições, o que significa que você provavelmente já o tem instalado no seu sistema local. No entanto, para que esse método funcione, é necessário ter acesso SSH com senha ao servidor.

Para usar o utilitário, você precisa especificar o host remoto ao qual deseja se conectar e a conta de usuário à qual você tem acesso SSH baseado em senha. Esta é a conta onde sua chave SSH pública será copiada.

A sintaxe do comanda é:
=======
O **ssh-copy-id** faz parte dos pacotes OpenSSH em muitas distribuições, o que significa que você provavelmente já o tem instalado no seu sistema local. No entanto, para que esse método funcione, é necessário ter acesso SSH com senha ao servidor.

Para usar o utilitário, é preciso especificar o host remoto ao qual deseja se conectar e a conta de usuário à qual você tem acesso SSH baseado em senha. Esta é a conta onde sua chave SSH pública será copiada.

A sintaxe do comando é:
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

```zsh
ssh-copy-id username@remote_host
```
Você pode ver uma mensagem como esta:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/">
  <br>
  Figura : 
=======
  <img src="Imagens/host remoto não reconhecido.png">
  <br>
  Figura 6 : Host Remoto Não Reconhecido no Primeiro Login
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
</p>

Isso significa que o seu computador local não reconhece o host remoto. Isso acontecerá na primeira vez que você se conectar a um novo host. Digite `yes` e pressione `ENTER` para continuar.

<<<<<<< HEAD
Em seguida, o utilitário verificará sua conta local em busca da `id_rsa.pub`, chave que criamos anteriormente. Ao encontrar a chave, ele solicitará a senha da conta do usuário remoto:

<p align="center">
  <img src="imagens/auntenticação na chave.png">
  <br>
  Figura : Senha da Conta Remota
</p>

Digite a senha (sua digitação não será exibida por motivos de segurança) e pressione ENTER. O utilitário se conectará à conta no host remoto usando a senha fornecida. Em seguida, ele copiará o conteúdo da sua cahve `~/.ssh/id_rsa.pub` em um arquivo no `~/.ssh` diretório inicial da conta remota chamado ***`authorized_keys`***.
=======
Em seguida, o utilitário verificará sua conta local em busca da `id_rsa.pub`, a chave que criamos anteriormente. Ao encontrar a chave, ele solicitará a senha da conta do usuário remoto:

<p align="center">
  <img src="Imagens/auntenticação na chave.png">
  <br>
  Figura 7 : Senha da Conta Remota
</p>

Digite a senha (sua digitação não será exibida por motivos de segurança) e pressione `ENTER`. O utilitário  irá estabelecer uma conexão com a conta no servidor remoto utilizando a senha fornecida. Em seguida, será feita a cópia do conteúdo da sua chave `~/.ssh/id_rsa.pub` para um arquivo no diretório inicial da conta remota, denominado ***authorized_keys*** em `~/.ssh`.
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

Você verá uma saída semelhante a esta:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/">
  <br>
  Figura : 
=======
  <img src="Imagens/chave copiada.png">
  <br>
  Figura 8 : Chave Copiada com Sucesso
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
</p>

Neste ponto, sua chave **`id_rsa.pub`** foi carregada na conta remota. Você pode continuar na próxima seção.

### 2° Método: Copiar a Chave Pública usando `SSH`

<<<<<<< HEAD
Se você não tiver ssh-copy-idacesso SSH baseado em senha a uma conta em seu servidor, poderá fazer upload de suas chaves usando um método SSH convencional.

Podemos fazer isso enviando o conteúdo de nossa chave SSH pública em nosso computador local e canalizando-o por meio de uma conexão SSH para o servidor remoto. Por outro lado, podemos ter certeza de que o ~/.sshdiretório existe na conta que estamos usando e então enviar o conteúdo que canalizamos para um arquivo chamado authorized_keysdentro deste diretório.

Usaremos o símbolo `>>` de redirecionamento para anexar o conteúdo em vez de substituí-lo. Isso nos permitirá adicionar chaves sem destruir as chaves adicionadas anteriormente.
=======

Caso não tenha acesso SSH baseado em senha para uma conta em seu servidor usando **ssh-copy-id**, é possível carregar suas chaves utilizando um método SSH convencional.

Podemos fazer isso enviando o conteúdo de nossa chave SSH pública em nosso computador local e canalizando-o através de uma conexão SSH para o servidor remoto. Alternativamente, podemos garantir a existência do diretório **~/.ssh** na conta que estamos utilizando e então enviar o conteúdo que canalizamos para um arquivo chamado ***authorized_keys*** dentro deste diretório.

Para evitar a substituição do conteúdo existente, usaremos o símbolo de redirecionamento `>>` para anexar o conteúdo. Dessa forma, podemos adicionar chaves sem apagar as chaves adicionadas anteriormente.
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

O comando completo ficará assim:

```zsh
cat ~/.ssh/id_rsa.pub | ssh username@remote_host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

Você pode ver uma mensagem como esta:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/local da chave.png">
  <br>
  Figura : 
</p>

Isso significa que o seu computador local não reconhece o host remoto. Isso acontecerá na primeira vez que você se conectar a um novo host. Digite yese pressione ENTERpara continuar.
=======
  <img src="Imagens/copia da chave método 2.png">
  <br>
  Figura 9 : Host Remoto Não Reconhecido no Primeiro Login
</p>

Isso significa que o seu computador local não reconhece o host remoto. Isso acontecerá na primeira vez que você se conectar a um novo host. Digite `yes` e pressione `ENTER` para continuar.
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

Posteriormente, você será solicitado a fornecer a senha da conta à qual está tentando se conectar:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/local da chave.png">
  <br>
  Figura : 
</p>

Após inserir sua senha, o conteúdo da sua id_rsa.pubchave será copiado para o final do authorized_keysarquivo da conta do usuário remoto. Continue para a próxima seção se tiver sido bem-sucedido.

### 3° Método: Copiar a Chave Pública usando Manualmente

Se você não tiver acesso SSH baseado em senha ao seu servidor disponível, você terá que fazer o processo acima manualmente.

O conteúdo do seu id_rsa.pubarquivo deverá ser adicionado a um arquivo ~/.ssh/authorized_keysna sua máquina remota de alguma forma.

Para exibir o conteúdo da sua id_rsa.pubchave, digite isto em seu computador local:
=======
  <img src="Imagens/auntenticação na chave com método 2.png">
  <br>
  Figura 10 : Solicitação de Senha da Conta Remota
</p>

Após inserir sua senha, o conteúdo da sua chave **id_rsa.pub** será copiado para o final do arquivo **authorized_keys** da conta do usuário remoto. Continue para a próxima seção se tiver sido bem-sucedido.

### 3° Método: Copiar a Chave Pública usando Manualmente

Se, por alguma razão você não tiver acesso SSH baseado em senha ao seu servidor, precisará executar o procedimento manualmente.

O conteúdo do arquivo **id_rsa.pub** deverá ser inserido no arquivo `~/.ssh/authorized_keys` em sua máquina remota de alguma maneira.

Para visualizar o conteúdo da sua chave **id_rsa.pub**, digite o seguinte comando em seu computador local:
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

```zsh
cat ~/.ssh/id_rsa.pub
```

Você verá o conteúdo da chave, que pode ser parecido com isto:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/local da chave.png">
  <br>
  Figura : 
</p>

Acesse seu host remoto usando qualquer método disponível. Pode ser um console baseado na Web fornecido pelo seu provedor de infraestrutura.

Depois de ter acesso à sua conta no servidor remoto, você deve certificar-se de que o ~/.sshdiretório foi criado. Este comando criará o diretório se necessário ou não fará nada se ele já existir:
=======
  <img src="Imagens/conteúdo da chave método 3.png">
  <br>
  Figura 11 : Conteúdo da Chave SSH
</p>

Depois de ter acesso à sua conta no servidor remoto, você deve certificar-se de que o diretório `~/.ssh` foi criado. Este comando criará o diretório se necessário ou não fará nada se ele já existir:
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

```zsh
mkdir -p ~/.ssh
```

<<<<<<< HEAD
Agora você pode criar ou modificar o authorized_keysarquivo neste diretório. Você pode adicionar o conteúdo do seu id_rsa.pubarquivo ao final do authorized_keysarquivo, criando-o se necessário, usando isto:
=======
Agora você pode criar ou modificar o arquivo `authorized_keys` neste diretório. Você pode adicionar o conteúdo do seu arquivo `id_rsa.pub` ao final do arquivo `authorized_keys`, criando-o se necessário, utilizando o comando abaixo:
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

```zsh
echo public_key_string >> ~/.ssh/authorized_keys
```

<<<<<<< HEAD
No comando acima, substitua public_key_stringpela saída do cat ~/.ssh/id_rsa.pubcomando que você executou em seu sistema local. Deve começar com ssh-rsa AAAA...ou similar.
=======
No comando acima, substitua ***`public_key_string`*** pela saída do comando cat ***`~/.ssh/id_rsa.pub`*** que você executou no passo anterior. Deve começar com `ssh-rsa AAAA...` ou algo similar.

Uma vez que a chave tiver sido copiada, você pode configurar as permissões requeridas pelo com o comando abaixo:

```zsh
chmod -766 ~/.ssh
```
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

Se isso funcionar, você pode testar sua nova autenticação SSH baseada em chave.

## Emulação de Ameaça - Etapa III: Autenticando no Servidor usando Chaves SSH

Se você tiver concluído com êxito um dos procedimentos acima, deverá conseguir fazer login no host remoto sem a senha da conta remota.

O processo é basicamente o mesmo:

```zsh
ssh username@remote_host
```

Se esta for a primeira vez que você se conecta a este host (se você usou o último método acima), você poderá ver algo assim:

<p align="center">
<<<<<<< HEAD
  <img src="imagens/local da chave.png">
  <br>
  Figura : 
</p>

Isso significa que o seu computador local não reconhece o host remoto. Digite yese pressione ENTERpara continuar.

Se você não forneceu uma senha para sua chave privada, você fará login imediatamente. Se você forneceu uma senha para a chave privada quando criou a chave, será necessário inseri-la agora. Posteriormente, uma nova sessão shell será criada para você com a conta no sistema remoto.

Se tiver sucesso, continue para descobrir como bloquear o servidor.

## Emulação de Ameaça - Etapa IV: Desabilitar a Autenticação por Senha SSH

Se você conseguiu fazer login em sua conta usando SSH sem uma senha, você configurou com êxito a autenticação baseada em chave SSH em sua conta. No entanto, o seu mecanismo de autenticação baseado em senha ainda está ativo, o que significa que o seu servidor ainda está exposto a ataques de força bruta.

Antes de concluir as etapas desta seção, certifique-se de ter a autenticação baseada em chave SSH configurada para a conta raiz neste servidor ou, de preferência, de ter a autenticação baseada em chave SSH configurada para uma conta neste servidor com sudoacesso. Esta etapa bloqueará logins baseados em senha, portanto, é essencial garantir que você ainda poderá obter acesso administrativo.

Assim que as condições acima forem verdadeiras, faça login em seu servidor remoto com chaves SSH, como root ou com uma conta com sudoprivilégios. Abra o arquivo de configuração do daemon SSH:
=======
  <img src="Imagens/host nao reconhecido método 3.png">
  <br>
  Figura 12 : Host Remoto Não Reconhecido no Primeiro Login
</p>

Isso significa que o seu computador local não reconhece o host remoto. Digite `yes`e pressione `ENTER` para continuar.

Se você não forneceu uma senha para sua chave privada, você fará login imediatamente. Se você forneceu uma senha para a chave privada quando criou a chave, será necessário inseri-la agora. Posteriormente, uma nova sessão shell será criada para você com a conta no sistema remoto.

Se tiver sucesso, continue para descobrir como bloquear o servidor na sessão de mitgação, após a engenharia de detecção.

Abaixo é demonstrado a emulação do início do processo de ataque, desde a criação das chaves, a cópia e authenticação:

<p align="center">
  <img src="Imagens/gif da emulação.gif">
  <br>
  Figura 13: Demonstração do Processo de Ataque
</p>

## Engenharia de Detecção

Para monitorar o arquivo `authorized_keys` usando Sysmon, é necessário configurar uma regra específica no Sysmon para Linux que capture eventos de criação de arquivos neste diretório específico.

<p align="center">
  <img src="Imagens/configuração sysmon.png">
  <br>
  Figura : Configuração do Arquivo do Sysmon para Linux
</p>

Quando uma modificação ocorre no arquivo **authorized_keys**, o Sysmon registra um evento com ID 1. Aqui está um exemplo de como esse evento pode aparecer no log:

<p align="center">
  <img src="Imagens/log do sysmon, event id 1.png">
  <br>
  Figura : Event Id 1, do Sysmon para Linux, no Log do Elastic
</p>

O Event ID 1 do Sysmon para Linux é usado para monitorar e registrar eventos de criação de arquivos. o que inclui a criação, modificação ou sobrescrita de arquivos específicos. Quando ocorre uma modificação no arquivo `authorized_keys` em um sistema Linux, este evento pode ser crucial para a segurança, pois indica uma possível alteração nas chaves SSH autorizadas para acesso remoto.

Abaixo é demonstrado a regra criada no Elastic para detecção do log de auteração do arquivo authorized_key e seus alertas gerados:

<p align="center">
  <img src="Imagens/Detecção no Elastic.png">
  <br>
  Figura : Alertas Gerados com a Regra Criada pelo Purple Team
</p>

## Mitigação: Desabilitar a Autenticação Sem Senha SSH

Se você conseguiu fazer login em sua conta usando SSH sem uma senha, você configurou com êxito a autenticação baseada em chave SSH em sua conta. No entanto, o seu mecanismo de autenticação baseado em senha ainda está ativo, o que significa que o seu servidor ainda está exposto a ataques de força bruta.

Antes de concluir as etapas desta seção, certifique-se de ter a autenticação baseada em chave SSH configurada para a conta **raiz** neste servidor ou, de preferência, de ter a autenticação baseada em chave SSH configurada para uma conta neste servidor com acesso `sudo`. Esta etapa bloqueará logins baseados em senha, portanto, é essencial garantir que você ainda poderá obter acesso administrativo.

Assim que as condições acima forem verdadeiras, faça login em seu servidor remoto com chaves SSH, como **root** ou com uma conta com de privilégios `sudo`. Abra o arquivo de configuração do `daemon` SSH:
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

```zsh
sudo nano /etc/ssh/sshd_config
```

<<<<<<< HEAD
Dentro do arquivo, procure por uma diretiva chamada PasswordAuthentication. Isso pode ser comentado. Remova o comentário da linha removendo qualquer #no início da linha e defina o valor como no. Isso desativará sua capacidade de fazer login por meio de SSH usando senhas de conta:

<p align="center">
  <img src="imagens/event ID 4657.png">
  <br>
  Figura 12: Ativação do Event ID 4657
</p>

Salve e feche o arquivo quando terminar. Para realmente implementar as alterações que acabamos de fazer, você deve reiniciar o serviço.
=======
Dentro do arquivo, procure por uma diretiva chamada `PasswordAuthentication`. Isso pode ser comentado. Remova o comentário da linha removendo qualquer `#`no inicio da linha e defina o valor como `no`. Isso desativará sua capacidade de fazer login por meio de SSH usando senhas de conta:

<p align="center">
  <img src="Imagens/Desativar Capacidade de Fazer Login com SSH.png">
  <br>
  Figura : Desativar Capacidade de Realizar Login sem Senha com SSH
</p>

Salve e feche o arquivo quando terminar. Para realmente implementar as alterações que acabamos de fazer, você deve reiniciar o servidor.
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

Na maioria das distribuições Linux, você pode emitir o seguinte comando para fazer isso:

```zsh
sudo systemctl restart ssh
```

<<<<<<< HEAD
Depois de concluir esta etapa, você fez a transição bem-sucedida do seu daemon SSH para responder apenas às chaves SSH.

## Engenharia de Detecção

A detecção consiste em ativar a auditoria de segurança do *Event ID 4657*, seguindo o fluxo demonstrado na imagem abaixo.

<p align="center">
  <img src="imagens/event ID 4657.png">
  <br>
  Figura 12: Ativação do Event ID 4657
</p>

Como podemos observar, o comportamento produzido pela modificação da chave de registro é bem notório, gerando um único evento encontrado no *Microsoft Security Event IDs* e um único Event do Sysmon:

- [4657: A Registry Value was Modified](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4657)
- Log 13, Sysmon

<p align="center">
  <img src="imagens/Event ID log de alteração.png">
  <br>
  Figura 13: Log evidenciando a alteração da chave de registro
</p>

<p align="center">
  <img src="imagens/Event ID 13, Sysmom.png">
  <br>
  Figura 14: Event 13, Sysmon
</p>

### Padrão SIGMA: Event Triggered Execution: Change Default File Association

```yaml
title: 'CTI Purple Team - Persistência Utilizando Chaves Autorizadas SSH'
id: 19469c03-2a2e-4cce-953c-374a8d16c40d
status: stable
description: 'Esta regra detecta o comportamento gerado pela modificação da chave de registro de uma extenção de arquivo, para a realização de Persistência.'
references:
    - 'https://attack.mitre.org/techniques/T1098/004/'
author: CTI Purple Team
date: 10/04/2024
=======
Depois de concluir esta etapa, você fez a transição bem-sucedida do seu **daemon** SSH para responder apenas às chaves SSH.

### Padrão SIGMA: Account Manipulation: SSH Authorized Keys

```yaml
title: 'CTI Purple Team - Persistência Utilizando Chaves Autorizadas SSH'
id: d4bb6e92-00b8-48be-a11e-bf6591796548
status: stable
description: 'Esta regra detecta o comportamento gerado pela modificação do arquivo de chaves autorizadas SSH no Linux, para a realização de Persistência.'
references:
    - 'https://attack.mitre.org/techniques/T1098/004/'
author: CTI Purple Team
date: 17/05/2024
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
tags:
    - attack.persistence.TA0003
    - attack.T1098.004 # Account Manipulation: SSH Authorized Keys
logsource:
    category: 'process_creation'
<<<<<<< HEAD
    product: 'windows', 'sysmon'
detection:
    RegistryModification:
      EventID:
        - 4657
        - 13
      TargetRegistryKey|contains|all:
        - 'shell'
        - 'open'
        - 'command'
    condition: RegistryModification
fields:
    - ProcessName;
    - TargetObject.
falsepositives:
    - No
=======
    product: 'sysmon'
detection:
    Process_Creation:
      EventID:
        - 1
      Process.command_line|contains|all:
        - 'authorized_keys'
    condition: Process_Creation
fields:
    - 'User'
    - 'ParentUser'
falsepositives:
    - "É necessário validar se foi realizado uma ação administrativa de conhecimento da equipe de infraestrutura"
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42
level: high
```

## Conclusão

<<<<<<< HEAD
Agora você deve ter a autenticação baseada em chave SSH configurada e em execução no seu servidor, permitindo entrar sem fornecer uma senha de conta. A partir daqui, há muitas direções que você pode seguir. Se quiser saber mais sobre como trabalhar com SSH, dê uma olhada em nosso guia básico de SSH .
=======
Agora você deve ter a autenticação baseada em chave SSH configurada e em execução no seu servidor, permitindo entrar sem fornecer uma senha de conta. A partir daqui, há muitas direções que você pode seguir.
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42

Esperamos que você que leu ou assistiu o Webinar, possa ter compreendido a inteligência que trouxemos nesta pesquisa. Qualquer dúvida, é só nos contactar.

## Link do Webinar

<<<<<<< HEAD
Caso você não pode participar do Webinar de apresentação da pesquisa, ou gostaria rever, basta clicar neste [link](https://ishtecnologia.sharepoint.com/:v:/s/CTI-PurpleTeam/Ec4VyYNxFWtHlKHst_JMY5oBxP0OOPMKydRHO1BqWFiNpQ?e=D94s2B&nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJTdHJlYW1XZWJBcHAiLCJyZWZlcnJhbFZpZXciOiJTaGFyZURpYWxvZy1MaW5rIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXcifX0%3D).
=======
Caso você não pode participar do Webinar de apresentação da pesquisa, ou gostaria rever, basta clicar neste [link]
>>>>>>> be0fe62914480fa0d0a245cbe223eb1acf261c42


