#!/bin/bash
#
# Description: Procura em log por contas comprometidas
# Author: Michel Peterson
# Version: 1.0
# Created Date: 08-05-2018
# Changelog: 
#    03.08.2022 - Adicionado integracrao com o mysql
#    04.08.2022 - Melhorardo logica de detectacao de contas

#
# Logs onde os buscas devem ser feitas.
# Os logs abaixo sao dos servidores SMTP do zimbra.
#

ItabelaLog="/var/log/zimbra/zimbra-mail01.log"
CaetiteLog="/var/log/zimbra/zimbra-mail02.log"

#
# Variaveis auxiliares
#

DATE=$(date "+%d-%m-%Y")

#
# Carrega funcoes auxiliares
#

source ./functions/common_func.sh

#
# E-mail de destino para notificacao das contas comprometidas.
#

MailTo="monitorlinux@domain.com etir@domain.com"

#
# IPs e Emails que devem ser removidos dos testes.
#

MailException="impressoras@domain.com"
NetException="10\.[0-9][0-9]?\. 192\.168\. 10\.129\. 10\.130\."

#
# Destinos considerados suspeitos e que normalmente os spammers
# enviam mensagem quando comprometem as contas.

BadDestination="yahoo.co.uk\|aol.com\|yahoo.es\|yahoo.fr"

# Necessario para o ldapsearch, visto que o tls desse servidor n
# funciona mais no AD.

JumpHost="barropreto.intranet.domain.com"

#
# Limites que devem ser considerados para verificacao e classificacao
# nos testes efetuados pelo script.
#

CutScore=2
IpLimit=5
CbpolicyLimit=200
SentLimit=200
LoginLimit=15

#
# Api do site ipinfo.io para saber o pais de origem de um ip.
#

ApiUrl="ipinfo.io"
ApiToken01=""
ApiToken02=""

# Site ipinfodb.com
#http://api.ipinfodb.com/v3/ip-country/?key=$ApiToken02&ip=$ip
#ApiToken03="0c36ac33555dd24fa0bc9160f6d0e7be8af9e6843c7f8cf61a8cef6fa44981d5"

#
# Parametros de conexao com o banco do Cbpolicyd do zimbra
#

CbUser='zmcbpolicyusr'
CbPass=''
CbDbase=''
CbHost="itabela.domain.com"
cb_mysql_cmd="/opt/zimbra/bin/mysql -B -N -u $CbUser -p$CbPass -h $CbHost $CbDbase"

#
# Parametros de conexao com o banco Findhackerdb que e utilizado por esse script
# para armazenar informacoes.
#

FhUser='findhackermng'
FhPass=''
FhDbase='findhackerdb'
FhHost="canudos.intranet.domain.com"
fh_mysql_cmd="/opt/zimbra/bin/mysql -B -N -u $FhUser -p"$FhPass" -h $FhHost $FhDbase"

#
# Parametros para conectar ao LDAP-AD
#

LdapUser="CN=sync-ad,OU=Servicos,DC=intranet,DC=domain,DC=br"
LdapPass=""
LdapHost="ldap.intranet.domain.com"
ad_ldap_cmd="ldapsearch -vvv -E pr=2000/noprompt -D $LdapUser -w $LdapPass -x -b dc=intranet,dc=domain,dc=br -H ldaps://$LdapHost -LLL" 

#
# Cria pasta temporaria se ela nao existir.
#

ZmbTemp="/tmp/zmbfha"

if [ ! -d $ZmbTemp ]; then
	mkdir $ZmbTemp
fi

#
# Chama funcao para obter lita de contas suspeitas que devem
# ser verificadas.
#
echo "$(date "+%d-%m-%Y %H:%M:%S") - ## Collecting ##"
echo -e "$(date "+%d-%m-%Y %H:%M:%S") - 1. Generating suspect accounts list...\n"
GetSuspectUsersAndLoginCount

#
# Consulta a lista de contas suspeitas para iniciar a verificacao.
#

session=$($fh_mysql_cmd -e "SELECT session FROM tracking WHERE verified = 'no'")

if [ ! -z "$session" ]; then

   #
   # Chama as funcoes para comecar a verificacao em busta
   # de contas comprometidas.
   #
   echo "$(date "+%d-%m-%Y %H:%M:%S") - ## Analyzing ##"
   echo -e "$(date "+%d-%m-%Y %H:%M:%S") - 2. Checking accounts...\n"
   echo "## Actions ##"
   for s in $session; do
      user=$($fh_mysql_cmd -B -N -e "SELECT email FROM tracking WHERE session = $s" |tr '[:upper:]' '[:lower:]')
      users=$($cb_mysql_cmd -e 'select Member from policy_group_members where PolicyGroupID=5' | tr '\n' ' ')
      if no_exists_in_list "$users" " " $user ; then
         CheckLogins
         CountAndCheckSuspectIP
         CheckSentMail
         CkeckSuspectDestination
         MarkVerified
   
         ##
         ## Se o peso das checagens acima for maior que $CutScore
         ## a conta e considerada comprometida e inicia o 
         ## tratamento da conta.
         ##
   
         if [ $weight -ge $CutScore ]; then
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - ## Account: $user" 
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 1/8: Adding account in cbpolicyd ###"
         BlockUserInCbpolicyd
   
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 2/8: Changing account password ###"
         ChangeLdapPass
   
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 3/8: Invalidating zimbra session ###"
         InvalidateZimbraSession
   
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 4/8: Creating mail for admin notification ###"
         CreateNotify to_admin
   
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 5/8: Creating mail for user notification ###"
         CreateNotify to_user
   
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 6/8: Sending mail for user ###"
         SendMailNotify to_user
   
   	     echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 7/8: Logging accoounts compromised ###"
         LogCompromisedAccounts
         fi
      fi
      unset weight
   done
   
   #
   # Envia e-mail para os admins
   #
   echo "$(date "+%d-%m-%Y %H:%M:%S") - => Step 8/8: Sending mail for Admins ###"
   SendMailNotify to_admin
fi
