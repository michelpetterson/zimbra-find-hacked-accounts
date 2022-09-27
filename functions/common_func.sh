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


#
# Funcao que simula o parser "in" dentro de uma variavel
# como se fosse uma lista.
#

function no_exists_in_list() {
   LIST=$1
   DELIMITER=$2
   VALUE=$3
   LIST_WHITESPACES=`echo $LIST | tr "$DELIMITER" " "`
   for x in $LIST_WHITESPACES; do
     if [ "$x" = "$VALUE" ]; then
        return 1
     fi
   done
   return 0
}

#
# Funcao que gera diff dos arquivos de log considerando 
# apenas os registros desde a ultima execucao.
#

function LogDiff() {
   DiffLogMerged="$ZmbTemp/itabela-caetite.diff.log"
   ItabelaLogPrevious="$ZmbTemp/itabela-previous.log"
   CaetiteLogPrevious="$ZmbTemp/caetite-previous.log"

   if [ ! -f $ItabelaLogPrevious ]; then
      touch $ItabelaLogPrevious
   fi
   if [ ! -f $CaetiteLogPrevious ]; then
      touch $CaetiteLogPrevious
   fi

   if [ -f "$ItabelaLog" ] && [ -f "$CaetiteLog" ]; then
      diff -N -u $ItabelaLog $ItabelaLogPrevious > $DiffLogMerged
      diff -N -u $CaetiteLog $CaetiteLogPrevious >> $DiffLogMerged
      cp $ItabelaLog $ItabelaLogPrevious
      cp $CaetiteLog $CaetiteLogPrevious
   else
      clear
      echo -e "Error! Arquivos de logs nao existem...verifique\n"
      exit 1
   fi
}

#
# Verifica se o usuario tem alguma notificao feita
# no dia atual.
#

function CheckIfUserWasNotifiedToday() {
    date_query=$($fh_mysql_cmd -e "SELECT SUBSTRING(date,1,10) date from notification WHERE email = '$1';")
    date_query=${date_query:-null}
    if [ "$date_query" == "$(date "+%Y-%m-%d")" ]; then
       user_notified="yes"
    else
       user_notified="no"
    fi
}


#
# Busca os 10 primeiros logins e agrupa usuarios de 
# acordo com a quantidade de logins, utlizando o log 
# vigente e armazena no banco de dados.
#

function GetSuspectUsersAndLoginCount() { 
   LogDiff
   grep sasl_user $DiffLogMerged | sed 's/.*sasl_username=//g' | sort | \
   uniq -c | sort -nr | head -10 > $ZmbTemp/Sasl_logins-$DATE.list
   
   #
   # Consulta MySQL para receber a lista de usuarios com 
   # a cota de envio de emails estourada no cbpolicyd.
   #
   
   while read line; do
       CbpolicydQuotaFault+=("$line")
   done < <($cb_mysql_cmd -B -N -e "SELECT SUBSTRING(TrackKey,8) TrackKey FROM quotas_tracking WHERE Counter > $CbpolicyLimit")
   
   # Pega lista de usuarios que tiveram logins no servidor de e-mail.
   # Baseado na lista de usuarios gerados na query acima.
   
   count=0

   while [ ${#CbpolicydQuotaFault[@]} -gt $count ]; do
      users=$($cb_mysql_cmd -e 'select Member from policy_group_members where PolicyGroupID=5' | tr '\n' ' ')
      if no_exists_in_list "$users" " " ${CbpolicydQuotaFault[$count]} ; then
         if no_exists_in_list "$MailException" " " ${CbpolicydQuotaFault[$count]} ; then
            CheckIfUserWasNotifiedToday ${CbpolicydQuotaFault[$count]}
            if [ $user_notified != "no" ]; then
               grep -i "from=<${CbpolicydQuotaFault[$count]}" $ItabelaLog $CaetiteLog > $ZmbTemp/sents-$DATE.list
               destbadcount=$(grep "$BadDestination" $ZmbTemp/sents-$DATE.list | wc -l &> /dev/null)
               result=$(grep ${CbpolicydQuotaFault[$count]} $ZmbTemp/Sasl_logins-$DATE.list)
               logincount=$(echo $result | awk '{print $1}')
               email=$(echo $result | awk '{print $2}')
               sentcount=$(grep -i "from=<${CbpolicydQuotaFault[$count]}" $ItabelaLog $CaetiteLog | wc -l)
               asession=$(shuf -i 100-100000000000 -n 1)
      	       verified="no"
      	       logincount="${logincount:-0}"
      	       email="${email:-null}"
      	       sentcount="${sentcount:-0}"
      	       destbadcount="${destbadcount:=0}"

               if [[ $email != null ]] && [[ $sentcount -ne 0 || $destbadcount -ne 0 || $logincount -ne 0 ]]; then
      	          $fh_mysql_cmd -e "INSERT INTO tracking (session, date, email, login_count, sent_count, dest_bad_count, verified) \
      	          VALUES ($asession, SYSDATE(), '$email', $logincount, $sentcount, $destbadcount, '$verified')"
      	       fi
            fi

         fi
      fi
        let count++
   done
}

#
# Funcao que quantifica a quantidade de logins feita por determinado usuario.
#

function CheckLogins() {
   LoginCount=$($fh_mysql_cmd -B -N -e "SELECT login_count from tracking WHERE session = $s")
   
   if [ $LoginCount -ge $LoginLimit ]; then
      let weight++
      MultiplesLogins=true
   else
      MultiplesLogins=false
   fi
}

#
# Funcao para consultar pais de origem do ip
# 

function CheckCountryIP() {
  echo $ip | egrep $NetException &> /dev/null
  if [ $? -ne 0 ]; then
     CheckCountry=$(curl -s $ApiUrl/$ip?token=$ApiToken01 | awk -F\" '/country/ {print $4}')
     if [ -z $CheckCountry ]; then
        CheckCountry=$(curl -s $ApiUrl/$ip?token=$ApiToken02 | awk -F\" '/country/ {print $4}')
     fi
     if [ x"$CheckCountry" != x"BR" ]; then
        let weight++
		ConnectionSourceOutsideFromBrazil=true
     else
		ConnectionSourceOutsideFromBrazil=false
	 fi
  fi
}

#
# Funcao que quantifica o numero de ips de origem que fizeram login com determinado usuario.
#

function CountAndCheckSuspectIP() {
   IPLIST=$(awk -vuser=preza@domain.com '$0~user{print $7}' $DiffLogMerged \
   | grep 'client.*[0-9]' | cut '-d]' -f 1 | cut '-d[' -f2 | sort -n | uniq)

   IpCount=$(echo $IPLIST | wc -l)

   if [ $IpCount -ge $IpLimit ]; then
      let weight++
	  MultiplesSourceConnections=true
   else
	  MultiplesSourceConnections=false
   fi

   IPLIST=$(echo $IPLIST | tr '\n' ' ' | sed 's/\(.*\)\( .*\)/\1/g' | cut -d' ' -f -10)
   for ip in $(echo $IPLIST); do
      NetException=$(echo $NetException | sed 's/ /\|/')
   	  CheckCountryIP
   done
}

#
# Funcao que verifica a quantidade de emails enviando por usuario.
#

function CheckSentMail() {
   SentCount=$($fh_mysql_cmd -B -N -e "SELECT sent_count from tracking WHERE session = $s")

   if [ $SentCount -ge $SentLimit ]; then
      let weight++
	  MassMailSent=true
   else
      MassMailSent=false
   fi
}

#
# Funcao que verifica a quantidade de emails enviada para destinos suspeitos.
#

function CkeckSuspectDestination() {
   BadDestCount=$($fh_mysql_cmd -B -N -e "SELECT dest_bad_count from tracking WHERE session = $s")

   if [ $BadDestCount -gt 10 ]; then
      let weight++
      MailSentToSupectDestination=true
   else
      MailSentToSupectDestination=false
   fi
}

#
# Insere usuario no grupo suspectusers do cbpolicyd
# URL: http://cbpolicyd.intranet.domain.com
#


function BlockUserInCbpolicyd() {
   echo "Start block"
   echo $users | grep $user &> /dev/null
   if [ $? -eq 1 ]; then
      $cb_mysql_cmd -e "INSERT INTO policy_group_members (PolicyGroupID, Member, Disabled, Comment) VALUES ('5','$user','0','')"
   fi
}

#
# Funcao que modifica a senha do usuario no AD
#

function ChangeLdapPass() {
   username=$(echo $user | cut -d'@' -f1)
   GetDN=$(ssh -p 2131 $JumpHost "$ad_ldap_cmd \"samaccountname=$username\" dn | awk \"/CN=$username,/ {print $3}\" | cut -d: -f2 | sed 's/ //'")
   AdPassConv=$(echo -n "\"!2NYWaSPNdfCz\"" | iconv -f UTF8 -t UTF16LE | base64 -w 0)
   cp template/ldap.template /tmp/changepwd.ldif
   sed -i -e "s/_GetDN_/$GetDN/" -e "s/_AdPassConv_/$AdPassConv/" /tmp/changepwd.ldif
   scp -P 2131 /tmp/changepwd.ldif $JumpHost:/tmp/ &> /dev/null
   ssh -p 2131 $JumpHost "ldapmodify -H ldaps://$LdapHost -D $LdapUser -w $LdapPass -f /tmp/changepwd.ldif" &> /dev/null
}

#
# Funcao para invalidar sessao do usuario no zimbra
#

function InvalidateZimbraSession() {
   zmprov ma $user zimbraAuthTokenValidityValue 1
   zmprov ma $user zimbraAuthTokenValidityValue ""
   zmprov fc account $user
}

#
# Funcao que cria a mensagem para notificar os admins de email e a cosic.
#

function CreateNotify() {
   case $1 in
      "to_admin")
          probability=$(echo "($weight * 100)/5" | bc)
          echo -e "Conta: $user - Probabilidade: $probability% \n" >> $ZmbTemp/result-$DATE.list.$$
          echo -e "==> Resultado dos testes:\n" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- MultiplesLogins: $MultiplesLogins" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- ConnectionSourceOutsideFromBrazil: $ConnectionSourceOutsideFromBrazil" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- MultiplesSourceConnections: $MultiplesSourceConnections" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- MassMailSent: $MassMailSent" >> $ZmbTemp/result-$DATE.list.$$
          echo -e "--- MailSentToSupectDestination: $MailSentToSupectDestination \n" >> $ZmbTemp/result-$DATE.list.$$

          echo -e "==> Valores:\n" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- Logins consecutivos: $LoginCount" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- IPs de origem diferentes: $IpCount" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- Total E-mails enviados: $SentCount" >> $ZmbTemp/result-$DATE.list.$$
          echo "--- E-mails suspeitos enviados: $BadDestCount" >> $ZmbTemp/result-$DATE.list.$$
          echo -e "===========================================\n" >> $ZmbTemp/result-$DATE.list.$$
	  ;;

	  "to_user")
          cp template/user.template $ZmbTemp/user.notify
	      if [ -f $ZmbTemp/user.notify ]; then
             sed -i "s/_EMAIL_/$user/" $ZmbTemp/user.notify
	      fi
	  ;;
	esac
}

#
# Funcao que registra as contas comprometidas no banco de dados.
#

function LogCompromisedAccounts() {
   alt_email=$(ssh -p 2131 $JumpHost "$ad_ldap_cmd samaccountname=$username mailexterno" | \
   awk '/mailexterno/ {print $2}')

   if [ -z $alt_email ]; then
      alt_email="NA"
   fi

   if [ ! -z $status && $status == "sent" ]; then
      notified="yes"
   else
      notified="no"
   fi

   #notified="yes"
   pwdchanged=$(ssh -p 2131 $JumpHost "$ad_ldap_cmd samaccountname=$username dn pwdlastset" | \
   awk '/pwdLastSet/ {print $2}')
   $fh_mysql_cmd -e "INSERT INTO notification (date, email, alt_email, pass_changed_time, notified) \
   VALUES (SYSDATE(), '$email', '$alt_email', $pwdchanged, '$notified')"
}

#
# Funcao que envia notificacao das contas comprometidas 
# para equipe de seguranca e servidores da CRI.
#

function SendMailNotify() {
   case $1 in
      "to_admin")
         if [ -f $ZmbTemp/result-$DATE.list.$$ ]; then
            mail -s "Hacked Accounts - $DATE" $MailTo < $ZmbTemp/result-$DATE.list.$$
         fi
      ;;

      "to_user")
         if [ $alt_email != "NA" && -f $ZmbTemp/user.notify ]; then
            mail -r "ETIR-DOMAIN - Equpe de Tratamento de Incidentes de Redes da DOMAIN<etir@domain.com>" \ 
       	    -s "Aviso de comprometimento de conta de e-mail - Envio de SPAM" $user < $ZmbTemp/user.notify
            status=$(grep $alt_email /var/log/zimbra/zimbra-mail-ilheus.log |tail -n1 | awk '{print $12}' | cut -d\= -f 2)
         fi
      ;;
   esac
}

#
# Funcao que verifica quais usuarios estao no grupo suspect users 
# do cbpolicyd.
#

function CheckUserInCbpolicyd() {
   echo -e "Accounts in cbpolicyd table:\n" >> $ZmbTemp/result-$DATE.list
   $cb_mysql_cmd -e 'select Member from policy_group_members where PolicyGroupID=5' >> $ZmbTemp/result-$DATE.list
}


#
# Funcao que marca uma conta como verificada pelo 
# script no banco de dados.
#

function MarkVerified() {
    $fh_mysql_cmd -e "UPDATE tracking SET verified = 'yes' WHERE session = $s;"
}

