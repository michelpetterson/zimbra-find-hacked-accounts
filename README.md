## Como utilizar esse script ##

## Requerimento ##

- O script deve ser instalado no servidor do zimbra que está atuando com o serviço de logger host.

## Procedimento ##

1. Clone o repositório para o servidor utilizando o comando abaixo:

```
server# git clone https://gitlab.intranet.domain.com/servidores/linux/zimbra-find-hacked-accounts.git
```

2. Com usuário do zimbra, configure no cron:

```
server# crontab -e
```

3. Adicione ao crontab:
```
*/5 * * * * cd /opt/zimbra/scripts/spam-utils/findHackedAccounts; bash -x findHackedAccount.sh
```

