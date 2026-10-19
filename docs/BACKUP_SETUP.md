# Encrypted off-VM backups (owner)

`scripts/backup_encrypted.sh` dumps the database, compresses it and encrypts it with `age` to a **public** key. The VM can create backups but can never read them. Only your laptop holds the private key.

## 1. Generate the key on the laptop (PowerShell)

```powershell
winget install FiloSottile.age
New-Item -ItemType Directory -Force D:\exposight-backups | Out-Null
age-keygen -o D:\exposight-backups\exposight_backup_key.txt
```

`age-keygen` prints `Public key: age1...`. Copy that line only.

Keep `exposight_backup_key.txt` safe: without it no backup can be restored. Store a second copy offline (USB stick or password manager). Never copy it to the VM, chat, email or the repository.

## 2. Put the public key on the VM

```bash
ssh -i ~/.ssh/exposight_ed25519 exposight@172.198.136.164
sudo apt-get install -y age
sudo install -d -m 755 /etc/exposight
echo "age1...your public key..." | sudo tee /etc/exposight/backup_age_recipient.pub
sudo chmod 644 /etc/exposight/backup_age_recipient.pub
sudo install -d -o exposight -g exposight -m 700 /var/backups/exposight
```

The script refuses to run if the file contains `AGE-SECRET-KEY-` (a private key).

Test once by hand:

```bash
cd /opt/exposight
sudo bash scripts/backup_encrypted.sh /var/backups/exposight
ls -l /var/backups/exposight/*.age
```

## 3. Daily cron at 03:30 UTC

The VM clock is UTC (check with `timedatectl`). Edit root's crontab:

```bash
sudo crontab -e
```

Add this one line:

```cron
30 3 * * * bash /opt/exposight/scripts/backup_encrypted.sh /var/backups/exposight >> /var/log/exposight_backup.log 2>&1 && chown -R exposight:exposight /var/backups/exposight
```

The `chown` lets the `exposight` user copy the encrypted files off the VM. The script keeps 7 days of backups on the VM. Check the log: `sudo tail /var/log/exposight_backup.log`.

## 4. Weekly copy to the laptop (PowerShell)

Run once a week (or add it to Windows Task Scheduler):

```powershell
$key = "$HOME\.ssh\exposight_ed25519"
$vm = "exposight@172.198.136.164"
$f = ssh -i $key $vm "ls -1t /var/backups/exposight/exposight_db_*.sql.gz.age | head -1"
scp -i $key "${vm}:$f" D:\exposight-backups\
Get-ChildItem D:\exposight-backups\*.age | Sort-Object LastWriteTime | Select-Object -Last 3
```

The laptop copies are not deleted automatically. Delete old ones by hand when you no longer need them.

## 5. Restore test into a throwaway local container

Do this after the first copy, and then every few months. It proves the key and the backup work. It never touches production. Docker Desktop must be running.

```powershell
$file = (Get-ChildItem D:\exposight-backups\*.sql.gz.age | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
age --decrypt -i D:\exposight-backups\exposight_backup_key.txt -o D:\exposight-backups\restore-test.sql.gz $file

docker run -d --name exposight-restore-test -e POSTGRES_PASSWORD=restoretest -e POSTGRES_DB=asm postgres:18.6-alpine
Start-Sleep -Seconds 5
docker exec exposight-restore-test psql -U postgres -c "CREATE ROLE exposight_owner; CREATE ROLE exposight_app;"
docker cp D:\exposight-backups\restore-test.sql.gz exposight-restore-test:/tmp/restore.sql.gz
docker exec exposight-restore-test sh -c "gunzip -c /tmp/restore.sql.gz | psql -v ON_ERROR_STOP=1 -q -U postgres -d asm"
docker exec exposight-restore-test psql -U postgres -d asm -c "SELECT version_num FROM alembic_version;" -c "SELECT count(*) AS domains FROM domains;"
```

Expected: the restore finishes without `ERROR`, `version_num` shows the production revision, and the domain count matches the dashboard. The roles are created first because the dump assigns tables to `exposight_owner` and grants to `exposight_app`; if your `.env` uses other role names, use those.

Clean up (the decrypted file contains real data):

```powershell
docker rm -f exposight-restore-test
Remove-Item D:\exposight-backups\restore-test.sql.gz
```
