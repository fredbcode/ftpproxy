###############################################################################
Proxy Suite 
Voici les sources de Suse ftp proxy avec les modifications non incluses dans 
la version Suse officielle (Plus d'infos http://traceroot.fr/).

Un proxy FTP est un serveur où s'exécute un relais transférant les transactions FTP
depuis votre client vers un site FTP

Pour compiler Proxy-Suite avec ldap il vous faut les paquets openldap-devel et libwrap-dev
( libldap2-dev et libwrap0-dev suivant les distributions )

./configure --prefix=/usr --exec-prefix=/usr --sysconfdir=/etc --with-libldap=/usr/lib/libldap.so.2

Sous Debian etch il suffit d'installer le paque ftp-proxy et de remplacer le binaire, je suppose que ça fonctionne
pour d'autres distributions.

Voici la liste des modifications que j'ai apportés au produit Suse ftp-proxy-suite.

- Correction: Faille de sécu de l'appli pour l'identification Ldap (mot de passe blanc).

- Ajout: Vérification de l'appartenance à un groupe pour l'utilisateur

- Ajout: Système de filtrage.

- Format des logs

Le Proxy FTP modifié inclut maintenant des fonctionnalités de filtrage d'accès avancées, 
basées sur des ACL, listes de commandes disponibles sur des groupes (utilsateurs et destinations),

le Proxy FTP intercepte tous les flux à destination des serveurs FTP et bloque immédiatement 
les sites interdits, restreint les commandes ftp pour d'autres, ou bien autorise toutes les connections.
