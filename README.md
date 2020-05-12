# Code_reseau

Compilation de scripts utilisant la bibliothèque scapy de python. Ils sont tous fait pour être utilisés sur une machine sous Linux, et demandent des droits de super-utilisateur pour être lancés.

#Network_scanner

Un scanner de réseau relativement classique, utilisant le protocole ARP pour découvrir l'IP et l'adresse MAC de toutes les machines connectées au réseau.
Quelques particularités cependant : 
  - Il sauvegarde l'adresse IP et l'adresse MAC de chaque dans un fichier texte appelé .scan-logs.txt dans le répertoire du super-utilisateur.
  - Il se rafraichit toutes les 30 secondes jusqu'à ce que l'utilisateur décide d'arrêter le programme.
  - Si une machine entre ou sort du réseau pendant le scan, le programme note son entrée ou sa sortie dans le fichier .scan_logs.txt et l'horodate.
