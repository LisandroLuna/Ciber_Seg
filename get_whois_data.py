#Obtener informacion WHOIS de un dominio

import pythonwhois
import pythonwhois.shared


def get_whois(dom):
    return pythonwhois.get_whois(dom)


domain = str(input('Ingrese dominio a analizar: '))

try:
    print(get_whois(domain))
except pythonwhois.shared.WhoisException as e:
    print('\nError - ' + str(e))
