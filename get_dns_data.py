#Obtener informacion de los registros DNS de un dominio

import dns
import dns.resolver
import dns.exception


def get_data(dom, typ):
    return dns.resolver.query(dom, typ)


print('Bienvenido a GetDNSData\n')

domain = str(input('Ingrese dominio a analizar: '))

typeR = str(input('Tipo de registro DNS a consultar [A/AAAA/NS/MX]:  ')).upper()
try:
    if typeR == 'A':
        regA = get_data(domain, typeR)
        print('\n' + regA.response.to_text())
    elif typeR == 'AAAA':
        reg4A = get_data(domain, typeR)
        print('\n' + reg4A.response.to_text())
    elif typeR == 'NS':
        regNS = get_data(domain, typeR)
        print('\n' + regNS.response.to_text())
    elif typeR == 'MX':
        regMX = get_data(domain, typeR)
        print('\n' + regMX.response.to_text())
    else:
        print('Registro DNS no valido o no soportado!s')
except dns.exception.DNSException as e:
    print('Error - ' + str(e))
finally:
    print('\nGitHub.com/LisandroLuna')
