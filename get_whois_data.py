import pythonwhois

def get_whois(dom):
    return pythonwhois.get_whois(dom)


domain = str(input('Ingrese dominio a analizar: '))

try:
    dataw = get_whois(domain)
    dky = dataw.keys()
    for s in dky:
        idom = dataw.get(s)
        print(idom)
except pythonwhois.shared.WhoisException as e:
    print('\nError - ' + str(e))
