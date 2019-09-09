import netifaces
import subprocess as sp
import nmap
import socket
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--iface", help="Ingresar interfaz a utilizar", action="store_true")
args = parser.parse_args()


def getbitsnetmask(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])


def gethostnum(bits):
    mbits = 32 - bits
    nhost = 2 ** mbits
    return nhost


def splitip(ip):
    ipdata = ip.split('.')
    ipdata[0] = int(ipdata[0])
    ipdata[1] = int(ipdata[1])
    ipdata[2] = int(ipdata[2])
    ipdata[3] = int(ipdata[3])
    return ipdata


def getstarterip(broad, nhosts):
    ipdata = splitip(broad)
    for i in range(0, nhosts - 1):
        if ipdata[3] > 0:
            ipdata[3] = ipdata[3] - 1
        else:
            if ipdata[2] > 0:
                ipdata[2] = ipdata[2] - 1
            else:
                if ipdata[1] > 0:
                    ipdata[1] = ipdata[1] - 1
                else:
                    if ipdata[0] > 0:
                        ipdata[0] = ipdata[0] - 1
                    else:
                        print('IP Erroenea!')
    datastr = str(ipdata[0]) + '.' + str(ipdata[1]) + '.' + str(ipdata[2]) + '.' + str(ipdata[3])
    return datastr


def scanip(start, nhosts):
    startip = splitip(start)
    datastr = str(startip[0]) + '.' + str(startip[1]) + '.' + str(startip[2]) + '.' + str(startip[3])
    # Limito la cantidad de host a escanear a 10 para evitar demoras
    # for i in range(0, nhosts-1):
    for i in range(0, 11):
        print('\nIP a analizar: ' + datastr)
        if getping(datastr) == True:
            analizeip(datastr)
        else:
            print('    - Sin respuesta a ping.')
        if startip[3] <= 255:
            startip[3] = startip[3] + 1
        else:
            if startip[2] <= 255:
                startip[2] = startip[2] + 1
            else:
                if startip[1] <= 255:
                    startip[1] = startip[1] + 1
                else:
                    if startip[0] <= 255:
                        startip[0] = startip[0] + 1
                    else:
                        print('IP Erroenea!')
        datastr = str(startip[0]) + '.' + str(startip[1]) + '.' + str(startip[2]) + '.' + str(startip[3])


def analizeip(host):
    try:
        nm = nmap.PortScanner()
        try:
            r = nm.scan(host, arguments='-sT -T5')
            print('    - Puertos TCP:')
            getportsinfo(nm[host]['tcp'], host)
        except Exception as e:
            print('        - Error al leer puertos TCP.')
        try:
            r = nm.scan(host, arguments='-sU -T5')
            print('    - Puertos UDP:')
            getportsinfo(nm[host]['udp'], host)
        except Exception as e:
            print('        -  Error al leer puertos UDP.')
    except Exception as e:
        print('    - Error al Escanear.')


def getbannerdata(ip, port):
    try:
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        banner = str(banner).replace('b\'', '').replace('\'', '').rstrip('\r\n')
        banner = (banner[:75] + '..') if len(banner) > 75 else banner
        return banner
    except Exception as e:
        return str(e)


def getportsinfo(data, host):
    for k in data:
        try:
            banner = getbannerdata(host, int(k))
            print('        - ' + str(k) + ': ' + banner)
        except Exception as e:
            return 'N/A' + str(e)


def getlistif(ifli):
    for i in (0, (len(ifli) - 1)):
        print('    - ' + ifli[i])


def getifdata(iface):
    data = netifaces.ifaddresses(iface)
    ipv4data = data[netifaces.AF_INET]
    return ipv4data


def getping(ip):
    try:
        status, result = sp.getstatusoutput("ping -c1 -w2 " + ip)

        if status == 0:
            return True
        else:
            return False
    except Exception as e:
        return False


def checkkey(dict, key):
    if key in dict.keys():
        return True
    else:
        return False


print('Bienvenido PyScan')
iface =  args.iface
print('')
if iface == 'lo':
    print('El script no escanea redes lcoales!')
elif iface == 'localhost':
    print('El script no escanea redes lcoales!')
else:
    ifaces = getlistif(netifaces.interfaces())
    if iface in ifaces:
        ifdata = getifdata(iface)
        nbits = getbitsnetmask(ifdata[0]['netmask'])
        hosts = gethostnum(nbits)
        shost = getstarterip(ifdata[0]['broadcast'], hosts)
        print('    - IP: ' + ifdata[0]['addr'])
        print('    - Netmask: ' + ifdata[0]['netmask'])
        print('    - Broadcast: ' + ifdata[0]['broadcast'])
        print('    - Hosts: ' + str(hosts))
        print('    - Tipo de red: ' + str(shost) + '/' + str(nbits))
        print('\nComenzando analisis de red, solo se analizaran los host que respondan ping.')
        print('-Escaneo limitado a 10 hosts-')
        print('Iniciando...')
        # scanIp('10.40.7.20', hosts)
        scanip(shost, hosts)
    else:
        print('Interfaz no valida!')
