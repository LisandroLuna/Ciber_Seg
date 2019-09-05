import netifaces
import subprocess as sp
import nmap


def getBitsNetmask(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])


def getHostNum(bits):
    mbits = 32 - bits
    nhost = 2**mbits
    return nhost


def splitIp(ip):
    ipdata = ip.split('.')
    ipdata[0] = int(ipdata[0])
    ipdata[1] = int(ipdata[1])
    ipdata[2] = int(ipdata[2])
    ipdata[3] = int(ipdata[3])
    return ipdata


def getStarterIp(broad, nhosts):
    ipdata = splitIp(broad)
    for i in range(0, nhosts-1):
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


def scanIp(start, nhosts):
    startip = splitIp(start)
    datastr = str(startip[0]) + '.' + str(startip[1]) + '.' + str(startip[2]) + '.' + str(startip[3])
    #Limito la cantidad de host a escanear a 10 para evitar demoras
    #for i in range(0, nhosts-1):
    for i in range(0, 11):
        print('\nIP a analizar: ' + datastr)
        if getPing(datastr) == True:
            analizeIp(datastr)
        else:
            print('    - Sin respuesta.')
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


def analizeIp(host):
    nm = nmap.PortScanner()
    try:
        r = nm.scan(host, arguments='-sV - O - p 21, 22, 80, 110, 135, 139, 455, 8080')
        print(nm[host]['tcp'])
    except:
        print('    - Error al leer IP')


def getListIf(ifli):
    for i in (0, (len(ifli)-1)):
        print('    - ' + ifli[i])


def getIfData(iface):
    data = netifaces.ifaddresses(iface)
    ipv4data = data[netifaces.AF_INET]
    return ipv4data


def getPing(ip):
    status, result = sp.getstatusoutput("ping -c1 -w2 " + ip)

    if status == 0:
        return True
    else:
        return False


print('Bienvenido PyScan')
print('\nInterfaces disponibles: ')
getListIf(netifaces.interfaces())
ifa = str(input('\nIngrese la interfaz a utilizar: '))
print('')
ifdata = getIfData(ifa)
nbits = getBitsNetmask(ifdata[0]['netmask'])
hosts = getHostNum(nbits)
shost = getStarterIp(ifdata[0]['broadcast'], hosts)
print('    - IP: ' + ifdata[0]['addr'])
print('    - Netmask: ' + ifdata[0]['netmask'])
print('    - Broadcast: ' + ifdata[0]['broadcast'])
print('    - Hosts: ' + str(hosts))
print('    - Tipo de red: ' + str(shost) + '/' + str(nbits))
print('\nComenzando analisis de red, solo se analizaran los host que respondan ping.')
print('-Escaneo limitado a 10 hosts-')
print('Iniciando...')
#scanIp('10.40.7.20', hosts)
scanIp(shost, hosts)

