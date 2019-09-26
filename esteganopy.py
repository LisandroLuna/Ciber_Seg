import platform
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", type=str, help="Ingresar ruta del archivo a esconder")
parser.add_argument("-i", "--image", type=str, help="Ingresar ruta del archivo receptor")
args = parser.parse_args()

def hidefile(file, file2):
    osl = platform.system()
    try:
        if osl == 'Windows':
            os.system('copy /b ' + file + '+' + file2 + ' ' + file2)
        elif osl == 'Linux':
            os.system('cat ' + file + ' >> ' + file2)
        print('Se escondio el archivo\'' + file + '\' en el archivo \'' + file2 + '\'.\n\n')
    except Exception as e:
        print(e + '\n')


def showfile(file2):
    osl = platform.system()
    try:
        if osl == 'Windows':
            os.system('WinRAR e -y ' + file2)
        elif osl == 'Linux':
            os.system('unrar x ' + file2)
        print('Se extrajo el archivo oculto en \'' + file2 + '\'.\n\n')
    except Exception as e:
        print(e + '\n')

def main():
    file = args.file
    file2 = args.image
    print('EstegoPy es un script que permite ocultar un archivo X en una imagen.\n')
    action = 0
    if file and file2:
        action = 1
    elif file2 and not file:
        action = 2
    if action == 1:
        hidefile(file, file2)
    elif action == 2:
        showfile(file2)
    elif action == 0:
        print('Debe ingresar al menos la variable de imagen!')
        exit()


main()