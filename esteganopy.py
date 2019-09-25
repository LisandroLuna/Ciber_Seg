from steg import steg_img
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", type=str, help="Ingresar archivo a esconder")
parser.add_argument("-i", "--image", type=str, help="Ingresar imagen de destino")
args = parser.parse_args()

def hidefile(file, img):
    hfile = steg_img.IMG(payload_path=file, image_path=img)
    try:
        hfile.hide()
        print('Se escondio el archivo\'' + file + '\' en la imagen \'' + img + '\'.\n\n')
    except Exception as e:
        print(e)


def showfile(img):
    sfile = steg_img.IMG(image_path=img)
    try:
        sfile.extract()
        print('Se extrajo el archivo oculto en la imagen \'' + img + '\'.\n\n')
    except Exception as e:
        print(e)

def main():
    file = args.file
    img = args.image
    print('EstegoPy es un script que permite ocultar un archivo X en una imagen.\n')
    action = 0
    if file and img:
        action = 1
    elif img and not file:
        action = 2
    if action == 1:
        hidefile(file, img)
    elif action == 2:
        showfile(img)
    elif action == 0:
        print('Debe ingresar al menos la variable de imagen!')
        exit()


main()